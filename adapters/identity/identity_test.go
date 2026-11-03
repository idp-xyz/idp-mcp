package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"idp-mcp/internal/release"
)

const (
	issuer   = "http://127.0.0.1:7080/realms/idp"
	resource = "http://127.0.0.1:3220/mcp"
)

type keyring struct {
	rsa     *rsa.PrivateKey
	ec      *ecdsa.PrivateKey
	kids    atomic.Value // []string published
	fetches atomic.Int32
}

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (k *keyring) server(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k.fetches.Add(1)
		var keys []map[string]string
		for _, kid := range k.kids.Load().([]string) {
			switch kid {
			case "rsa-1":
				keys = append(keys, map[string]string{"kty": "RSA", "kid": kid, "use": "sig", "n": enc(k.rsa.N.Bytes()), "e": enc(big.NewInt(int64(k.rsa.E)).Bytes())})
			case "ec-1":
				x, y := k.ec.X.FillBytes(make([]byte, 32)), k.ec.Y.FillBytes(make([]byte, 32))
				keys = append(keys, map[string]string{"kty": "EC", "kid": kid, "crv": "P-256", "x": enc(x), "y": enc(y)})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func setup(t *testing.T) (*keyring, *JWTAuth) {
	t.Helper()
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k := &keyring{rsa: rk, ec: ek}
	k.kids.Store([]string{"rsa-1"})
	srv := k.server(t)
	doc := &release.Document{TenantID: "t1", Auth: release.Auth{Mode: "jwt", JWT: &release.JWT{Issuer: issuer, Resource: resource,
		JWKSURL: srv.URL, AuthorizationServers: []string{issuer}, TenantClaim: "tenant_id", RolesClaim: "roles"}}}
	keys := &JWKS{URL: srv.URL, HTTP: srv.Client(), TTL: time.Minute, MinRefresh: 0}
	return k, NewJWTAuth(doc, keys)
}

func claims(mut func(jwt.MapClaims)) jwt.MapClaims {
	c := jwt.MapClaims{"iss": issuer, "aud": []string{resource}, "sub": "alice", "tenant_id": "t1",
		"roles": []any{"operator"}, "exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix()}
	if mut != nil {
		mut(c)
	}
	return c
}

func sign(t *testing.T, method jwt.SigningMethod, kid string, key any, c jwt.MapClaims) string {
	tok := jwt.NewWithClaims(method, c)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestValidTokensRSAAndECWithRotation(t *testing.T) {
	k, auth := setup(t)
	p, err := auth.Authenticate(context.Background(), sign(t, jwt.SigningMethodRS256, "rsa-1", k.rsa, claims(nil)))
	if err != nil || p.Subject != "alice" || p.Tenant != "t1" || p.Roles[0] != "operator" || p.Method != "jwt" {
		t.Fatalf("%+v %v", p, err)
	}
	// key rotation: a new kid is fetched on first sight
	k.kids.Store([]string{"rsa-1", "ec-1"})
	if _, err := auth.Authenticate(context.Background(), sign(t, jwt.SigningMethodES256, "ec-1", k.ec, claims(nil))); err != nil {
		t.Fatalf("rotated EC key refused: %v", err)
	}
}

func TestRefusedTokens(t *testing.T) {
	k, auth := setup(t)
	rs := func(c jwt.MapClaims) string { return sign(t, jwt.SigningMethodRS256, "rsa-1", k.rsa, c) }
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	valid := rs(claims(nil))
	cases := map[string]string{
		"wrong issuer":      rs(claims(func(c jwt.MapClaims) { c["iss"] = "http://evil/realms/idp" })),
		"raw gateway aud":   rs(claims(func(c jwt.MapClaims) { c["aud"] = "http://127.0.0.1:3219/mcp" })),
		"expired":           rs(claims(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() })),
		"no exp":            rs(claims(func(c jwt.MapClaims) { delete(c, "exp") })),
		"no tenant":         rs(claims(func(c jwt.MapClaims) { delete(c, "tenant_id") })),
		"roles not array":   rs(claims(func(c jwt.MapClaims) { c["roles"] = "operator" })),
		"role not string":   rs(claims(func(c jwt.MapClaims) { c["roles"] = []any{1} })),
		"no sub":            rs(claims(func(c jwt.MapClaims) { delete(c, "sub") })),
		"foreign key":       sign(t, jwt.SigningMethodRS256, "rsa-1", other, claims(nil)),
		"unknown kid":       sign(t, jwt.SigningMethodRS256, "nope", k.rsa, claims(nil)),
		"tampered":          valid[:len(valid)-6] + "AAAAAA",
		"hs256 with pubkey": sign(t, jwt.SigningMethodHS256, "rsa-1", []byte(enc(k.rsa.N.Bytes())), claims(nil)),
		"none":              sign(t, jwt.SigningMethodNone, "rsa-1", jwt.UnsafeAllowNoneSignatureType, claims(nil)),
	}
	for name, tok := range cases {
		if _, err := auth.Authenticate(context.Background(), tok); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestUnknownKidFetchesAreRateLimited(t *testing.T) {
	k, auth := setup(t)
	auth.keys.MinRefresh = time.Hour
	_, _ = auth.Authenticate(context.Background(), sign(t, jwt.SigningMethodRS256, "rsa-1", k.rsa, claims(nil)))
	before := k.fetches.Load()
	for i := 0; i < 20; i++ {
		_, _ = auth.Authenticate(context.Background(), sign(t, jwt.SigningMethodRS256, "junk", k.rsa, claims(nil)))
	}
	if k.fetches.Load() != before {
		t.Fatalf("unknown kids caused %d JWKS fetches", k.fetches.Load()-before)
	}
}

func TestChallengeAndMetadata(t *testing.T) {
	_, auth := setup(t)
	if c := auth.Challenge(false); c != `Bearer resource_metadata="http://127.0.0.1:3220/.well-known/oauth-protected-resource/mcp"` {
		t.Fatal(c)
	}
	if !strings.Contains(auth.Challenge(true), `error="invalid_token"`) {
		t.Fatal("invalid token challenge")
	}
	m := auth.ResourceMetadata()
	if m["resource"] != resource || m["authorization_servers"].([]string)[0] != issuer {
		t.Fatalf("%v", m)
	}
}

func TestAPIKeys(t *testing.T) {
	doc := &release.Document{TenantID: "t1", Auth: release.Auth{Mode: "api-key", APIKeys: []release.APIKey{
		{ID: "k1", Subject: "svc", Roles: []string{"operator"}, SHA256: HashKey("s3cret-key-value")}}}}
	a := NewAPIKeys(doc)
	p, err := a.Authenticate(context.Background(), "s3cret-key-value")
	if err != nil || p.Subject != "svc" || p.Tenant != "t1" || p.KeyID != "k1" {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := a.Authenticate(context.Background(), "wrong"); !errors.Is(err, ErrInvalid) {
		t.Fatal("wrong key accepted")
	}
	if a.ResourceMetadata() != nil {
		t.Fatal("api-key profile must not publish resource metadata")
	}
}

func TestBearerParsing(t *testing.T) {
	r := httptest.NewRequest("POST", "/mcp", nil)
	if _, err := Bearer(r); !errors.Is(err, ErrNoCredentials) {
		t.Fatal(err)
	}
	for _, h := range []string{"Basic abc", "Bearer", "Bearer a b", "Bearer "} {
		r.Header.Set("Authorization", h)
		if _, err := Bearer(r); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: %v", h, err)
		}
	}
	r.Header.Set("Authorization", "bearer tok")
	if tok, err := Bearer(r); err != nil || tok != "tok" {
		t.Fatal(tok, err)
	}
	r.Header.Add("Authorization", "Bearer second")
	if _, err := Bearer(r); !errors.Is(err, ErrInvalid) {
		t.Fatal("duplicate Authorization accepted")
	}
}
