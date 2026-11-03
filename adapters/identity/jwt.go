package identity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"idp-mcp/internal/authorization"
	"idp-mcp/internal/release"
)

// Algorithms accepted for bearer tokens. HS* is never accepted on the data plane.
var Algorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

// JWKS fetches and caches the signing keys of an issuer.
type JWKS struct {
	URL        string
	HTTP       *http.Client
	TTL        time.Duration // how long a fetched key set is trusted
	MinRefresh time.Duration // unknown kids trigger at most one fetch per MinRefresh

	mu        sync.Mutex
	keys      map[string]crypto.PublicKey
	fetchedAt time.Time
	lastTry   time.Time
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func b64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func (k jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err1 := b64(k.N)
		e, err2 := b64(k.E)
		if err1 != nil || err2 != nil || len(n) < 256 || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("bad RSA key (needs >= 2048-bit modulus)")
		}
		exp := 0
		for _, b := range e {
			exp = exp<<8 | int(b)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}, nil
	case "EC":
		curves := map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()}
		curve, ok := curves[k.Crv]
		x, err1 := b64(k.X)
		y, err2 := b64(k.Y)
		if !ok || err1 != nil || err2 != nil {
			return nil, errors.New("bad EC key")
		}
		size := (curve.Params().BitSize + 7) / 8
		if len(x) != size || len(y) != size {
			return nil, errors.New("bad EC coordinates")
		}
		return ecdsa.ParseUncompressedPublicKey(curve, append(append([]byte{4}, x...), y...))
	}
	return nil, fmt.Errorf("unsupported key type %q", k.Kty)
}

func (j *JWKS) fetch(ctx context.Context) (map[string]crypto.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := j.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, errors.New("JWKS is not a key set")
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pk, err := k.publicKey()
		if err != nil {
			continue // a key we cannot use is simply not trusted
		}
		keys[k.Kid] = pk
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS has no usable signing keys")
	}
	return keys, nil
}

// Key returns the key for kid, refreshing the set when it is stale or kid is unknown.
func (j *JWKS) Key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()
	k, known := j.keys[kid]
	if known && now.Sub(j.fetchedAt) < j.TTL {
		return k, nil
	}
	if now.Sub(j.lastTry) >= j.MinRefresh || j.keys == nil {
		j.lastTry = now
		fctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		keys, err := j.fetch(fctx)
		cancel()
		if err == nil {
			j.keys, j.fetchedAt = keys, now
			k, known = keys[kid]
		}
	}
	if !known {
		return nil, errors.New("unknown signing key")
	}
	return k, nil
}

// JWTAuth validates bearer JWTs of a jwt release.
type JWTAuth struct {
	profile release.JWT
	tenant  string
	keys    *JWKS
	leeway  time.Duration
}

// NewJWTAuth builds the authenticator of a jwt release.
func NewJWTAuth(d *release.Document, keys *JWKS) *JWTAuth {
	return &JWTAuth{profile: *d.Auth.JWT, tenant: d.TenantID, keys: keys, leeway: 30 * time.Second}
}

// Authenticate implements Authenticator: signature by a JWKS key, issuer, audience = the resource
// URI (RFC 8707), exp required, sub/tenant/roles claims present and well-typed.
func (a *JWTAuth) Authenticate(ctx context.Context, bearer string) (authorization.Principal, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(bearer, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return a.keys.Key(ctx, kid)
	}, jwt.WithValidMethods(Algorithms), jwt.WithIssuer(a.profile.Issuer), jwt.WithAudience(a.profile.Resource),
		jwt.WithExpirationRequired(), jwt.WithLeeway(a.leeway))
	if err != nil {
		return authorization.Principal{}, ErrInvalid
	}
	sub, _ := claims["sub"].(string)
	tenant, _ := claims[a.profile.TenantClaim].(string)
	rawRoles, ok := claims[a.profile.RolesClaim].([]any)
	if sub == "" || tenant == "" || !ok {
		return authorization.Principal{}, ErrInvalid
	}
	roles := make([]string, 0, len(rawRoles))
	for _, r := range rawRoles {
		s, ok := r.(string)
		if !ok {
			return authorization.Principal{}, ErrInvalid
		}
		roles = append(roles, s)
	}
	var expires time.Time
	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
		expires = exp.Time
	}
	return authorization.Principal{Subject: sub, Tenant: tenant, Roles: roles, Method: "jwt", Expires: expires}, nil
}

// Challenge implements Authenticator: points the client at the RFC 9728 metadata.
func (a *JWTAuth) Challenge(invalid bool) string {
	c := `Bearer resource_metadata="` + MetadataURL(a.profile.Resource) + `"`
	if invalid {
		c += `, error="invalid_token"`
	}
	return c
}

// ResourceMetadata implements Authenticator.
func (a *JWTAuth) ResourceMetadata() map[string]any {
	return map[string]any{
		"resource":                 a.profile.Resource,
		"authorization_servers":    a.profile.AuthorizationServers,
		"bearer_methods_supported": []string{"header"},
	}
}
