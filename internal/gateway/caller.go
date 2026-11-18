package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"idp-mcp/internal/authorization"
	"idp-mcp/internal/release"
)

// MetaCaller is the _meta key under which the gateway passes the verified caller to an upstream that was
// approved to receive it (target identity "forward", ADR-0001 D31). The gateway owns this key: whatever a
// client sent under it is removed from every request, so an upstream that trusts the key can trust that it
// came from the gateway's own authentication, not from the caller.
const MetaCaller = "io.idp.telos/caller"

// MetaCallerAssertion is the _meta key of the gateway's signature over the caller (ADR-0001 D44): a compact
// JWS an upstream verifies with the gateway's public key, so that it need not trust the network to know that
// MetaCaller came from the gateway. Like MetaCaller it is the gateway's key: a client's own is removed.
const MetaCallerAssertion = "io.idp.telos/caller-assertion"

// CallerAssertionType is the JWS typ of a caller assertion; CallerAssertionTTL is how long one is valid.
const (
	CallerAssertionType = "idp-caller+jwt"
	CallerAssertionTTL  = 60 * time.Second
)

// Caller is the document under MetaCaller. Grants are decided on Subject, Tenant and Roles; Client (the
// OAuth client the token was issued to) and Actor (the delegating party of an RFC 8693 token) are for the
// upstream's audit.
type Caller struct {
	Subject string   `json:"subject"`
	Tenant  string   `json:"tenant"`
	Roles   []string `json:"roles"`
	Client  string   `json:"client,omitempty"`
	Actor   string   `json:"actor,omitempty"`
}

type principalKey struct{}

func withPrincipal(ctx context.Context, pr authorization.Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, pr)
}

func principalFrom(ctx context.Context) (authorization.Principal, bool) {
	pr, ok := ctx.Value(principalKey{}).(authorization.Principal)
	return pr, ok
}

// identityOf reports the identity mode of the target that owns endpoint.
func identityOf(doc *release.Document, endpoint string) string {
	for _, t := range doc.Targets {
		if t.Endpoint == endpoint {
			return t.Identity
		}
	}
	return ""
}

// CallerSigner signs the caller the gateway forwards (ADR-0001 D44). One P-256 key per gateway; upstreams hold
// the public key.
type CallerSigner struct {
	key    *ecdsa.PrivateKey
	kid    string
	issuer string
	now    func() time.Time
}

// NewCallerSigner reads a PEM private key (PKCS #8 or SEC 1, P-256). issuer names the gateway in the assertion.
func NewCallerSigner(pemBytes []byte, issuer string) (*CallerSigner, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	var key *ecdsa.PrivateKey
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("the key is not an EC key")
		}
		key = ec
	} else if ec, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		key = ec
	} else {
		return nil, errors.New("not a PKCS #8 or SEC 1 EC private key")
	}
	if key.Curve != elliptic.P256() {
		return nil, errors.New("the key is not on P-256")
	}
	kid, err := KeyID(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &CallerSigner{key: key, kid: kid, issuer: issuer, now: time.Now}, nil
}

// KeyID is the RFC 7638 thumbprint of a P-256 public key (base64url of the SHA-256 of its canonical JWK).
func KeyID(pub *ecdsa.PublicKey) (string, error) {
	raw, err := pub.Bytes() // 0x04 || X || Y
	if err != nil || len(raw) != 65 {
		return "", errors.New("not an uncompressed P-256 point")
	}
	enc := base64.RawURLEncoding.EncodeToString
	sum := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + enc(raw[1:33]) + `","y":"` + enc(raw[33:]) + `"}`))
	return enc(sum[:]), nil
}

// KeyID of the signing key, for the operator's log.
func (s *CallerSigner) KeyID() string { return s.kid }

// RequestDigest binds an assertion to one request: "sha256:<hex>" of the canonical JSON of the method and the
// params without _meta (release.Canonical: sorted keys, no insignificant whitespace, numbers as written).
func RequestDigest(method string, params map[string]json.RawMessage) (string, error) {
	p := make(map[string]json.RawMessage, len(params))
	for k, v := range params {
		if k != "_meta" {
			p[k] = v
		}
	}
	return release.Digest(map[string]any{"method": method, "params": p})
}

// sign returns the assertion for c sent to audience (the target's endpoint) with this request.
func (s *CallerSigner) sign(c Caller, audience, method string, params map[string]json.RawMessage) (string, error) {
	req, err := RequestDigest(method, params)
	if err != nil {
		return "", err
	}
	var id [12]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	now := s.now()
	claims := jwt.MapClaims{"iss": s.issuer, "aud": audience, "iat": now.Unix(), "exp": now.Add(CallerAssertionTTL).Unix(),
		"jti": base64.RawURLEncoding.EncodeToString(id[:]), "sub": c.Subject, "tenant_id": c.Tenant, "roles": c.Roles, "req": req}
	if c.Client != "" {
		claims["client"] = c.Client
	}
	if c.Actor != "" {
		claims["actor"] = c.Actor
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"], tok.Header["kid"] = CallerAssertionType, s.kid
	return tok.SignedString(s.key)
}

// stampCaller returns params with the client's MetaCaller and MetaCallerAssertion removed and, for a forwarding
// target, the verified caller set; with a signer, also the gateway's assertion over that caller, the target's
// endpoint and this request. params itself is not modified.
func stampCaller(params map[string]json.RawMessage, mode string, pr authorization.Principal, known bool,
	signer *CallerSigner, endpoint, method string) (map[string]json.RawMessage, error) {
	out := make(map[string]json.RawMessage, len(params))
	for k, v := range params {
		out[k] = v
	}
	var meta map[string]json.RawMessage
	if raw, ok := out["_meta"]; ok {
		_ = json.Unmarshal(raw, &meta)
	}
	if meta == nil {
		meta = map[string]json.RawMessage{}
	}
	delete(meta, MetaCaller)
	delete(meta, MetaCallerAssertion)
	if mode == release.IdentityForward && known {
		roles := pr.Roles
		if roles == nil {
			roles = []string{}
		}
		c := Caller{Subject: pr.Subject, Tenant: pr.Tenant, Roles: roles, Client: pr.Client, Actor: pr.Actor}
		raw, _ := json.Marshal(c)
		meta[MetaCaller] = raw
		if signer != nil {
			assertion, err := signer.sign(c, endpoint, method, out)
			if err != nil {
				return nil, fmt.Errorf("sign the caller: %w", err)
			}
			meta[MetaCallerAssertion], _ = json.Marshal(assertion)
		}
	}
	b, _ := json.Marshal(meta)
	out["_meta"] = b
	return out, nil
}
