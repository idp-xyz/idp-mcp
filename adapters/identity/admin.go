package identity

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AdminClaims are the claims an admin API token must carry.
type AdminClaims struct {
	Subject string
	Tenant  string
	Roles   []string
}

// AdminVerifier validates admin API bearer tokens: issuer, audience, exp, sub, tenant_id and a
// roles array. Production uses an IdP's JWKS; development may use an HS256 shared secret.
type AdminVerifier struct {
	issuer, audience string
	hmac             []byte
	keys             *JWKS
}

// NewDevAdminVerifier accepts HS256 tokens signed with secret. Development only.
func NewDevAdminVerifier(issuer, audience string, secret []byte) (*AdminVerifier, error) {
	if len(secret) < 32 {
		return nil, errors.New("development admin secret must be at least 32 bytes")
	}
	return &AdminVerifier{issuer: issuer, audience: audience, hmac: secret}, nil
}

// NewJWKSAdminVerifier accepts asymmetric tokens signed by a key of the JWKS.
func NewJWKSAdminVerifier(issuer, audience string, keys *JWKS) *AdminVerifier {
	return &AdminVerifier{issuer: issuer, audience: audience, keys: keys}
}

// Verify implements the admin token check.
func (v *AdminVerifier) Verify(ctx context.Context, token string) (AdminClaims, error) {
	claims := jwt.MapClaims{}
	methods := Algorithms
	key := func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return v.keys.Key(ctx, kid)
	}
	if v.hmac != nil {
		methods = []string{"HS256"}
		key = func(*jwt.Token) (any, error) { return v.hmac, nil }
	}
	if _, err := jwt.ParseWithClaims(token, claims, key, jwt.WithValidMethods(methods), jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience), jwt.WithExpirationRequired(), jwt.WithLeeway(30*time.Second)); err != nil {
		return AdminClaims{}, ErrInvalid
	}
	sub, _ := claims["sub"].(string)
	tenant, _ := claims["tenant_id"].(string)
	raw, ok := claims["roles"].([]any)
	if sub == "" || tenant == "" || !ok {
		return AdminClaims{}, ErrInvalid
	}
	var roles []string
	for _, r := range raw {
		s, ok := r.(string)
		if !ok {
			return AdminClaims{}, ErrInvalid
		}
		roles = append(roles, s)
	}
	return AdminClaims{Subject: sub, Tenant: tenant, Roles: roles}, nil
}

// DevAdminToken signs a development admin token (registry-service dev-token, tests).
func DevAdminToken(secret []byte, issuer, audience, subject, tenant string, roles []string, ttl time.Duration) (string, error) {
	now := time.Now()
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": issuer, "aud": audience, "sub": subject, "tenant_id": tenant, "roles": roles,
		"iat": now.Unix(), "exp": now.Add(ttl).Unix(),
	}).SignedString(secret)
}
