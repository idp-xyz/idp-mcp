// Package identity authenticates data-plane callers: API keys (development, service accounts) and
// OAuth 2.1 bearer JWTs validated against a JWKS (production). It also builds the RFC 9728
// protected resource metadata and the 401 challenge that lead MCP clients to the authorization
// server.
package identity

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"idp-mcp/internal/authorization"
	"idp-mcp/internal/release"
)

// ErrNoCredentials means the request carried no bearer credential.
var ErrNoCredentials = errors.New("no bearer credential")

// ErrInvalid means a credential was presented and refused. The reason is never returned to clients.
var ErrInvalid = errors.New("invalid credential")

// Authenticator turns a bearer credential into a principal.
type Authenticator interface {
	Authenticate(ctx context.Context, bearer string) (authorization.Principal, error)
	// Challenge is the WWW-Authenticate value for a 401; invalid marks a refused credential.
	Challenge(invalid bool) string
	// ResourceMetadata is the RFC 9728 document, nil when the profile publishes none.
	ResourceMetadata() map[string]any
}

// Bearer extracts the token of an "Authorization: Bearer <token>" header.
func Bearer(r *http.Request) (string, error) {
	values := r.Header.Values("Authorization")
	if len(values) == 0 {
		return "", ErrNoCredentials
	}
	if len(values) > 1 {
		return "", ErrInvalid
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t") {
		return "", ErrInvalid
	}
	return token, nil
}

// HashKey is the SHA-256 hex digest under which API keys are stored and distributed.
func HashKey(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// APIKeys authenticates keys listed (as hashes) in the release.
type APIKeys struct {
	tenant string
	keys   map[string]release.APIKey // sha256 hex -> key
}

// NewAPIKeys builds the authenticator of an api-key release.
func NewAPIKeys(d *release.Document) *APIKeys {
	a := &APIKeys{tenant: d.TenantID, keys: map[string]release.APIKey{}}
	for _, k := range d.Auth.APIKeys {
		a.keys[k.SHA256] = k
	}
	return a
}

// Authenticate implements Authenticator.
func (a *APIKeys) Authenticate(_ context.Context, bearer string) (authorization.Principal, error) {
	h := HashKey(bearer)
	k, ok := a.keys[h]
	if !ok || subtle.ConstantTimeCompare([]byte(k.SHA256), []byte(h)) != 1 {
		return authorization.Principal{}, ErrInvalid
	}
	return authorization.Principal{Subject: k.Subject, Tenant: a.tenant, Roles: k.Roles, Method: "api-key", KeyID: k.ID}, nil
}

// Challenge implements Authenticator.
func (a *APIKeys) Challenge(invalid bool) string {
	if invalid {
		return `Bearer error="invalid_token"`
	}
	return "Bearer"
}

// ResourceMetadata implements Authenticator: the api-key profile publishes none.
func (a *APIKeys) ResourceMetadata() map[string]any { return nil }

// MetadataURL is the path-aware RFC 9728 metadata URL of an MCP resource URI:
// https://h/mcp -> https://h/.well-known/oauth-protected-resource/mcp
func MetadataURL(resource string) string {
	u, err := url.Parse(resource)
	if err != nil {
		return ""
	}
	path := strings.TrimSuffix(u.Path, "/")
	return u.Scheme + "://" + u.Host + "/.well-known/oauth-protected-resource" + path
}
