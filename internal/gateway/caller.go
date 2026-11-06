package gateway

import (
	"context"
	"encoding/json"

	"idp-mcp/internal/authorization"
	"idp-mcp/internal/release"
)

// MetaCaller is the _meta key under which the gateway passes the verified caller to an upstream that was
// approved to receive it (target identity "forward", ADR-0001 D31). The gateway owns this key: whatever a
// client sent under it is removed from every request, so an upstream that trusts the key can trust that it
// came from the gateway's own authentication, not from the caller.
const MetaCaller = "io.idp.telos/caller"

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

// stampCaller returns params with the client's MetaCaller removed and, for a forwarding target, the
// verified caller set. params itself is not modified.
func stampCaller(params map[string]json.RawMessage, mode string, pr authorization.Principal, known bool) map[string]json.RawMessage {
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
	if mode == release.IdentityForward && known {
		roles := pr.Roles
		if roles == nil {
			roles = []string{}
		}
		raw, _ := json.Marshal(Caller{Subject: pr.Subject, Tenant: pr.Tenant, Roles: roles, Client: pr.Client, Actor: pr.Actor})
		meta[MetaCaller] = raw
	}
	b, _ := json.Marshal(meta)
	out["_meta"] = b
	return out
}
