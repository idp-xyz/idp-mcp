package gateway

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"idp-mcp/internal/authorization"
	"idp-mcp/internal/release"
	"idp-mcp/internal/server"
)

func harnessWithIdentity(t *testing.T, identity string) *harness {
	t.Helper()
	up := newUpstream(t)
	rec := &recorder{}
	g := New(Config{GatewayID: "g1", Info: server.ServerInfo{Name: "idp-mcp-gateway", Version: "test"}, DevMode: true,
		CallTimeout: 2 * time.Second, Recorder: rec})
	if err := g.Activate(buildRelease(t, up.srv.URL+"/mcp", "block", func(d *release.Document) { d.Targets[0].Identity = identity })); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(g.Handler())
	t.Cleanup(srv.Close)
	return &harness{g: g, up: up, rec: rec, srv: srv}
}

func upstreamMeta(t *testing.T, h *harness) map[string]any {
	t.Helper()
	params := h.up.bodies[len(h.up.bodies)-1]["params"].(map[string]any)
	meta, _ := params["_meta"].(map[string]any)
	return meta
}

// A target approved for identity learns who is calling, from the gateway's authentication.
func TestForwardIdentityPassesTheVerifiedCaller(t *testing.T) {
	h := harnessWithIdentity(t, release.IdentityForward)
	forged := `"io.idp.telos/caller":{"subject":"admin","tenant":"someone-else","roles":["root"]},`
	params := `{"name":"minimal__echo","arguments":{"text":"x"},"_meta":{` + forged + `"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}`
	r := h.rpc(t, operatorKey, "tools/call", params, map[string]string{server.HeaderName: "minimal__echo"})
	if r.status != 200 {
		t.Fatalf("%d %s", r.status, r.raw)
	}
	c, _ := upstreamMeta(t, h)[MetaCaller].(map[string]any)
	if c == nil || c["subject"] != "svc-operator" || c["tenant"] != "t1" || len(c["roles"].([]any)) != 1 || c["roles"].([]any)[0] != "operator" {
		t.Fatalf("the upstream got %v, not the authenticated caller", upstreamMeta(t, h))
	}
	if upstreamMeta(t, h)["io.modelcontextprotocol/protocolVersion"] != "2026-07-28" {
		t.Fatal("the client's other _meta keys were lost")
	}
}

// Without the approval nothing is forwarded, and a client cannot forge the key.
func TestNoIdentityIsForwardedByDefaultAndForgeryIsStripped(t *testing.T) {
	h := harnessWithIdentity(t, "")
	forged := `"io.idp.telos/caller":{"subject":"admin","tenant":"t1","roles":["root"]},`
	params := `{"name":"minimal__echo","arguments":{"text":"x"},"_meta":{` + forged + `"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}`
	r := h.rpc(t, operatorKey, "tools/call", params, map[string]string{server.HeaderName: "minimal__echo"})
	if r.status != 200 {
		t.Fatalf("%d %s", r.status, r.raw)
	}
	if _, ok := upstreamMeta(t, h)[MetaCaller]; ok {
		t.Fatalf("a client-supplied caller reached the upstream: %v", upstreamMeta(t, h))
	}
	if strings.Contains(r.raw, "root") {
		t.Fatal("the forged caller came back")
	}
}

func TestStampCallerDoesNotModifyItsInput(t *testing.T) {
	in := map[string]json.RawMessage{"_meta": json.RawMessage(`{"a":1}`), "name": json.RawMessage(`"x"`)}
	out := stampCaller(in, release.IdentityForward, principalForTest(), true)
	if string(in["_meta"]) != `{"a":1}` || !strings.Contains(string(out["_meta"]), `"subject":"svc"`) {
		t.Fatalf("%s / %s", in["_meta"], out["_meta"])
	}
	if got := stampCaller(in, "", principalForTest(), true); strings.Contains(string(got["_meta"]), "subject") {
		t.Fatal("identity stamped without approval")
	}
	if got := stampCaller(in, release.IdentityForward, principalForTest(), false); strings.Contains(string(got["_meta"]), "subject") {
		t.Fatal("identity stamped without a verified principal")
	}
}

func principalForTest() authorization.Principal {
	return authorization.Principal{Subject: "svc", Tenant: "t1", Roles: []string{"operator"}}
}
