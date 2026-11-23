package integration

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"idp-mcp/adapters/identity"
	"idp-mcp/adapters/store/postgres"
	"idp-mcp/internal/client"
	"idp-mcp/internal/policy"
	"idp-mcp/internal/registry"
	"idp-mcp/internal/server"
	"idp-mcp/tests/fixtures/hostileserver"
)

// TestTheDescriptionLimitOfAnExternalServerIsTheOperatorsPerServerSettingUnderACap follows ADR-0001 15.3: the
// default limit refuses a 1546-byte description (the real case of a hosted server's one long parameter description),
// a server's own limit accepts it and still refuses one byte more, the cap and the class are enforced at registration,
// a change is audited and invalidates the approval, and the reviewer sees, and the approval pins, the limit.
func TestTheDescriptionLimitOfAnExternalServerIsTheOperatorsPerServerSettingUnderACap(t *testing.T) {
	ctx := context.Background()
	ownerURL, serviceURL := scratchDB(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := postgres.Open(ctx, serviceURL)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	tenant, _ := postgres.SeedTenant(ctx, ownerURL, registry.NewID(), "acme")
	pol := &policy.Upstream{AllowedHosts: map[string]bool{"127.0.0.1": true}, PrivateHosts: map[string]bool{}, DevMode: true}
	svc := &registry.Service{Store: store, Policy: pol, DeployTimeout: 8 * time.Second, PollEvery: 100 * time.Millisecond, Log: log,
		MaxExternalDescription: 1024, MaxExternalDescriptionCap: 4096,
		Upstream: &client.Client{HTTP: client.NewHTTPClient(pol, 5*time.Second), Info: server.ServerInfo{Name: "registry", Version: "it"}}}
	if err := svc.ValidateDescriptionLimits(); err != nil {
		t.Fatal(err)
	}
	if err := (&registry.Service{MaxExternalDescription: 5000, MaxExternalDescriptionCap: 4096}).ValidateDescriptionLimits(); err == nil {
		t.Fatal("a default above the cap was accepted at start")
	}
	verifier, _ := identity.NewDevAdminVerifier("idp-mcp-dev", "idp-mcp-registry", []byte(adminSecret))
	reg := httptest.NewServer((&registry.API{Svc: svc, Admin: verifier, Log: log}).Handler())
	defer reg.Close()
	a := admin{t: t, base: reg.URL, tenant: tenant}
	alice, bob := a.token("alice", "operator"), a.token("bob", "reviewer")

	up := hostileserver.New()
	defer up.Close()
	tools := up.Tools()
	setDesc := func(n int) { tools[0]["description"] = strings.Repeat("d", n); up.SetTools(tools) }
	// each registration needs its own endpoint; the servers register on the same hostile upstream under other paths
	n := 0
	reg1 := func(name string, extra map[string]any, want int) map[string]any {
		n++
		body := map[string]any{"displayName": "Partner", "targetName": name, "endpoint": strings.Replace(up.URL(), "/mcp", "", 1) + "/x" + string(rune('a'+n)) + "/mcp", "class": "external"}
		for k, v := range extra {
			body[k] = v
		}
		return a.do(alice, "POST", "/api/v1/servers", body, want)
	}

	// registration: above the cap, not positive and for an internal server are refused; absent is the default
	if r := reg1("over-cap", map[string]any{"maxDescriptionBytes": 4097}, 400); !strings.Contains(r["error"].(string), "cap of 4096") {
		t.Fatalf("%v", r)
	}
	reg1("zero", map[string]any{"maxDescriptionBytes": 0}, 400)
	if r := a.do(alice, "POST", "/api/v1/servers", map[string]any{"displayName": "Ours", "targetName": "ours", "endpoint": up.URL() + "/o/mcp", "maxDescriptionBytes": 2048}, 400); !strings.Contains(r["error"].(string), "class external only") {
		t.Fatalf("an internal server took the field: %v", r)
	}
	plain := reg1("plain", nil, 201)
	if plain["maxDescriptionBytes"] != nil {
		t.Fatalf("%v", plain)
	}
	setDesc(1546)
	if r := a.do(alice, "POST", "/api/v1/servers/"+plain["serverId"].(string)+"/discover", nil, 422); !strings.Contains(r["error"].(string), "1546 bytes, more than the 1024 allowed") {
		t.Fatalf("the default did not refuse 1546 bytes: %v", r)
	}

	// a server with its own limit: 1546 is accepted, one over the limit is not
	srv := reg1("wide", map[string]any{"maxDescriptionBytes": 2048}, 201)
	sid := srv["serverId"].(string)
	if srv["maxDescriptionBytes"] != float64(2048) {
		t.Fatalf("%v", srv)
	}
	if r := a.do(alice, "POST", "/api/v1/servers/"+sid+"/discover", nil, 200); r["lifecycle"] != "REVIEWED" {
		t.Fatalf("%v", r)
	}
	setDesc(2049)
	if r := a.do(alice, "POST", "/api/v1/servers/"+sid+"/discover", nil, 422); !strings.Contains(r["error"].(string), "2049 bytes, more than the 2048 allowed") {
		t.Fatalf("%v", r)
	}
	setDesc(2048)
	a.do(alice, "POST", "/api/v1/servers/"+sid+"/discover", nil, 200)

	// the reviewer sees the limit, and the snapshot carries what it was checked against
	view := a.do(bob, "GET", "/api/v1/servers/"+sid+"/catalog", nil, 200)
	dl, _ := view["descriptionLimit"].(map[string]any)
	if dl["bytes"] != float64(2048) || dl["deploymentDefault"] != float64(1024) || dl["serverSetting"] != float64(2048) || dl["cap"] != float64(4096) {
		t.Fatalf("the review answer: %v", view["descriptionLimit"])
	}
	latest := view["latest"].(map[string]any)
	if latest["descriptionLimit"] != float64(2048) {
		t.Fatalf("the snapshot does not record its limit: %v", latest["descriptionLimit"])
	}
	a.do(bob, "POST", "/api/v1/servers/"+sid+"/approve", map[string]string{"digest": latest["digest"].(string)}, 200)
	if v := a.do(bob, "GET", "/api/v1/servers/"+sid+"/catalog", nil, 200); v["approved"].(map[string]any)["descriptionLimit"] != float64(2048) {
		t.Fatalf("approval did not pin the limit: %v", v["approved"])
	}

	// drift: the approved server grows a description over its limit; the re-discovery uses the server's limit
	setDesc(2049)
	a.do(alice, "POST", "/api/v1/servers/"+sid+"/discover", nil, 422)

	// a change: refused for the cap, for a bad value and for an operator-less caller; audited; invalidates the approval
	a.do(alice, "PATCH", "/api/v1/servers/"+sid, map[string]any{"maxDescriptionBytes": 4097}, 400)
	a.do(alice, "PATCH", "/api/v1/servers/"+sid, map[string]any{}, 400)
	a.do(bob, "PATCH", "/api/v1/servers/"+sid, map[string]any{"maxDescriptionBytes": 3000}, 403)
	if r := a.do(alice, "PATCH", "/api/v1/servers/"+sid, map[string]any{"maxDescriptionBytes": 2048}, 200); r["lifecycle"] != "APPROVED" {
		t.Fatalf("a change to the same value invalidated the approval: %v", r)
	}
	if r := a.do(alice, "PATCH", "/api/v1/servers/"+sid, map[string]any{"maxDescriptionBytes": 3000}, 200); r["lifecycle"] != "DRAFT" || r["maxDescriptionBytes"] != float64(3000) {
		t.Fatalf("%v", r)
	}
	a.do(bob, "POST", "/api/v1/servers/"+sid+"/approve", map[string]string{"digest": latest["digest"].(string)}, 409)
	if r := a.do(alice, "POST", "/api/v1/servers/"+sid+"/discover", nil, 200); r["lifecycle"] != "REVIEWED" {
		t.Fatalf("the catalog was not reviewed again: %v", r)
	}
	ours := a.do(alice, "POST", "/api/v1/servers", map[string]any{"displayName": "Ours", "targetName": "ours2", "endpoint": strings.Replace(up.URL(), "/mcp", "", 1) + "/o2/mcp"}, 201)
	a.do(alice, "PATCH", "/api/v1/servers/"+ours["serverId"].(string), map[string]any{"maxDescriptionBytes": 2048}, 400)

	// the audit has the registration's value and the change
	var registered, changed bool
	for _, e := range a.do(bob, "GET", "/api/v1/audit-events", nil, 200)["items"].([]any) {
		m := e.(map[string]any)
		d, _ := m["detail"].(map[string]any)
		switch m["action"] {
		case "server.register":
			registered = registered || d["maxDescriptionBytes"] == float64(2048)
		case "server.update":
			changed = changed || (d["maxDescriptionBytes"] == float64(3000) && d["was"] == float64(2048) && d["lifecycleWas"] == "APPROVED")
		}
	}
	if !registered || !changed {
		t.Fatalf("audit: registered %v, changed %v", registered, changed)
	}
}
