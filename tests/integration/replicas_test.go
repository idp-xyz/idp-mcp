package integration

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"idp-mcp/adapters/identity"
	"idp-mcp/adapters/store/postgres"
	"idp-mcp/internal/client"
	"idp-mcp/internal/gateway"
	"idp-mcp/internal/policy"
	"idp-mcp/internal/registry"
	"idp-mcp/internal/server"
)

// replica runs one gateway instance of a shared record.
type replica struct {
	g      *gateway.Gateway
	cancel context.CancelFunc
}

func startReplica(t *testing.T, regURL, token, gid, instance string, poll time.Duration) *replica {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sync := &gateway.RegistrySync{BaseURL: regURL, Token: token, HTTP: &http.Client{Timeout: 5 * time.Second},
		PollInterval: poll, HeartbeatInterval: 150 * time.Millisecond, Log: log}
	g := gateway.New(gateway.Config{GatewayID: gid, InstanceID: instance, Info: server.ServerInfo{Name: "gw", Version: "it"}, DevMode: true,
		CallTimeout: 5 * time.Second, DriftInterval: 300 * time.Millisecond, Log: log})
	sync.Gateway = g
	ctx, cancel := context.WithCancel(context.Background())
	go g.RunDriftChecks(ctx)
	go sync.Run(ctx)
	t.Cleanup(cancel)
	return &replica{g: g, cancel: cancel}
}

// TestReplicasMustAllAttest: a deployment is GOOD only when every live replica of the gateway record
// runs the release; a lagging replica fails it by name; a replica that stops heartbeating stops
// counting after the staleness window.
func TestReplicasMustAllAttest(t *testing.T) {
	ctx := context.Background()
	_, serviceURL := scratchDB(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := postgres.Open(ctx, serviceURL)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	tenant := seed(t, serviceURL)
	up := newUpstream(t)
	pol := &policy.Upstream{AllowedHosts: map[string]bool{"127.0.0.1": true}, PrivateHosts: map[string]bool{}, DevMode: true}
	svc := &registry.Service{Store: store, Policy: pol, DeployTimeout: 3 * time.Second, PollEvery: 100 * time.Millisecond, StaleAfter: time.Second, Log: log,
		Upstream: &client.Client{HTTP: client.NewHTTPClient(pol, 5*time.Second), Info: server.ServerInfo{Name: "registry", Version: "it"}}}
	verifier, _ := identity.NewDevAdminVerifier("idp-mcp-dev", "idp-mcp-registry", []byte(adminSecret))
	reg := httptest.NewServer((&registry.API{Svc: svc, Admin: verifier, Log: log}).Handler())
	defer reg.Close()
	a := admin{t: t, base: reg.URL, tenant: tenant}
	alice, bob, carol := a.token("alice", "operator"), a.token("bob", "reviewer"), a.token("carol", "admin")

	sid := a.do(alice, "POST", "/api/v1/servers", map[string]string{"displayName": "m", "targetName": "minimal", "endpoint": up.srv.URL + "/mcp"}, 201)["serverId"].(string)
	a.do(alice, "POST", "/api/v1/servers/"+sid+"/discover", nil, 200)
	a.do(bob, "POST", "/api/v1/servers/"+sid+"/approve", nil, 200)
	gr := a.do(alice, "POST", "/api/v1/grants", map[string]any{"serverId": sid, "tools": []string{"echo"}, "roles": []string{"operator"}}, 201)
	a.do(bob, "POST", "/api/v1/grants/"+gr["grantId"].(string)+"/approve", nil, 200)
	gw := a.do(carol, "POST", "/api/v1/gateways", map[string]any{"name": "edge", "authMode": "api-key"}, 201)
	gid, token := gw["gateway"].(map[string]any)["gatewayId"].(string), gw["token"].(string)
	a.do(carol, "POST", "/api/v1/gateways/"+gid+"/api-keys", map[string]any{"subject": "agent", "roles": []string{"operator"}}, 201)
	release := func() string {
		rid := a.do(alice, "POST", "/api/v1/releases", map[string]string{"gatewayId": gid}, 201)["releaseId"].(string)
		a.do(bob, "POST", "/api/v1/releases/"+rid+"/approve", nil, 200)
		return rid
	}

	// two replicas follow the record: both must be on the release before it is GOOD
	r1 := startReplica(t, reg.URL, token, gid, "pod-a", 150*time.Millisecond)
	r2 := startReplica(t, reg.URL, token, gid, "pod-b", 150*time.Millisecond)
	rid := release()
	dep := a.do(carol, "POST", "/api/v1/releases/"+rid+"/deploy", nil, 200)
	if dep["release"].(map[string]any)["status"] != "GOOD" {
		t.Fatalf("%v", dep)
	}
	g := a.do(carol, "GET", "/api/v1/gateways/"+gid, nil, 200)
	instances := g["instances"].([]any)
	if len(instances) != 2 || instances[0].(map[string]any)["instanceId"] != "pod-a" || instances[1].(map[string]any)["live"] != true {
		t.Fatalf("instances %v", instances)
	}

	// a third replica that heartbeats but never polls stays on an older release: the next
	// deployment fails and names it; the desired state returns to the previous release
	lagging := startReplica(t, reg.URL, token, gid, "pod-c", time.Hour)
	time.Sleep(400 * time.Millisecond) // let pod-c heartbeat
	rid2 := release()
	failed := a.do(carol, "POST", "/api/v1/releases/"+rid2+"/deploy", nil, 502)
	if msg := failed["error"].(string); !strings.Contains(msg, "pod-c") || !strings.Contains(msg, "not yet on the release") {
		t.Fatalf("lagging replica not named: %s", msg)
	}
	if res := failed["result"].(map[string]any); res["rolledBackToPrevious"] != true {
		t.Fatalf("no rollback: %v", res)
	}
	_ = r1
	_ = r2

	// once the lagging replica is gone for longer than StaleAfter, it no longer counts
	lagging.cancel()
	time.Sleep(1500 * time.Millisecond)
	a.do(carol, "GET", "/api/v1/gateways/"+gid, nil, 200)
	rid3 := release()
	if dep := a.do(carol, "POST", "/api/v1/releases/"+rid3+"/deploy", nil, 200); dep["release"].(map[string]any)["status"] != "GOOD" {
		t.Fatalf("after the stale replica dropped out: %v", dep)
	}
	g = a.do(carol, "GET", "/api/v1/gateways/"+gid, nil, 200)
	live := 0
	for _, in := range g["instances"].([]any) {
		if in.(map[string]any)["live"] == true {
			live++
		}
	}
	if live != 2 {
		t.Fatalf("%d live instances, want 2 (pod-c stale)", live)
	}
}
