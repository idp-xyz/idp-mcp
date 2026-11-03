package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
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
	"idp-mcp/internal/invocation"
	"idp-mcp/internal/policy"
	"idp-mcp/internal/registry"
	"idp-mcp/internal/server"
	"idp-mcp/internal/transport"
	"idp-mcp/internal/transport/tlstest"
)

func tlsClient(t *testing.T, ca, cert, key string) *http.Client {
	cfg, err := transport.ClientTLS(ca, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: cfg}}
}

// TestTLSEverywhere: admin API over TLS, gateway<->registry over mutual TLS with the certificate
// bound to the gateway credential, an https upstream behind a private CA, and an https data plane.
func TestTLSEverywhere(t *testing.T) {
	ctx := context.Background()
	_, serviceURL := scratchDB(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := postgres.Open(ctx, serviceURL)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ca := tlstest.NewCA(t, "idp-test")
	sc, sk := ca.Issue(t, "server", true)
	serverTLS, _ := transport.ServerTLS(sc, sk, "")
	upstreamTLS, _ := transport.ClientTLS(ca.File, "", "")

	// https upstream signed by the private CA
	up := &upstream{desc: "Return the text unchanged"}
	up.srv = httptest.NewUnstartedServer(up.handler())
	up.srv.TLS = serverTLS
	up.srv.StartTLS()
	defer up.srv.Close()

	tenant := seed(t, serviceURL)
	pol := &policy.Upstream{AllowedHosts: map[string]bool{"127.0.0.1": true}, PrivateHosts: map[string]bool{}, DevMode: true}
	svc := &registry.Service{Store: store, Policy: pol, DeployTimeout: 8 * time.Second, PollEvery: 100 * time.Millisecond, Log: log,
		Upstream: &client.Client{HTTP: client.NewHTTPClient(pol, 5*time.Second, upstreamTLS), Info: server.ServerInfo{Name: "registry", Version: "it"}}}
	verifier, _ := identity.NewDevAdminVerifier("idp-mcp-dev", "idp-mcp-registry", []byte(adminSecret))
	regTLS, err := transport.ServerTLS(sc, sk, ca.File)
	if err != nil {
		t.Fatal(err)
	}
	reg := httptest.NewUnstartedServer((&registry.API{Svc: svc, Admin: verifier, Log: log, RequireGatewayCert: true}).Handler())
	reg.TLS = regTLS
	reg.StartTLS()
	defer reg.Close()
	a := admin{t: t, base: reg.URL, tenant: tenant, client: tlsClient(t, ca.File, "", "")} // admins need no client certificate
	alice, bob, carol := a.token("alice", "operator"), a.token("bob", "reviewer"), a.token("carol", "admin")

	sid := a.do(alice, "POST", "/api/v1/servers", map[string]string{"displayName": "tls", "targetName": "minimal", "endpoint": up.srv.URL + "/mcp"}, 201)["serverId"].(string)
	a.do(alice, "POST", "/api/v1/servers/"+sid+"/discover", nil, 200) // https discovery with the private CA
	a.do(bob, "POST", "/api/v1/servers/"+sid+"/approve", nil, 200)
	gr := a.do(alice, "POST", "/api/v1/grants", map[string]any{"serverId": sid, "tools": []string{"echo"}, "roles": []string{"operator"}}, 201)
	a.do(bob, "POST", "/api/v1/grants/"+gr["grantId"].(string)+"/approve", nil, 200)
	gw1 := a.do(carol, "POST", "/api/v1/gateways", map[string]any{"name": "edge-1", "authMode": "api-key"}, 201)
	gw2 := a.do(carol, "POST", "/api/v1/gateways", map[string]any{"name": "edge-2", "authMode": "api-key"}, 201)
	gid := gw1["gateway"].(map[string]any)["gatewayId"].(string)
	token := gw1["token"].(string)
	key := a.do(carol, "POST", "/api/v1/gateways/"+gid+"/api-keys", map[string]any{"subject": "agent", "roles": []string{"operator"}}, 201)["key"].(string)
	rid := a.do(alice, "POST", "/api/v1/releases", map[string]string{"gatewayId": gid}, 201)["releaseId"].(string)
	a.do(bob, "POST", "/api/v1/releases/"+rid+"/approve", nil, 200)

	// the internal API: token alone, token + foreign certificate, plaintext - all refused
	desired := func(c *http.Client) (int, error) {
		req, _ := http.NewRequest("GET", reg.URL+gateway.PathDesired, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := c.Do(req)
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}
	if st, _ := desired(tlsClient(t, ca.File, "", "")); st != 401 {
		t.Fatalf("token without a client certificate: %d", st)
	}
	c2, k2 := ca.Issue(t, "gw2", false, transport.GatewayURI(gw2["gateway"].(map[string]any)["gatewayId"].(string)))
	if st, _ := desired(tlsClient(t, ca.File, c2, k2)); st != 401 {
		t.Fatalf("token of edge-1 with the certificate of edge-2: %d", st)
	}
	if _, err := desired(&http.Client{Transport: &http.Transport{Proxy: nil}}); err == nil {
		t.Fatal("certificate of an unknown CA trusted by default")
	}
	plain := strings.Replace(reg.URL, "https://", "http://", 1)
	if resp, err := http.Get(plain + "/api/v1/health"); err == nil && resp.StatusCode == 200 {
		t.Fatal("plaintext HTTP served by a TLS listener")
	}

	// the right certificate: the gateway follows its release over mutual TLS
	c1, k1 := ca.Issue(t, "gw1", false, transport.GatewayURI(gid))
	sync := &gateway.RegistrySync{BaseURL: reg.URL, Token: token, HTTP: tlsClient(t, ca.File, c1, k1),
		PollInterval: 150 * time.Millisecond, HeartbeatInterval: 150 * time.Millisecond, Log: log}
	rec := invocation.NewBatcher(sync.Sink(), log)
	rec.Interval = 200 * time.Millisecond
	g := gateway.New(gateway.Config{GatewayID: gid, Info: server.ServerInfo{Name: "gw", Version: "it"}, DevMode: true,
		CallTimeout: 5 * time.Second, DriftInterval: 300 * time.Millisecond, Recorder: rec, Dropped: rec.Dropped, UpstreamTLS: upstreamTLS, Log: log})
	sync.Gateway = g
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go rec.Run(runCtx)
	go g.RunDriftChecks(runCtx)
	go sync.Run(runCtx)
	if d := a.do(carol, "POST", "/api/v1/releases/"+rid+"/deploy", nil, 200); d["release"].(map[string]any)["status"] != "GOOD" {
		t.Fatalf("deploy over mTLS: %v", d)
	}

	// https data plane -> https upstream
	gw := httptest.NewUnstartedServer(g.Handler())
	gw.TLS = serverTLS.Clone()
	gw.StartTLS()
	defer gw.Close()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"minimal__echo","arguments":{"text":"over tls"},` + meta + `}}`
	req, _ := http.NewRequest("POST", gw.URL+"/mcp", strings.NewReader(body))
	req.Header = client.Headers("tools/call", "minimal__echo")
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := tlsClient(t, ca.File, "", "").Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if !strings.Contains(strings.ToLower(fmtJSON(out)), "over tls") {
		t.Fatalf("call over TLS: %d %v", resp.StatusCode, out)
	}
	if resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
		t.Fatal("data plane not on TLS 1.2+")
	}
}

func fmtJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// seed creates a tenant through the owner connection derived from the scratch database.
func seed(t *testing.T, serviceURL string) string {
	t.Helper()
	owner := ownerFor(t, serviceURL)
	id, err := postgres.SeedTenant(context.Background(), owner, registry.NewID(), "tls-acme")
	if err != nil {
		t.Fatal(err)
	}
	return id
}
