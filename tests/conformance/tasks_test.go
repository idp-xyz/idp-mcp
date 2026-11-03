package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"idp-mcp/adapters/identity"
	"idp-mcp/internal/client"
	"idp-mcp/internal/federation"
	"idp-mcp/internal/gateway"
	"idp-mcp/internal/policy"
	"idp-mcp/internal/release"
	"idp-mcp/internal/server"
	"idp-mcp/tests/fixtures/taskserver"
)

// The tasks extension scenarios of the official suite (extension, not part of the frozen 37).
// tasks-status-notifications is skipped by the suite itself (pending its own rewrite).
var taskScenarios = []string{"tasks-capability-negotiation", "tasks-wire-fields", "tasks-request-state-removal", "tasks-dispatch-and-envelope",
	"tasks-request-headers", "tasks-required-task-error", "tasks-mrtr-input", "tasks-lifecycle"}

func runScenarios(t *testing.T, root, edgeURL, label string) (passed []string, failed map[string][]check) {
	t.Helper()
	out, _ := filepath.Abs(filepath.Join("..", "..", "build", "conformance", "tasks-"+label+"-"+time.Now().UTC().Format("20060102T150405Z")))
	_ = os.MkdirAll(out, 0o755)
	logFile, _ := os.Create(filepath.Join(out, "runner.log"))
	defer logFile.Close()
	for _, sc := range taskScenarios {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		cmd := exec.CommandContext(ctx, "node", filepath.Join(root, "dist", "index.js"), "server", "--url", edgeURL, "--scenario", sc, "--output-dir", out)
		cmd.Env = append(os.Environ(), "NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost")
		cmd.Stdout, cmd.Stderr = logFile, logFile
		_ = cmd.Run()
		cancel()
	}
	passed, failed = score(out, taskScenarios)
	var bad []string
	for s := range failed {
		bad = append(bad, s)
	}
	sort.Strings(bad)
	for _, s := range bad {
		for _, c := range failed[s] {
			t.Logf("FAIL [%s] %-36s %s %s: %.300s", label, s, c.ID, c.Status, c.ErrorMessage)
		}
	}
	t.Logf("tasks extension conformance [%s]: %d/%d scenarios pass; evidence %s", label, len(passed), len(taskScenarios), out)
	return passed, failed
}

// TestTasksExtensionConformance scores the official tasks-extension scenarios against the reference
// task server directly (the fixture must be conformant on its own) and through the gateway.
func TestTasksExtensionConformance(t *testing.T) {
	root := os.Getenv("IDP_CONFORMANCE_ROOT")
	if root == "" {
		t.Skip("set IDP_CONFORMANCE_ROOT (make conformance)")
	}
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	fixture := httptest.NewServer(taskserver.New().Handler())
	defer fixture.Close()

	if _, failed := runScenarios(t, root, fixture.URL+"/mcp", "direct"); len(failed) > 0 {
		t.Fatalf("the reference task server itself fails %d scenario(s); the gateway run would be meaningless", len(failed))
	}

	// through the gateway: a release pinning the fixture, native names, everything granted
	endpoint := fixture.URL + "/mcp"
	pol := &policy.Upstream{AllowedHosts: map[string]bool{"127.0.0.1": true}, PrivateHosts: map[string]bool{}, DevMode: true}
	up := &client.Client{HTTP: client.NewHTTPClient(pol, 10*time.Second), Info: server.ServerInfo{Name: "setup", Version: "1"}}
	disc, err := up.Discover(ctx, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	raws, err := up.ListTools(ctx, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	tools, err := federation.NormalizeTools(raws)
	if err != nil {
		t.Fatal(err)
	}
	caps := federation.Capabilities(disc.Capabilities)
	if !strings.Contains(strings.Join(caps, ","), release.CapTasks) {
		t.Fatalf("fixture does not advertise the tasks extension: %v", caps)
	}
	digest, _ := release.Catalog{Tools: tools}.Digest()
	doc := &release.Document{SchemaVersion: release.SchemaVersion, ReleaseID: "tasks", TenantID: "t", GatewayID: "g",
		CreatedAt: time.Now().UTC().Format(time.RFC3339), CreatedBy: "harness", ApprovedBy: "harness-reviewer",
		DriftAction: "block", ToolNaming: release.NamingNative,
		Targets: []release.Target{{Name: "tasks", ServerID: "fx", Endpoint: endpoint, Network: release.NetworkLoopback, SnapshotDigest: digest, Tools: tools, Capabilities: caps}},
		Grants:  []release.Grant{{Target: "tasks", Tools: taskserver.ToolNames(), Roles: []string{"conformance"}}},
		Auth:    release.Auth{Mode: "api-key", APIKeys: []release.APIKey{{ID: "k", Subject: "official-runner", Roles: []string{"conformance"}, SHA256: identity.HashKey(key)}}}}
	env, err := release.Seal(doc)
	if err != nil {
		t.Fatal(err)
	}
	g := gateway.New(gateway.Config{GatewayID: "g", Info: server.ServerInfo{Name: "idp-mcp-gateway", Version: "conformance"}, DevMode: true, CallTimeout: 130 * time.Second, Log: log})
	if err := g.Activate(env); err != nil {
		t.Fatal(err)
	}
	gw := httptest.NewServer(g.Handler())
	defer gw.Close()
	target, _ := url.Parse(gw.URL)
	proxy := &httputil.ReverseProxy{FlushInterval: -1, Rewrite: func(r *httputil.ProxyRequest) {
		r.SetURL(target)
		r.Out.Host = r.In.Host
		if r.Out.Header.Get("Authorization") == "" {
			r.Out.Header.Set("Authorization", "Bearer "+key)
		}
	}}
	edge := httptest.NewServer(proxy)
	defer edge.Close()
	passed, failed := runScenarios(t, root, edge.URL+"/mcp", "gateway")
	if len(failed) > 0 {
		b, _ := json.MarshalIndent(failed, "", " ")
		t.Fatalf("%d/%d through the gateway; failures:\n%s", len(passed), len(taskScenarios), b)
	}
	fmt.Println()
}
