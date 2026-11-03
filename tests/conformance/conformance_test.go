// Package conformance scores the gateway with the official MCP conformance suite (2026-07-28 frozen
// requirements, 37 server scenarios).
//
// Chain: official runner -> authproxy (test harness) -> mcp-gateway (in process) -> Everything Server.
// The runner cannot send credentials, so the harness proxy adds a data-plane API key and otherwise
// forwards byte for byte (Host and Origin untouched, streams flushed as they arrive). The gateway runs
// its normal authenticated path; there is no unauthenticated mode in the product.
//
// Release: one target (the Everything Server), native tool naming, every tool, prompt and resource
// granted to the key's role.
//
//	IDP_CONFORMANCE_ROOT   mcp-conformance checkout with dist/index.js and requirements/2026-07-28.yaml
//	IDP_REFERENCE_SERVER   mcp-everything-server executable
//	IDP_CONFORMANCE_MIN    scenarios that must pass (default 37)
package conformance

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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
)

const key = "idpk_conformance-harness-key-0123456789"

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// requiredScenarios reads the frozen server list of requirements/2026-07-28.yaml (a plain YAML list
// under "server:"; parsed by hand to keep the module free of a YAML dependency).
func requiredScenarios(t *testing.T, path string) []string {
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	in := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "server:"):
			in = true
		case in && strings.HasPrefix(strings.TrimSpace(line), "- "):
			out = append(out, strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "- ")), `"'`))
		case in && line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "#"):
			in = false
		}
	}
	return out
}

type check struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	ErrorMessage string `json:"errorMessage"`
}

var known = map[string]bool{"SUCCESS": true, "FAILURE": true, "WARNING": true, "SKIPPED": true, "INFO": true}

func score(dir string, required []string) (passed []string, failed map[string][]check) {
	failed = map[string][]check{}
	for _, s := range required {
		re := regexp.MustCompile(`^server-` + regexp.QuoteMeta(s) + `-\d{4}`)
		var files []string
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if re.MatchString(e.Name()) {
				files = append(files, filepath.Join(dir, e.Name(), "checks.json"))
			}
		}
		if len(files) != 1 {
			failed[s] = []check{{ID: "(missing)", Status: "MISSING", ErrorMessage: fmt.Sprintf("%d result directories", len(files))}}
			continue
		}
		raw, err := os.ReadFile(files[0])
		var checks []check
		if err == nil {
			err = json.Unmarshal(raw, &checks)
		}
		if err != nil || len(checks) == 0 {
			failed[s] = []check{{ID: "(unreadable)", Status: "MISSING"}}
			continue
		}
		var bad []check
		success := false
		for _, c := range checks {
			if !known[c.Status] || c.Status == "FAILURE" {
				bad = append(bad, c)
			}
			success = success || c.Status == "SUCCESS"
		}
		if len(bad) == 0 && !success {
			bad = []check{{ID: "(scenario)", Status: "NO_SUCCESS"}}
		}
		if len(bad) > 0 {
			failed[s] = bad
		} else {
			passed = append(passed, s)
		}
	}
	return passed, failed
}

func TestOfficialConformance(t *testing.T) {
	root, ref := os.Getenv("IDP_CONFORMANCE_ROOT"), os.Getenv("IDP_REFERENCE_SERVER")
	if root == "" || ref == "" {
		t.Skip("set IDP_CONFORMANCE_ROOT and IDP_REFERENCE_SERVER (make conformance)")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// the reference server, on loopback
	refPort := freePort(t)
	cmd := exec.CommandContext(ctx, ref, "--port", strconv.Itoa(refPort), "--log-level", "WARNING")
	cmd.Env = append(os.Environ(), "NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	endpoint := fmt.Sprintf("http://127.0.0.1:%d/mcp", refPort)
	pol := &policy.Upstream{AllowedHosts: map[string]bool{"127.0.0.1": true}, PrivateHosts: map[string]bool{}, DevMode: true}
	up := &client.Client{HTTP: client.NewHTTPClient(pol, 10*time.Second), Info: server.ServerInfo{Name: "conformance-setup", Version: "1"}}
	var disc *client.Discovery
	for i := 0; i < 100; i++ {
		var err error
		if disc, err = up.Discover(ctx, endpoint); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if disc == nil {
		t.Fatal("reference server did not come up")
	}

	// a release pinning the reference server's catalog: native names, everything granted
	raws, err := up.ListTools(ctx, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	tools, err := federation.NormalizeTools(raws)
	if err != nil {
		t.Fatal(err)
	}
	var prompts []server.Prompt
	if _, ok := disc.Capabilities[release.CapPrompts]; ok {
		praws, err := up.ListPrompts(ctx, endpoint)
		if err != nil {
			t.Fatal(err)
		}
		if prompts, err = federation.NormalizePrompts(praws); err != nil {
			t.Fatal(err)
		}
	}
	var resources []server.Resource
	var templates []server.ResourceTemplate
	if _, ok := disc.Capabilities[release.CapResources]; ok {
		rraws, err := up.List(ctx, endpoint, "resources/list", "resources")
		if err != nil {
			t.Fatal(err)
		}
		if resources, err = federation.NormalizeResources(rraws); err != nil {
			t.Fatal(err)
		}
		traws, err := up.List(ctx, endpoint, "resources/templates/list", "resourceTemplates")
		if err != nil {
			t.Fatal(err)
		}
		if templates, err = federation.NormalizeResourceTemplates(traws); err != nil {
			t.Fatal(err)
		}
	}
	digest, _ := release.Catalog{Tools: tools, Prompts: prompts, Resources: resources, ResourceTemplates: templates}.Digest()
	var names []string
	for _, tl := range tools {
		names = append(names, tl.Name)
	}
	caps := federation.Capabilities(disc.Capabilities)
	doc := &release.Document{SchemaVersion: release.SchemaVersion, ReleaseID: "conformance", TenantID: "t", GatewayID: "g",
		CreatedAt: time.Now().UTC().Format(time.RFC3339), CreatedBy: "harness", ApprovedBy: "harness-reviewer",
		DriftAction: "block", ToolNaming: release.NamingNative,
		Targets: []release.Target{{Name: "reference", ServerID: "ref", Endpoint: endpoint, Network: release.NetworkLoopback,
			SnapshotDigest: digest, Tools: tools, Prompts: prompts, Resources: resources, ResourceTemplates: templates, Capabilities: caps}},
		Grants: []release.Grant{{Target: "reference", Tools: names, Prompts: []string{"*"}, Resources: true, Roles: []string{"conformance"}}},
		Auth:   release.Auth{Mode: "api-key", APIKeys: []release.APIKey{{ID: "k", Subject: "official-runner", Roles: []string{"conformance"}, SHA256: identity.HashKey(key)}}}}
	env, err := release.Seal(doc)
	if err != nil {
		t.Fatal(err)
	}
	g := gateway.New(gateway.Config{GatewayID: "g", Info: server.ServerInfo{Name: "idp-mcp-gateway", Version: "conformance"},
		DevMode: true, CallTimeout: 30 * time.Second, Log: log})
	if err := g.Activate(env); err != nil {
		t.Fatal(err)
	}
	gw := httptest.NewServer(g.Handler())
	defer gw.Close()

	// the harness proxy: adds the key, preserves Host/Origin, flushes immediately
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

	out, _ := filepath.Abs(filepath.Join("..", "..", "build", "conformance", time.Now().UTC().Format("20060102T150405Z")))
	_ = os.MkdirAll(out, 0o755)
	runner := exec.CommandContext(ctx, "node", filepath.Join(root, "dist", "index.js"), "server", "--url", edge.URL+"/mcp",
		"--requirements", server.ProtocolVersion, "--output-dir", out)
	runner.Env = append(os.Environ(), "NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost")
	logFile, _ := os.Create(filepath.Join(out, "runner.log"))
	runner.Stdout, runner.Stderr = logFile, logFile
	runErr := runner.Run()
	logFile.Close()

	required := requiredScenarios(t, filepath.Join(root, "requirements", server.ProtocolVersion+".yaml"))
	if len(required) != 37 {
		t.Fatalf("expected 37 frozen server scenarios, read %d", len(required))
	}
	passed, failed := score(out, required)
	var bad []string
	for s := range failed {
		bad = append(bad, s)
	}
	sort.Strings(bad)
	for _, s := range bad {
		for _, c := range failed[s] {
			t.Logf("FAIL %-48s %s %s: %.300s", s, c.ID, c.Status, c.ErrorMessage)
		}
	}
	t.Logf("official conformance (2026-07-28): %d/37 scored scenarios pass; runner exit %v; evidence %s", len(passed), runErr, out)
	min := 37
	if v, err := strconv.Atoi(os.Getenv("IDP_CONFORMANCE_MIN")); err == nil {
		min = v
	}
	if len(passed) < min {
		t.Errorf("%d/37 < required %d", len(passed), min)
	}
}
