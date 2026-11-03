// Package e2e drives the compose topology (deploy/e2e.sh) through its published ports only: the
// registry admin API and the gateway's /mcp. Upstreams are real MCP SDK servers: minimal (Node SDK,
// echo/sum) and reference (Python SDK Everything Server).
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"idp-mcp/adapters/identity"
	"idp-mcp/internal/client"
	"idp-mcp/internal/transport"
)

type env struct {
	t                                            *testing.T
	registry, gateway, tenant, gatewayID, secret string
	http                                         *http.Client // trusts IDP_E2E_CA when set
}

func setup(t *testing.T) *env {
	e := &env{t: t, registry: os.Getenv("IDP_E2E_REGISTRY"), gateway: os.Getenv("IDP_E2E_GATEWAY"),
		tenant: os.Getenv("IDP_E2E_TENANT"), gatewayID: os.Getenv("IDP_E2E_GATEWAY_ID"), secret: os.Getenv("IDP_E2E_ADMIN_SECRET")}
	if e.registry == "" {
		t.Skip("run through deploy/e2e.sh")
	}
	e.http = &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{Proxy: nil}}
	if ca := os.Getenv("IDP_E2E_CA"); ca != "" {
		if cfg, err := transport.ClientTLS(ca, "", ""); err == nil {
			e.http.Transport = &http.Transport{Proxy: nil, TLSClientConfig: cfg}
		}
	}
	return e
}

func (e *env) token(sub string, roles ...string) string {
	tok, err := identity.DevAdminToken([]byte(e.secret), "idp-mcp-dev", "idp-mcp-registry", sub, e.tenant, roles, 10*time.Minute)
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}

func (e *env) api(tok, method, path string, body any, want int) map[string]any {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.registry+path, rd)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.http.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		e.t.Fatalf("%s %s: HTTP %d (want %d): %s", method, path, resp.StatusCode, want, raw)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

const meta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"idp-mcp-e2e","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}`

func (e *env) mcp(key, method, params, name string) (int, map[string]any) {
	if params == "" {
		params = "{" + meta + "}"
	}
	req, _ := http.NewRequest("POST", e.gateway+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":42,"method":"`+method+`","params":`+params+`}`))
	req.Header = client.Headers(method, name)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := e.http.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	msg, err := transport.ParseMessage(resp.Header.Get("Content-Type"), raw)
	var out map[string]any
	if err == nil {
		_ = json.Unmarshal(msg, &out)
	}
	return resp.StatusCode, out
}

func call(name, args string) string {
	return `{"name":"` + name + `","arguments":` + args + `,` + meta + `}`
}

func TestComposeEndToEnd(t *testing.T) {
	e := setup(t)
	op, rev, adm := e.token("alice", "operator"), e.token("bob", "reviewer"), e.token("carol", "admin")

	// register, discover and approve both real upstreams
	ids := map[string]string{}
	for name, endpoint := range map[string]string{"minimal": "http://minimal:3111/mcp", "reference": "http://reference:3221/mcp"} {
		s := e.api(op, "POST", "/api/v1/servers", map[string]string{"displayName": name, "targetName": name, "endpoint": endpoint}, 201)
		ids[name] = s["serverId"].(string)
		d := e.api(op, "POST", "/api/v1/servers/"+ids[name]+"/discover", nil, 200)
		t.Logf("%s: network=%s tools=%d digest=%v", name, s["network"], len(d["toolNames"].([]any)), d["snapshotDigest"])
		e.api(rev, "POST", "/api/v1/servers/"+ids[name]+"/approve", nil, 200)
	}
	grants := []map[string]any{
		{"serverId": ids["minimal"], "tools": []string{"echo", "sum"}, "roles": []string{"operator"}},
		{"serverId": ids["reference"], "tools": []string{"test_simple_text"}, "roles": []string{"operator"}},
		{"serverId": ids["reference"], "prompts": []string{"*"}, "resources": true, "roles": []string{"operator"}}, // M2
	}
	e.api(op, "POST", "/api/v1/grants", map[string]any{"serverId": ids["minimal"], "prompts": []string{"*"}, "roles": []string{"operator"}}, 400) // minimal offers no prompts
	for _, body := range grants {
		g := e.api(op, "POST", "/api/v1/grants", body, 201)
		e.api(rev, "POST", "/api/v1/grants/"+g["grantId"].(string)+"/approve", nil, 200)
	}
	key := e.api(adm, "POST", "/api/v1/gateways/"+e.gatewayID+"/api-keys", map[string]any{"subject": "svc-agent", "roles": []string{"operator"}}, 201)["key"].(string)
	rel := e.api(op, "POST", "/api/v1/releases", map[string]string{"gatewayId": e.gatewayID}, 201)
	rid := rel["releaseId"].(string)
	e.api(rev, "POST", "/api/v1/releases/"+rid+"/approve", nil, 200)
	start := time.Now()
	dep := e.api(adm, "POST", "/api/v1/releases/"+rid+"/deploy", nil, 200)
	att := dep["attestation"].(map[string]any)
	t.Logf("deploy GOOD in %s; attested targets %v", time.Since(start).Round(time.Millisecond), att["targets"])

	checks := []struct {
		id string
		ok bool
	}{}
	check := func(id string, ok bool, detail ...any) {
		checks = append(checks, struct {
			id string
			ok bool
		}{id, ok})
		if !ok {
			t.Errorf("FAIL %s %v", id, detail)
		}
	}
	st, _ := e.mcp("", "tools/list", "", "")
	check("anonymous-denied", st == 401, st)
	st, _ = e.mcp("idpk_wrong", "tools/list", "", "")
	check("invalid-key-denied", st == 401, st)
	st, list := e.mcp(key, "tools/list", "", "")
	var names []string
	if res, ok := list["result"].(map[string]any); ok {
		for _, tool := range res["tools"].([]any) {
			names = append(names, tool.(map[string]any)["name"].(string))
		}
	}
	sort.Strings(names)
	check("catalog-match", st == 200 && strings.Join(names, ",") == "minimal__echo,minimal__sum,reference__test_simple_text", st, names)
	st, echo := e.mcp(key, "tools/call", call("minimal__echo", `{"text":"IDP Go E2E"}`), "minimal__echo")
	check("real-echo-call", st == 200 && strings.Contains(fmt.Sprint(echo["result"]), "IDP Go E2E"), st, echo)
	st, sum := e.mcp(key, "tools/call", call("minimal__sum", `{"a":3,"b":4}`), "minimal__sum")
	sc, _ := sum["result"].(map[string]any)["structuredContent"].(map[string]any)
	check("real-sum-call", st == 200 && fmt.Sprint(sc["sum"]) == "7", st, sum)
	st, ref := e.mcp(key, "tools/call", call("reference__test_simple_text", `{}`), "reference__test_simple_text")
	rr, _ := ref["result"].(map[string]any)
	check("real-reference-call", st == 200 && rr != nil && rr["isError"] != true && rr["content"] != nil, st, ref)
	check("release-record-good", e.api(rev, "GET", "/api/v1/releases/"+rid, nil, 200)["status"] == "GOOD")
	actions := map[string]bool{}
	for _, ev := range e.api(rev, "GET", "/api/v1/audit-events", nil, 200)["items"].([]any) {
		actions[ev.(map[string]any)["action"].(string)] = true
	}
	check("release-admin-audit-recorded", actions["release.compile"] && actions["release.approve"] && actions["release.deploy"] && actions["release.good"])

	// M2: prompts and resources of the Everything Server, federated through the gateway
	st, pl := e.mcp(key, "prompts/list", "", "")
	var prompts []string
	if res, ok := pl["result"].(map[string]any); ok {
		for _, p := range res["prompts"].([]any) {
			prompts = append(prompts, p.(map[string]any)["name"].(string))
		}
	}
	t.Logf("federated prompts: %v", prompts)
	allPrefixed := len(prompts) > 0
	for _, p := range prompts {
		allPrefixed = allPrefixed && strings.HasPrefix(p, "reference__")
	}
	check("prompts-list-federated", st == 200 && allPrefixed, st, prompts)
	st, pg := e.mcp(key, "prompts/get", `{"name":"reference__test_simple_prompt",`+meta+`}`, "reference__test_simple_prompt")
	pr, _ := pg["result"].(map[string]any)
	check("prompts-get-routed", st == 200 && pr != nil && pr["messages"] != nil, st, pg)
	st, rr2 := e.mcp(key, "resources/read", `{"uri":"test://static-text",`+meta+`}`, "test://static-text")
	rres, _ := rr2["result"].(map[string]any)
	check("resources-read-routed", st == 200 && rres != nil && rres["contents"] != nil, st, rr2)
	st, nf := e.mcp(key, "resources/read", `{"uri":"test://nope",`+meta+`}`, "test://nope")
	nfe, _ := nf["error"].(map[string]any)
	// the HTTP status of a JSON-RPC error is the upstream's choice (the Python SDK answers 400); the
	// suite (SEP-2164) checks the code and data.uri
	nfd, _ := nfe["data"].(map[string]any)
	check("resources-not-found-32602", nfe != nil && nfe["code"].(float64) == -32602 && nfd["uri"] == "test://nope", st, nf)

	// extra: invocations reached the registry, without arguments in clear
	deadline := time.Now().Add(10 * time.Second)
	var inv []any
	for time.Now().Before(deadline) {
		if inv = e.api(rev, "GET", "/api/v1/invocations", nil, 200)["items"].([]any); len(inv) >= 6 {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	methods := map[string]bool{}
	for _, it := range inv {
		methods[it.(map[string]any)["method"].(string)] = true
	}
	check("invocations-recorded", len(inv) >= 6 && methods["tools/call"] && methods["prompts/get"] && methods["resources/read"] &&
		!strings.Contains(fmt.Sprint(inv), "IDP Go E2E"), len(inv), methods)

	passed := 0
	for _, c := range checks {
		if c.ok {
			passed++
		}
	}
	t.Logf("compose E2E: %d/%d checks passed", passed, len(checks))
}
