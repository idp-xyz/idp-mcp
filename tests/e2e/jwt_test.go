package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"idp-mcp/adapters/identity"
)

var direct = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil}}

type kcClient struct {
	ClientID string `json:"clientId"`
	Secret   string `json:"secret"`
}

func (e *env) kcToken(label string) string {
	e.t.Helper()
	raw, err := os.ReadFile(os.Getenv("IDP_E2E_KEYCLOAK_CLIENTS"))
	if err != nil {
		e.t.Fatal(err)
	}
	var clients map[string]kcClient
	_ = json.Unmarshal(raw, &clients)
	c := clients[label]
	resp, err := direct.PostForm(os.Getenv("IDP_E2E_KEYCLOAK")+"/protocol/openid-connect/token",
		url.Values{"grant_type": {"client_credentials"}, "client_id": {c.ClientID}, "client_secret": {c.Secret}})
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tok)
	if tok.AccessToken == "" {
		e.t.Fatalf("no token for %s: HTTP %d", label, resp.StatusCode)
	}
	return tok.AccessToken
}

func get(t *testing.T, u string) (int, http.Header, map[string]any) {
	resp, err := direct.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, resp.Header, out
}

func toolList(m map[string]any) []string {
	var out []string
	if res, ok := m["result"].(map[string]any); ok {
		for _, tool := range res["tools"].([]any) {
			out = append(out, tool.(map[string]any)["name"].(string))
		}
	}
	sort.Strings(out)
	return out
}

// TestComposeJWT: Keycloak issues every token. Admin API: JWKS-verified (production mode). Data
// plane: OAuth bearer JWTs bound to the gateway's resource URI, with RFC 9728 discovery.
func TestComposeJWT(t *testing.T) {
	e := setup(t)
	if os.Getenv("IDP_E2E_MODE") != "jwt" {
		t.Skip("run through MODE=jwt deploy/e2e.sh")
	}
	issuer := os.Getenv("IDP_E2E_KEYCLOAK")
	resource := e.gateway + "/mcp"
	op, rev, adm := e.kcToken("alice"), e.kcToken("bob"), e.kcToken("carol")
	allowed, viewer, foreign := e.kcToken("agent-allowed"), e.kcToken("agent-viewer"), e.kcToken("agent-foreign")
	checks := 0
	check := func(id string, ok bool, detail ...any) {
		checks++
		if !ok {
			t.Errorf("FAIL %s %v", id, detail)
		} else {
			t.Logf("PASS %s", id)
		}
	}

	// --- admin API in production mode
	devTok, _ := identity.DevAdminToken([]byte(e.secret), "idp-mcp-dev", "idp-mcp-registry", "mallory", e.tenant, []string{"admin"}, time.Minute)
	req, _ := http.NewRequest("GET", e.registry+"/api/v1/servers", nil)
	req.Header.Set("Authorization", "Bearer "+devTok)
	resp, _ := direct.Do(req)
	check("admin-rejects-hs256-dev-token", resp.StatusCode == 401, resp.StatusCode)
	req.Header.Set("Authorization", "Bearer "+allowed) // a data-plane token is not an admin token
	resp, _ = direct.Do(req)
	check("admin-rejects-gateway-audience", resp.StatusCode == 401, resp.StatusCode)

	// --- the same lifecycle as the api-key run, with Keycloak identities
	s := e.api(op, "POST", "/api/v1/servers", map[string]string{"displayName": "minimal", "targetName": "minimal", "endpoint": "http://minimal:3111/mcp"}, 201)
	sid := s["serverId"].(string)
	e.api(op, "POST", "/api/v1/servers/"+sid+"/discover", nil, 200)
	e.api(op, "POST", "/api/v1/servers/"+sid+"/approve", nil, 403) // operators do not approve
	e.api(rev, "POST", "/api/v1/servers/"+sid+"/approve", nil, 200)
	g := e.api(op, "POST", "/api/v1/grants", map[string]any{"serverId": sid, "tools": []string{"echo", "sum"}, "roles": []string{"operator"}}, 201)
	e.api(rev, "POST", "/api/v1/grants/"+g["grantId"].(string)+"/approve", nil, 200)
	rid := e.api(op, "POST", "/api/v1/releases", map[string]string{"gatewayId": e.gatewayID}, 201)["releaseId"].(string)
	e.api(rev, "POST", "/api/v1/releases/"+rid+"/approve", nil, 200)
	dep := e.api(adm, "POST", "/api/v1/releases/"+rid+"/deploy", nil, 200)
	check("jwt-release-good", dep["release"].(map[string]any)["status"] == "GOOD", dep["release"])
	doc := dep["release"].(map[string]any)["document"].(map[string]any)["auth"].(map[string]any)
	check("release-auth-profile-jwt", doc["mode"] == "jwt" && doc["jwt"].(map[string]any)["resource"] == resource, doc)

	// --- MCP authorization discovery, as a spec client walks it
	st, _ := e.mcp("", "tools/list", "", "")
	req, _ = http.NewRequest("POST", resource, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{`+meta+`}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	resp, _ = direct.Do(req)
	challenge := resp.Header.Get("WWW-Authenticate")
	prmURL := e.gateway + "/.well-known/oauth-protected-resource/mcp"
	check("anonymous-401-with-resource-metadata", st == 401 && challenge == `Bearer resource_metadata="`+prmURL+`"`, st, challenge)
	st, _, prm := get(t, prmURL)
	servers, _ := prm["authorization_servers"].([]any)
	check("protected-resource-metadata", st == 200 && prm["resource"] == resource && len(servers) == 1 && servers[0] == issuer, st, prm)
	st, _, as := get(t, issuer+"/.well-known/openid-configuration")
	check("authorization-server-discovery", st == 200 && as["issuer"] == issuer && as["token_endpoint"] != nil, st, as["issuer"])

	// --- per-identity behaviour
	st, l := e.mcp(allowed, "tools/list", "", "")
	check("allowed-catalog", st == 200 && strings.Join(toolList(l), ",") == "minimal__echo,minimal__sum", st, toolList(l))
	st, c := e.mcp(allowed, "tools/call", call("minimal__echo", `{"text":"via keycloak"}`), "minimal__echo")
	check("allowed-call", st == 200 && strings.Contains(fmt.Sprint(c["result"]), "via keycloak"), st, c)
	st, l = e.mcp(viewer, "tools/list", "", "")
	check("viewer-empty-catalog", st == 200 && len(toolList(l)) == 0, st, toolList(l))
	st, c = e.mcp(viewer, "tools/call", call("minimal__echo", `{"text":"x"}`), "minimal__echo")
	check("viewer-call-denied", st == 200 && c["error"] != nil && strings.Contains(fmt.Sprint(c["error"]), "Unknown tool"), st, c)
	st, l = e.mcp(foreign, "tools/list", "", "")
	check("foreign-tenant-empty-catalog", st == 200 && len(toolList(l)) == 0, st, toolList(l))
	st, c = e.mcp(foreign, "tools/call", call("minimal__echo", `{"text":"x"}`), "minimal__echo")
	check("foreign-tenant-call-denied", c["error"] != nil, st, c)
	st, _ = e.mcp(op, "tools/list", "", "") // registry-audience token on the data plane
	check("registry-audience-token-401", st == 401, st)
	tampered := allowed[:len(allowed)-8] + map[bool]string{true: "AAAAAAAA", false: "BBBBBBBB"}[allowed[len(allowed)-8] != 'A']
	st, _ = e.mcp(tampered, "tools/list", "", "")
	check("tampered-token-401", st == 401, st)
	st, c = e.mcp(allowed, "tools/call", call("minimal__echo", `{"text":"`+strings.Repeat("x", 600)+`"}`), "minimal__echo")
	check("arguments-validated", c["error"] != nil && strings.Contains(fmt.Sprint(c["error"]), "maxLength"), st, c)

	// --- the audit trail records the Keycloak subjects
	subjects := map[string]bool{}
	for _, ev := range e.api(rev, "GET", "/api/v1/audit-events", nil, 200)["items"].([]any) {
		subjects[ev.(map[string]any)["subject"].(string)] = true
	}
	check("audit-subjects-from-keycloak", len(subjects) >= 3, subjects)
	t.Logf("compose JWT E2E: %d checks", checks)
}
