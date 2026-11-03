package e2e

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestComposeOIDC: Keycloak in production mode (TLS, PostgreSQL) with TLS on the registry and the
// gateway. Real users log in with the authorization code flow (PKCE) through Keycloak's login form;
// an agent exchanges their tokens (RFC 8693 standard exchange, and delegation with an act claim)
// for the gateway audience; the gateway accepts exactly those and records who acted for whom.
func TestComposeOIDC(t *testing.T) {
	e := setup(t)
	if os.Getenv("IDP_E2E_MODE") != "oidc" {
		t.Skip("run through MODE=oidc deploy/e2e.sh")
	}
	issuer := os.Getenv("IDP_E2E_KEYCLOAK")
	resource := e.gateway + "/mcp"
	checks := 0
	check := func(id string, ok bool, detail ...any) {
		checks++
		if !ok {
			t.Errorf("FAIL %s %v", id, detail)
		} else {
			t.Logf("PASS %s", id)
		}
	}
	if !strings.HasPrefix(issuer, "https://") || !strings.HasPrefix(e.registry, "https://") || !strings.HasPrefix(e.gateway, "https://") {
		t.Fatalf("not all on TLS: %s %s %s", issuer, e.registry, e.gateway)
	}
	var clients map[string]json.RawMessage
	raw, _ := os.ReadFile(os.Getenv("IDP_E2E_KEYCLOAK_CLIENTS"))
	_ = json.Unmarshal(raw, &clients)
	var users map[string]string
	_ = json.Unmarshal(clients["users"], &users)
	var exchangeClient kcClient
	_ = json.Unmarshal(clients["agent-exchange"], &exchangeClient)

	form := func(u string, v url.Values, c *http.Client) (int, map[string]any) {
		resp, err := c.PostForm(u, v)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	tokenEndpoint := issuer + "/protocol/openid-connect/token"

	// --- the admin API over TLS, with Keycloak service accounts (JWKS fetched over TLS)
	op, rev, adm := e.kcTokenTLS("alice"), e.kcTokenTLS("bob"), e.kcTokenTLS("carol")
	s := e.api(op, "POST", "/api/v1/servers", map[string]string{"displayName": "minimal", "targetName": "minimal", "endpoint": "http://minimal:3111/mcp"}, 201)
	sid := s["serverId"].(string)
	e.api(op, "POST", "/api/v1/servers/"+sid+"/discover", nil, 200)
	e.api(rev, "POST", "/api/v1/servers/"+sid+"/approve", nil, 200)
	g := e.api(op, "POST", "/api/v1/grants", map[string]any{"serverId": sid, "tools": []string{"echo", "sum"}, "roles": []string{"operator"}}, 201)
	e.api(rev, "POST", "/api/v1/grants/"+g["grantId"].(string)+"/approve", nil, 200)
	rid := e.api(op, "POST", "/api/v1/releases", map[string]string{"gatewayId": e.gatewayID}, 201)["releaseId"].(string)
	e.api(rev, "POST", "/api/v1/releases/"+rid+"/approve", nil, 200)
	dep := e.api(adm, "POST", "/api/v1/releases/"+rid+"/deploy", nil, 200)
	check("tls-admin-api-and-jwt-release-good", dep["release"].(map[string]any)["status"] == "GOOD", dep["release"])

	// --- a real user: authorization code + PKCE through Keycloak's login form
	login := func(user string) string {
		t.Helper()
		jar, _ := cookiejar.New(nil)
		c := &http.Client{Transport: e.http.Transport, Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		vb := make([]byte, 48)
		_, _ = rand.Read(vb)
		verifier := base64.RawURLEncoding.EncodeToString(vb)
		sum := sha256.Sum256([]byte(verifier))
		q := url.Values{"client_id": {"agent-app"}, "response_type": {"code"}, "redirect_uri": {"http://127.0.0.1:18080/callback"}, "scope": {"openid"},
			"state": {"s1"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
		resp, err := c.Get(issuer + "/protocol/openid-connect/auth?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		page, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		m := regexp.MustCompile(`action="([^"]+login-actions/authenticate[^"]+)"`).FindSubmatch(page)
		if m == nil {
			t.Fatalf("no login form (HTTP %d): %.300s", resp.StatusCode, page)
		}
		action := strings.ReplaceAll(string(m[1]), "&amp;", "&")
		resp, err = c.PostForm(action, url.Values{"username": {user}, "password": {users[user]}, "credentialId": {""}})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		loc, _ := url.Parse(resp.Header.Get("Location"))
		code := ""
		if loc != nil {
			code = loc.Query().Get("code")
		}
		if resp.StatusCode != 302 || code == "" {
			t.Fatalf("login of %s: HTTP %d Location %q", user, resp.StatusCode, resp.Header.Get("Location"))
		}
		st, tok := form(tokenEndpoint, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"http://127.0.0.1:18080/callback"},
			"client_id": {"agent-app"}, "code_verifier": {verifier}}, c)
		at, _ := tok["access_token"].(string)
		if st != 200 || at == "" {
			t.Fatalf("code exchange for %s: %d %v", user, st, tok)
		}
		return at
	}
	alice := login("alice")
	ac := decodeClaims(alice)
	check("user-login-authorization-code-pkce", ac["tenant_id"] == e.tenant && fmt.Sprint(ac["roles"]) == "[operator]" && ac["azp"] == "agent-app" && ac["preferred_username"] == "alice", ac)
	st, l := e.mcp(alice, "tools/list", "", "")
	check("user-token-catalog", st == 200 && strings.Join(toolList(l), ",") == "minimal__echo,minimal__sum", st, toolList(l))
	st, c := e.mcp(alice, "tools/call", call("minimal__echo", `{"text":"as alice"}`), "minimal__echo")
	check("user-token-call", st == 200 && strings.Contains(fmt.Sprint(c["result"]), "as alice"), st, c)
	bob := login("bob")
	st, l = e.mcp(bob, "tools/list", "", "")
	check("viewer-user-empty-catalog", st == 200 && len(toolList(l)) == 0, st, toolList(l))

	// --- RFC 8693 standard token exchange: the agent gets a token for the gateway audience on alice's behalf
	st, ex := form(tokenEndpoint, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "client_id": {"agent-exchange"},
		"client_secret": {exchangeClient.Secret}, "subject_token": {alice}, "subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "audience": {resource}}, e.http)
	exchanged, _ := ex["access_token"].(string)
	xc := decodeClaims(exchanged)
	check("standard-token-exchange", st == 200 && xc["sub"] == ac["sub"] && xc["azp"] == "agent-exchange" && xc["aud"] == resource && xc["act"] == nil, st, xc)
	st, c = e.mcp(exchanged, "tools/call", call("minimal__echo", `{"text":"agent for alice"}`), "minimal__echo")
	check("exchanged-token-accepted", st == 200 && strings.Contains(fmt.Sprint(c["result"]), "agent for alice"), st, c)

	// --- delegation (Keycloak preview): alice's token must name the actor (may_act), the agent presents
	// its own token as actor_token, and the result carries an act claim
	st, own := form(tokenEndpoint, url.Values{"grant_type": {"client_credentials"}, "client_id": {"agent-exchange"}, "client_secret": {exchangeClient.Secret}}, e.http)
	agentToken, _ := own["access_token"].(string)
	agentSub, _ := decodeClaims(agentToken)["sub"].(string)
	check("agent-own-token-refused-by-gateway", func() bool { st, _ := e.mcp(agentToken, "tools/list", "", ""); return st == 401 }(), "aud=account must not pass")
	e.kcAdminAddMapper(t, "agent-app", map[string]any{"name": "may_act", "protocol": "openid-connect", "protocolMapper": "oidc-hardcoded-claim-mapper",
		"config": map[string]any{"claim.name": "may_act", "claim.value": fmt.Sprintf(`{"sub":%q,"client_id":"agent-exchange"}`, agentSub), "jsonType.label": "JSON",
			"access.token.claim": "true", "id.token.claim": "false", "introspection.token.claim": "true"}})
	alice2 := login("alice")
	st, dl := form(tokenEndpoint, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "client_id": {"agent-exchange"},
		"client_secret": {exchangeClient.Secret}, "subject_token": {alice2}, "subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"actor_token": {agentToken}, "actor_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "audience": {resource}}, e.http)
	delegated, _ := dl["access_token"].(string)
	dc := decodeClaims(delegated)
	act, _ := dc["act"].(map[string]any)
	check("delegation-token-has-act", st == 200 && dc["sub"] == ac["sub"] && act != nil && act["client_id"] == "agent-exchange", st, dc)
	st, c = e.mcp(delegated, "tools/call", call("minimal__sum", `{"a":2,"b":5}`), "minimal__sum")
	sc, _ := c["result"].(map[string]any)["structuredContent"].(map[string]any)
	check("delegated-token-accepted", st == 200 && fmt.Sprint(sc["sum"]) == "7", st, c)
	tampered := delegated[:len(delegated)-6] + "AAAAAA"
	check("tampered-token-401", func() bool { st, _ := e.mcp(tampered, "tools/list", "", ""); return st == 401 }())

	// --- the registry's record says who acted for whom (records arrive in batches)
	var seen struct{ user, standard, delegated bool }
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !(seen.user && seen.standard && seen.delegated) {
		for _, it := range e.api(rev, "GET", "/api/v1/invocations", nil, 200)["items"].([]any) {
			m := it.(map[string]any)
			if m["subject"] != ac["sub"] || m["method"] != "tools/call" {
				continue
			}
			client, _ := m["client"].(string)
			actor, _ := m["actor"].(string)
			switch {
			case client == "agent-app" && actor == "":
				seen.user = true
			case client == "agent-exchange" && actor == "":
				seen.standard = true
			case client == "agent-exchange" && actor == "agent-exchange":
				seen.delegated = true
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	check("invocations-record-client-and-actor", seen.user && seen.standard && seen.delegated, seen)
	t.Logf("compose OIDC E2E: %d checks", checks)
}

func decodeClaims(tok string) map[string]any {
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return map[string]any{}
	}
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

// kcTokenTLS issues a service-account token over TLS (the CA from IDP_E2E_CA).
func (e *env) kcTokenTLS(label string) string {
	e.t.Helper()
	raw, err := os.ReadFile(os.Getenv("IDP_E2E_KEYCLOAK_CLIENTS"))
	if err != nil {
		e.t.Fatal(err)
	}
	var clients map[string]json.RawMessage
	_ = json.Unmarshal(raw, &clients)
	var c kcClient
	_ = json.Unmarshal(clients[label], &c)
	resp, err := e.http.PostForm(os.Getenv("IDP_E2E_KEYCLOAK")+"/protocol/openid-connect/token",
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

// kcAdminAddMapper adds a protocol mapper to a client through the admin REST API.
func (e *env) kcAdminAddMapper(t *testing.T, clientID string, mapper map[string]any) {
	t.Helper()
	base := strings.TrimSuffix(os.Getenv("IDP_E2E_KEYCLOAK"), "/realms/idp")
	resp, err := e.http.PostForm(base+"/realms/master/protocol/openid-connect/token", url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"},
		"username": {os.Getenv("IDP_E2E_KC_ADMIN_USER")}, "password": {os.Getenv("IDP_E2E_KC_ADMIN_PASSWORD")}})
	if err != nil {
		t.Fatal(err)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tok)
	resp.Body.Close()
	if tok.AccessToken == "" {
		t.Fatalf("keycloak admin login failed: HTTP %d", resp.StatusCode)
	}
	do := func(method, path string, body any) (int, []byte) {
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, base+"/admin/realms/idp"+path, rd)
		req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := e.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, raw
	}
	_, raw := do("GET", "/clients?clientId="+url.QueryEscape(clientID), nil)
	var found []struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(raw, &found)
	if len(found) != 1 {
		t.Fatalf("client %s: %s", clientID, raw)
	}
	if st, body := do("POST", "/clients/"+found[0].ID+"/protocol-mappers/models", mapper); st != 201 {
		t.Fatalf("mapper: HTTP %d %s", st, body)
	}
}
