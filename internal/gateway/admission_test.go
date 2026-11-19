package gateway

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"idp-mcp/adapters/identity"
	"idp-mcp/internal/admission"
	"idp-mcp/internal/invocation"
	"idp-mcp/internal/release"
	"idp-mcp/internal/server"
)

// The clients of these tests are API keys, whose client id is "api-key:<id>" (authorization.Principal.ClientID):
// the gateway treats an OAuth client and a key alike once it has a client id, and the JWT path that makes the id
// from azp is tested separately below.
const (
	hostKey     = "host-key-0123456789abcdef0000"
	platformKey = "platform-key-0123456789abcdef"
	partnerKey  = "partner-key-0123456789abcdef0"
	serverKey   = "server-key-0123456789abcdef00"
	strangerKey = "stranger-key-0123456789abcde"
)

// admissionRelease adds to the standard test release five operator keys, one per kind of client, and a second key
// of the platform client's subject, for the per-subject limit.
func admissionRelease(d *release.Document) {
	d.Auth.APIKeys = append(d.Auth.APIKeys,
		release.APIKey{ID: "host", Subject: "svc-host", Roles: []string{"operator"}, SHA256: identity.HashKey(hostKey)},
		release.APIKey{ID: "platform", Subject: "svc-platform", Roles: []string{"operator"}, SHA256: identity.HashKey(platformKey)},
		release.APIKey{ID: "partner", Subject: "svc-partner", Roles: []string{"operator"}, SHA256: identity.HashKey(partnerKey)},
		release.APIKey{ID: "server", Subject: "svc-server", Roles: []string{"operator"}, SHA256: identity.HashKey(serverKey)},
		release.APIKey{ID: "stranger", Subject: "svc-stranger", Roles: []string{"operator"}, SHA256: identity.HashKey(strangerKey)})
}

const baseClients = `
clients:
  "api-key:host":     {kind: platform, host: true}
  "api-key:platform": {kind: platform}
  "api-key:partner":  {kind: external, tools: ["minimal__sum"]}
  "api-key:server":   {kind: external, servers: [minimal]}
  "api-key:k2":       {kind: platform}
`

func mustClients(t *testing.T, text string) *admission.Clients {
	t.Helper()
	c, err := admission.Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// admissionHarness is newHarness with the release of admissionRelease and the clients file text.
func admissionHarness(t *testing.T, text string) *harness {
	t.Helper()
	up := newUpstream(t)
	rec := &recorder{}
	g := New(Config{GatewayID: "g1", Clients: mustClients(t, text), Info: server.ServerInfo{Name: "idp-mcp-gateway", Version: "test"}, DevMode: true,
		CallTimeout: 2 * time.Second, Recorder: rec})
	if err := g.Activate(buildRelease(t, up.srv.URL+"/mcp", "block", admissionRelease)); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(g.Handler())
	t.Cleanup(srv.Close)
	return &harness{g: g, up: up, rec: rec, srv: srv}
}

func (r *recorder) all() []invocation.Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]invocation.Record(nil), r.recs...)
}

func (h *harness) callTool(t *testing.T, key, name string) reply {
	t.Helper()
	return h.rpc(t, key, "tools/call", call(name, `{"text":"hi"}`), map[string]string{server.HeaderName: name})
}

func has(list []string, want ...string) bool {
	if len(list) != len(want) {
		return false
	}
	for i := range want {
		if list[i] != want[i] {
			return false
		}
	}
	return true
}

func TestAnUnlistedClientSeesNoToolsAndEveryCallIsRefusedAndAudited(t *testing.T) {
	h := admissionHarness(t, baseClients)
	// authenticated, holds the role that allows everything, and is not listed
	r := h.rpc(t, strangerKey, "tools/list", "", nil)
	if r.status != 200 || len(toolNames(r)) != 0 {
		t.Fatalf("an unlisted client sees tools: %d %s", r.status, r.raw)
	}
	r = h.callTool(t, strangerKey, "minimal__echo")
	if r.status != 200 || errCode(r) != server.CodeInvalidParams || !strings.Contains(r.raw, "Unknown tool") {
		t.Fatalf("an unlisted client's call was not refused: %d %s", r.status, r.raw)
	}
	if h.up.calls() != 0 {
		t.Fatal("the refused call reached the upstream")
	}
	// the answer is the one given for a tool that does not exist: the refusal tells nothing about the catalog
	if missing := h.callTool(t, strangerKey, "minimal__nothing"); missing.raw != strings.ReplaceAll(r.raw, "minimal__echo", "minimal__nothing") {
		t.Fatalf("a refused tool and a missing tool are told apart:\n%s\n%s", r.raw, missing.raw)
	}
	recs := h.rec.all()
	if len(recs) != 3 {
		t.Fatalf("%d records: %+v", len(recs), recs)
	}
	for i, want := range []string{"tools/list", "tools/call", "tools/call"} {
		got := recs[i]
		if got.Method != want || got.Decision != invocation.Deny || got.Outcome != invocation.OutcomeDenied || got.Reason != admission.NotListed || got.Subject != "svc-stranger" {
			t.Errorf("record %d: %+v", i, got)
		}
	}
	// a listed client in the same gateway still works
	if got := toolNames(h.rpc(t, platformKey, "tools/list", "", nil)); !has(got, "minimal__echo", "minimal__sum") {
		t.Fatalf("a platform client sees %v", got)
	}
}

func TestATokenWithoutAClientIsNotListed(t *testing.T) {
	// the client of a JWT is its azp; a token without one has none, and only the wildcard serves it
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		enc := base64.RawURLEncoding.EncodeToString
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k", "use": "sig",
			"n": enc(rk.N.Bytes()), "e": enc(big.NewInt(int64(rk.E)).Bytes())}}})
	}))
	defer jwks.Close()
	const issuer, resource = "http://issuer.example/realms/idp", "http://127.0.0.1:3220/mcp"
	token := func(azp string) string {
		c := jwt.MapClaims{"iss": issuer, "aud": []string{resource}, "sub": "alice", "tenant_id": "t1", "roles": []any{"operator"},
			"exp": time.Now().Add(time.Hour).Unix()}
		if azp != "" {
			c["azp"] = azp
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
		tok.Header["kid"] = "k"
		s, err := tok.SignedString(rk)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	run := func(clients string) *harness {
		up := newUpstream(t)
		g := New(Config{GatewayID: "g1", Clients: mustClients(t, clients), DevMode: true, CallTimeout: 2 * time.Second, IdentityHTTP: jwks.Client()})
		env := buildRelease(t, up.srv.URL+"/mcp", "block", func(d *release.Document) {
			d.Auth = release.Auth{Mode: "jwt", JWT: &release.JWT{Issuer: issuer, Resource: resource, JWKSURL: jwks.URL,
				AuthorizationServers: []string{issuer}, TenantClaim: "tenant_id", RolesClaim: "roles"}}
		})
		if err := g.Activate(env); err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(g.Handler())
		t.Cleanup(srv.Close)
		return &harness{g: g, up: up, srv: srv, rec: &recorder{}}
	}
	h := run(`clients: {idp-host: {kind: platform, host: true}}`)
	if got := toolNames(h.rpc(t, token("idp-host"), "tools/list", "", nil)); !has(got, "minimal__echo", "minimal__sum") {
		t.Fatalf("the listed client sees %v", got)
	}
	if got := toolNames(h.rpc(t, token("someone-else"), "tools/list", "", nil)); len(got) != 0 {
		t.Fatalf("an unlisted client sees %v", got)
	}
	if got := toolNames(h.rpc(t, token(""), "tools/list", "", nil)); len(got) != 0 {
		t.Fatalf("a token with no client claim sees %v", got)
	}
	// the deliberate opt-out serves the token with no client as well
	open := run(`clients: {"*": platform}`)
	if got := toolNames(open.rpc(t, token(""), "tools/list", "", nil)); !has(got, "minimal__echo", "minimal__sum") {
		t.Fatalf("under the wildcard a token with no client sees %v", got)
	}
}

func TestAnExternalClientSeesAndCallsOnlyWhatItsAllowListNames(t *testing.T) {
	h := admissionHarness(t, baseClients)
	// partner: the tool pattern minimal__sum, although its role also allows echo
	if got := toolNames(h.rpc(t, partnerKey, "tools/list", "", nil)); !has(got, "minimal__sum") {
		t.Fatalf("partner sees %v", got)
	}
	if r := h.callTool(t, partnerKey, "minimal__echo"); errCode(r) != server.CodeInvalidParams || h.up.calls() != 0 {
		t.Fatalf("partner called a tool outside its list: %s", r.raw)
	}
	if r := h.callTool(t, partnerKey, "minimal__sum"); strings.Contains(r.raw, "Unknown tool") || h.up.calls() != 1 {
		t.Fatalf("partner's own tool: %d %s", r.status, r.raw)
	}
	if last := h.rec.last(); last.Decision != invocation.Allow || last.Client != "" {
		t.Fatalf("%+v", last)
	}
	// server: the whole server minimal, but only what its role allows (the viewer role would see sum alone)
	if got := toolNames(h.rpc(t, serverKey, "tools/list", "", nil)); !has(got, "minimal__echo", "minimal__sum") {
		t.Fatalf("server client sees %v", got)
	}
	// the role still decides: an external client's allow-list never grants what the role does not
	nobodyAsPartner := mustClients(t, `clients: {"api-key:k3": {kind: external, servers: [minimal]}}`)
	n := newHarness(t, "block", nobodyAsPartner)
	if got := toolNames(n.rpc(t, nobodyKey, "tools/list", "", nil)); len(got) != 0 {
		t.Fatalf("a role with no grant sees %v through an allow-list", got)
	}
}

func TestAPlatformClientSeesWhatItsRolesAllowAsBefore(t *testing.T) {
	h := admissionHarness(t, baseClients)
	if got := toolNames(h.rpc(t, platformKey, "tools/list", "", nil)); !has(got, "minimal__echo", "minimal__sum") {
		t.Fatalf("operator role through a platform client: %v", got)
	}
	if got := toolNames(h.rpc(t, viewerKey, "tools/list", "", nil)); !has(got, "minimal__sum") {
		t.Fatalf("viewer role through a platform client: %v", got)
	}
	if r := h.callTool(t, viewerKey, "minimal__echo"); errCode(r) != server.CodeInvalidParams {
		t.Fatalf("a platform client got past the role: %s", r.raw)
	}
	if last := h.rec.last(); last.Reason != "role" {
		t.Fatalf("the audit does not say it was the role: %+v", last)
	}
}

func TestAHostOnlyToolIsVisibleAndCallableForTheHostClientOnly(t *testing.T) {
	h := admissionHarness(t, baseClients+"hostOnlyTools: [\"minimal__echo\"]\n")
	if got := toolNames(h.rpc(t, hostKey, "tools/list", "", nil)); !has(got, "minimal__echo", "minimal__sum") {
		t.Fatalf("the host sees %v", got)
	}
	if r := h.callTool(t, hostKey, "minimal__echo"); r.body["error"] != nil || h.up.calls() != 1 {
		t.Fatalf("the host's call: %s", r.raw)
	}
	// the same role, a platform client that is not the host, and an external client that lists the whole server
	for name, key := range map[string]string{"platform": platformKey, "external server": serverKey} {
		if got := toolNames(h.rpc(t, key, "tools/list", "", nil)); !has(got, "minimal__sum") {
			t.Errorf("%s client sees %v", name, got)
		}
		before := h.up.calls()
		r := h.callTool(t, key, "minimal__echo")
		if errCode(r) != server.CodeInvalidParams || h.up.calls() != before {
			t.Errorf("%s client called a host-only tool: %s", name, r.raw)
		}
		if last := h.rec.last(); last.Decision != invocation.Deny || last.Reason != admission.HostOnly {
			t.Errorf("%s: %+v", name, last)
		}
	}
}

func TestAnExternalClientsOwnPatternDoesNotLiftHostOnly(t *testing.T) {
	h := admissionHarness(t, `
clients:
  "api-key:host": {kind: platform, host: true}
  "api-key:partner": {kind: external, tools: ["minimal__*"]}
hostOnlyTools: ["minimal__echo"]
`)
	if got := toolNames(h.rpc(t, partnerKey, "tools/list", "", nil)); !has(got, "minimal__sum") {
		t.Fatalf("partner sees %v", got)
	}
	if r := h.callTool(t, partnerKey, "minimal__echo"); errCode(r) != server.CodeInvalidParams {
		t.Fatalf("%s", r.raw)
	}
}

func TestAHostOnlyExceptionLetsOtherClientsThroughAndIsAuditedWithItsReason(t *testing.T) {
	h := admissionHarness(t, baseClients+`
hostOnlyTools: ["minimal__*"]
hostOnlyExcept:
  - {pattern: "minimal__sum", reason: "approved by security, ticket SEC-17"}
`)
	if got := toolNames(h.rpc(t, platformKey, "tools/list", "", nil)); !has(got, "minimal__sum") {
		t.Fatalf("a platform client sees %v", got)
	}
	r := h.callTool(t, platformKey, "minimal__sum")
	if strings.Contains(r.raw, "Unknown tool") || h.up.calls() != 1 {
		t.Fatalf("the exception did not let the call through: %s", r.raw)
	}
	if last := h.rec.last(); last.Decision != invocation.Allow || last.Reason != "host-only exception: approved by security, ticket SEC-17" {
		t.Fatalf("the use of the exception is not audited with its reason: %+v", last)
	}
	// a tool outside the exception stays host-only, and the host's own call uses no exception
	if r := h.callTool(t, platformKey, "minimal__echo"); errCode(r) != server.CodeInvalidParams {
		t.Fatalf("%s", r.raw)
	}
	h.callTool(t, hostKey, "minimal__sum")
	if last := h.rec.last(); last.Reason != "" {
		t.Fatalf("the host's call is recorded as an exception use: %+v", last)
	}
}

func TestPromptsAndResourcesAreGrantedToExternalClientsByServerOnly(t *testing.T) {
	a, b := newRich(t, "alpha"), newRich(t, "beta")
	env := richRelease(t, release.NamingPrefixed, a, b)
	clients := mustClients(t, `clients:
  "api-key:k1": {kind: external, servers: [alpha]}
  "api-key:k2": {kind: external, tools: ["alpha__t"]}
`)
	h := richHarness(t, env, clients)
	// k1 holds the operator role (everything) but is limited to the server alpha
	if got := strings.Join(names(h.rpc(t, operatorKey, "prompts/list", "", nil), "prompts", "name"), ","); got != "alpha__greet,alpha__secret" {
		t.Fatalf("prompts: %s", got)
	}
	if got := names(h.rpc(t, operatorKey, "resources/list", "", nil), "resources", "uri"); !has(got, "alpha://static") {
		t.Fatalf("resources: %v", got)
	}
	if got := names(h.rpc(t, operatorKey, "resources/templates/list", "", nil), "resourceTemplates", "uriTemplate"); !has(got, "alpha://item/{id}") {
		t.Fatalf("templates: %v", got)
	}
	if r := h.rpc(t, operatorKey, "resources/read", `{"uri":"beta://static",`+metaJSON+`}`, map[string]string{server.HeaderName: "beta://static"}); errCode(r) != server.CodeInvalidParams {
		t.Fatalf("read of another server's resource: %s", r.raw)
	}
	if r := h.rpc(t, operatorKey, "prompts/get", `{"name":"beta__greet",`+metaJSON+`}`, map[string]string{server.HeaderName: "beta__greet"}); errCode(r) != server.CodeInvalidParams {
		t.Fatalf("get of another server's prompt: %s", r.raw)
	}
	complete := `{"ref":{"type":"ref/prompt","name":"beta__greet"},"argument":{"name":"who","value":"a"},` + metaJSON + `}`
	if r := h.rpc(t, operatorKey, "completion/complete", complete, nil); errCode(r) != server.CodeInvalidParams {
		t.Fatalf("completion for another server's prompt: %s", r.raw)
	}
	if h.rec.last().Reason != admission.NotAllowed {
		t.Fatalf("the audit does not name the client: %+v", h.rec.last())
	}
	// k2 lists one tool pattern and no server: its role allows greet, but a tool pattern grants no prompt or resource
	if got := names(h.rpc(t, viewerKey, "prompts/list", "", nil), "prompts", "name"); len(got) != 0 {
		t.Fatalf("a tool-only client sees prompts %v", got)
	}
	if r := h.rpc(t, viewerKey, "prompts/get", `{"name":"alpha__greet",`+metaJSON+`}`, map[string]string{server.HeaderName: "alpha__greet"}); errCode(r) != server.CodeInvalidParams {
		t.Fatalf("a tool-only client got a prompt: %s", r.raw)
	}
}

func TestAnUnlistedClientGetsEmptyPromptAndResourceListsAndNoCapabilities(t *testing.T) {
	a := newRich(t, "alpha")
	h := richHarness(t, richRelease(t, release.NamingPrefixed, a), mustClients(t, `clients: {"api-key:k2": platform}`))
	if got := names(h.rpc(t, operatorKey, "prompts/list", "", nil), "prompts", "name"); len(got) != 0 {
		t.Fatalf("prompts %v", got)
	}
	if got := names(h.rpc(t, operatorKey, "resources/list", "", nil), "resources", "uri"); len(got) != 0 {
		t.Fatalf("resources %v", got)
	}
	if r := h.rpc(t, operatorKey, "resources/read", `{"uri":"alpha://static",`+metaJSON+`}`, map[string]string{server.HeaderName: "alpha://static"}); errCode(r) != server.CodeInvalidParams {
		t.Fatalf("read %s", r.raw)
	}
	caps := h.rpc(t, operatorKey, "server/discover", "", nil).body["result"].(map[string]any)["capabilities"].(map[string]any)
	if _, ok := caps["prompts"]; ok {
		t.Fatalf("an unlisted client is told the server's capabilities: %v", caps)
	}
	for _, rec := range h.rec.all() {
		if rec.Decision != invocation.Deny || rec.Reason != admission.NotListed {
			t.Errorf("%+v", rec)
		}
	}
}

func TestATaskBelongsToTheClientThatCreatedIt(t *testing.T) {
	u := newTasksUpstream(t)
	clients := mustClients(t, `clients: {"api-key:k1": platform, "api-key:twin": platform}`)
	// a second key of the same subject and role, under another client: the member is the same, the client is not
	h := tasksHarnessWith(t, u, func(d *release.Document) {
		d.Auth.APIKeys = append(d.Auth.APIKeys, release.APIKey{ID: "twin", Subject: "svc-operator", Roles: []string{"operator"}, SHA256: identity.HashKey(partnerKey)})
	}, clients)
	r := h.rpc(t, operatorKey, "tools/call", call("minimal__slow", `{}`), map[string]string{server.HeaderName: "minimal__slow"})
	if res, _ := r.body["result"].(map[string]any); res["taskId"] != "task-1" {
		t.Fatalf("create: %s", r.raw)
	}
	get := func(key string) reply {
		return h.rpc(t, key, "tasks/get", taskParams("task-1"), map[string]string{server.HeaderName: "task-1"})
	}
	if r := get(operatorKey); r.body["error"] != nil {
		t.Fatalf("the creating client: %s", r.raw)
	}
	r = get(partnerKey)
	if errCode(r) != server.CodeInvalidParams || !strings.Contains(r.raw, "Unknown task") {
		t.Fatalf("another client of the same member got the task: %s", r.raw)
	}
	// and an unlisted client is told so in the audit
	h2 := tasksHarness(t, newTasksUpstream(t), mustClients(t, `clients: {"api-key:k2": platform}`))
	h2.rpc(t, operatorKey, "tasks/get", taskParams("task-1"), map[string]string{server.HeaderName: "task-1"})
	if last := h2.rec.last(); last.Reason != admission.NotListed || last.Decision != invocation.Deny {
		t.Fatalf("%+v", last)
	}
}

func TestSubscriptionsHonourOnlyWhatTheClientMaySee(t *testing.T) {
	a, b := newRich(t, "alpha"), newRich(t, "beta")
	clients := mustClients(t, `clients:
  "api-key:k1": {kind: external, servers: [alpha]}
`)
	h := richHarness(t, richRelease(t, release.NamingPrefixed, a, b), clients)
	s := openListen(t, h, operatorKey, `{"toolsListChanged":true,"promptsListChanged":true,"resourceSubscriptions":["alpha://static","beta://static"]}`)
	ack := s.next(t, 2*time.Second)
	honoured := ack["params"].(map[string]any)["notifications"].(map[string]any)
	if subs, _ := honoured["resourceSubscriptions"].([]any); len(subs) != 1 || subs[0] != "alpha://static" {
		t.Fatalf("subscriptions honoured: %v", honoured)
	}
	// k2 is not listed: it gets an acknowledgment that honours nothing and the end of the stream
	u := openListen(t, h, viewerKey, `{"toolsListChanged":true,"promptsListChanged":true,"resourceSubscriptions":["alpha://static"]}`)
	ack = u.next(t, 2*time.Second)
	if honoured := ack["params"].(map[string]any)["notifications"].(map[string]any); len(honoured) != 0 {
		t.Fatalf("an unlisted client's subscription honours %v", honoured)
	}
	if end := u.next(t, 2*time.Second); end["result"] == nil {
		t.Fatalf("the stream did not end: %v", end)
	}
	eventually(t, func() bool {
		for _, r := range h.rec.all() {
			if r.Subject == "viewer" && r.Method == "subscriptions/listen" {
				return r.Decision == invocation.Deny && r.Reason == admission.NotListed
			}
		}
		return false
	}, "the refused subscription is recorded")
}

func eventually(t *testing.T, ok func() bool, what string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("not in time: %s", what)
}

// ---- rate limits ------------------------------------------------------------------------------

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func TestTheRequestLimitOfAnExternalClientRefusesWithRetryAfterAndIsAudited(t *testing.T) {
	h := admissionHarness(t, baseClients+"rateLimits: {perClient: {requests: 3, window: 1m}, perSubject: {requests: 100}}\n")
	clk := &clock{now: time.Unix(1_000_000, 0)}
	h.g.limiter = admission.NewLimiter(clk.Now)
	for i := 0; i < 3; i++ {
		if r := h.rpc(t, partnerKey, "tools/list", "", nil); r.status != 200 {
			t.Fatalf("call %d: %d", i, r.status)
		}
	}
	r := h.callTool(t, partnerKey, "minimal__sum")
	if r.status != http.StatusTooManyRequests || errCode(r) != server.CodeRateLimited || r.header.Get("Retry-After") != "60" {
		t.Fatalf("over the limit: %d %q %s", r.status, r.header.Get("Retry-After"), r.raw)
	}
	if h.up.calls() != 0 {
		t.Fatal("the refused call reached the upstream")
	}
	if last := h.rec.last(); last.Outcome != invocation.OutcomeRateLimited || last.Decision != invocation.Deny || last.Reason != "client rate limit; retry after 60s" || last.Subject != "svc-partner" {
		t.Fatalf("%+v", last)
	}
	// another external client has its own window
	if r := h.rpc(t, serverKey, "tools/list", "", nil); r.status != 200 {
		t.Fatalf("another client: %d", r.status)
	}
	clk.now = clk.now.Add(45 * time.Second)
	if r := h.rpc(t, partnerKey, "tools/list", "", nil); r.status != 429 || r.header.Get("Retry-After") != "15" {
		t.Fatalf("inside the window: %d %q", r.status, r.header.Get("Retry-After"))
	}
	clk.now = clk.now.Add(16 * time.Second)
	if r := h.rpc(t, partnerKey, "tools/list", "", nil); r.status != 200 {
		t.Fatalf("after the window: %d", r.status)
	}
}

func TestAnExternalClientsSubjectsAreLimitedPerSubject(t *testing.T) {
	h := admissionHarness(t, baseClients+"rateLimits: {perClient: {requests: 100}, perSubject: {requests: 2, window: 1m}}\n")
	for i := 0; i < 2; i++ {
		h.rpc(t, partnerKey, "tools/list", "", nil)
	}
	r := h.rpc(t, partnerKey, "tools/list", "", nil)
	if r.status != 429 || !strings.Contains(r.raw, "this subject") {
		t.Fatalf("%d %s", r.status, r.raw)
	}
	if r := h.rpc(t, serverKey, "tools/list", "", nil); r.status != 200 {
		t.Fatalf("another subject: %d", r.status)
	}
}

func TestPlatformClientsAndTheirSubjectsAreNotLimitedByTheDefaults(t *testing.T) {
	// with limits of 3 for everyone the file sets, the platform client's requests (and its subject's) are still free
	h := admissionHarness(t, baseClients+"rateLimits: {perClient: {requests: 3, window: 1m}, perSubject: {requests: 3, window: 1m}}\n")
	for i := 0; i < 50; i++ {
		if r := h.rpc(t, hostKey, "tools/list", "", nil); r.status != 200 {
			t.Fatalf("the host was limited at call %d: %d", i, r.status)
		}
		if r := h.rpc(t, platformKey, "tools/list", "", nil); r.status != 200 {
			t.Fatalf("a platform client was limited at call %d: %d", i, r.status)
		}
	}
}

func TestTheRequestLimitOfASubjectCountsAcrossClientsWhenAPlatformEntrySetsOne(t *testing.T) {
	// two clients, one member: the member's own limit holds whichever client asks
	const one, two = "one-key-0123456789abcdef000000", "two-key-0123456789abcdef000000"
	up := newUpstream(t)
	rec := &recorder{}
	g := New(Config{GatewayID: "g1", DevMode: true, Recorder: rec, Clients: mustClients(t, `
clients:
  "api-key:one": {kind: platform, subjectRateLimit: 3}
  "api-key:two": {kind: platform, subjectRateLimit: 3}
  "api-key:k1": {kind: platform}
`)})
	if err := g.Activate(buildRelease(t, up.srv.URL+"/mcp", "block", func(d *release.Document) {
		d.Auth.APIKeys = append(d.Auth.APIKeys,
			release.APIKey{ID: "one", Subject: "member", Roles: []string{"operator"}, SHA256: identity.HashKey(one)},
			release.APIKey{ID: "two", Subject: "member", Roles: []string{"operator"}, SHA256: identity.HashKey(two)})
	})); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(g.Handler())
	defer srv.Close()
	h := &harness{g: g, up: up, rec: rec, srv: srv}
	h.rpc(t, one, "tools/list", "", nil)
	h.rpc(t, two, "tools/list", "", nil)
	h.rpc(t, one, "tools/list", "", nil)
	r := h.rpc(t, two, "tools/list", "", nil)
	if r.status != 429 || !strings.Contains(r.raw, "this subject") {
		t.Fatalf("%d %s", r.status, r.raw)
	}
	if last := rec.last(); last.Outcome != invocation.OutcomeRateLimited || last.Reason != "subject rate limit; retry after 60s" {
		t.Fatalf("%+v", last)
	}
	if r := h.rpc(t, operatorKey, "tools/list", "", nil); r.status != 200 {
		t.Fatalf("another subject: %d", r.status)
	}
}

func TestAClientsOwnRateLimitOverridesTheDefaultsForPlatformAndExternalClients(t *testing.T) {
	h := admissionHarness(t, `
clients:
  "api-key:platform": {kind: platform, rateLimit: 1}
  "api-key:host": {kind: platform, host: true}
  "api-key:partner": {kind: external, tools: ["minimal__sum"], rateLimit: 2}
`)
	if r := h.rpc(t, platformKey, "tools/list", "", nil); r.status != 200 {
		t.Fatal(r.status)
	}
	if r := h.rpc(t, platformKey, "tools/list", "", nil); r.status != 429 {
		t.Fatalf("the override of 1 did not apply to a platform client: %d", r.status)
	}
	h.rpc(t, partnerKey, "tools/list", "", nil)
	h.rpc(t, partnerKey, "tools/list", "", nil)
	if r := h.rpc(t, partnerKey, "tools/list", "", nil); r.status != 429 {
		t.Fatalf("the override of 2 did not apply to an external client: %d", r.status)
	}
}

func TestAnUnlistedClientIsAlwaysLimitedByTheDefaults(t *testing.T) {
	h := admissionHarness(t, baseClients+"rateLimits: {perClient: {requests: 2, window: 1m}}\n")
	h.rpc(t, strangerKey, "tools/list", "", nil)
	h.rpc(t, strangerKey, "tools/list", "", nil)
	if r := h.rpc(t, strangerKey, "tools/list", "", nil); r.status != 429 {
		t.Fatalf("probing by an unlisted client is not limited: %d", r.status)
	}
	// and with no limits in the file at all it is limited by the built-in ones
	d := admissionHarness(t, baseClients)
	var refused int
	for i := 0; i < admission.DefaultClientRequests+5; i++ {
		if d.rpc(t, strangerKey, "tools/list", "", nil).status == 429 {
			refused++
		}
	}
	if refused == 0 {
		t.Fatal("an unlisted client is free of the default limit")
	}
}

// ---- the completed audit -----------------------------------------------------------------------

func TestListCallsAreRecordedForListedClientsToo(t *testing.T) {
	h := admissionHarness(t, baseClients)
	h.rpc(t, platformKey, "tools/list", "", nil)
	h.rpc(t, platformKey, "prompts/list", "", nil)
	h.rpc(t, platformKey, "resources/list", "", nil)
	h.rpc(t, platformKey, "resources/templates/list", "", nil)
	recs := h.rec.all()
	if len(recs) != 4 {
		t.Fatalf("%d records", len(recs))
	}
	for i, m := range []string{"tools/list", "prompts/list", "resources/list", "resources/templates/list"} {
		r := recs[i]
		if r.Method != m || r.Tool != invocation.Whole || r.Decision != invocation.Allow || r.Outcome != invocation.OutcomeOK || r.Subject != "svc-platform" || r.AuthMethod != "api-key" {
			t.Errorf("%s: %+v", m, r)
		}
	}
}

func TestAuthenticationFailuresAreRecordedWithoutTheCredential(t *testing.T) {
	h := admissionHarness(t, baseClients)
	h.rpc(t, "", "tools/list", "", nil)
	h.rpc(t, "a-secret-that-is-not-a-key-0123456789", "tools/call", call("minimal__echo", `{"text":"classified"}`), map[string]string{server.HeaderName: "minimal__echo"})
	recs := h.rec.all()
	if len(recs) != 2 {
		t.Fatalf("%d records: %+v", len(recs), recs)
	}
	want := []struct{ method, reason string }{{"tools/list", "no bearer credential"}, {"tools/call", "the credential was refused"}}
	for i, w := range want {
		r := recs[i]
		if r.Method != w.method || r.Reason != w.reason || r.Decision != invocation.Deny || r.Outcome != invocation.OutcomeUnauthorized ||
			r.Subject != invocation.NoSubject || r.AuthMethod != "api-key" || r.Tool != invocation.Whole {
			t.Errorf("record %d: %+v", i, r)
		}
	}
	raw, _ := json.Marshal(recs)
	if strings.Contains(string(raw), "a-secret") || strings.Contains(string(raw), "classified") {
		t.Fatalf("a record holds the credential or the arguments: %s", raw)
	}
}

func TestAFloodOfRefusedCredentialsFromOneAddressIsCountedButNotAllRecorded(t *testing.T) {
	h := admissionHarness(t, baseClients)
	for i := 0; i < authFailureRecords+20; i++ {
		if r := h.rpc(t, "wrong-"+strconv.Itoa(i), "tools/list", "", nil); r.status != 401 {
			t.Fatal(r.status)
		}
	}
	if n := len(h.rec.all()); n != authFailureRecords {
		t.Fatalf("%d records for %d failures", n, authFailureRecords+20)
	}
	var out strings.Builder
	h.g.Metrics().Write(&out)
	if !strings.Contains(out.String(), "idp_mcp_gateway_auth_failures_total "+strconv.Itoa(authFailureRecords+20)) {
		t.Fatalf("the failures are not counted:\n%s", out.String())
	}
}

func TestAStreamedCallRecordsItsStartItsEndAndItsBytes(t *testing.T) {
	h := admissionHarness(t, baseClients)
	h.up.sse = true
	r := h.callTool(t, platformKey, "minimal__echo")
	if r.status != 200 || !strings.Contains(r.raw, "data:") {
		t.Fatalf("%d %s", r.status, r.raw)
	}
	recs := h.rec.all()
	if len(recs) != 2 {
		t.Fatalf("%d records: %+v", len(recs), recs)
	}
	start, end := recs[0], recs[1]
	if start.Outcome != invocation.OutcomeStreamStarted || start.Decision != invocation.Allow || start.Target != "minimal" || start.Bytes != 0 || start.Tool != "minimal__echo" {
		t.Errorf("start: %+v", start)
	}
	if end.Outcome != invocation.OutcomeStreamed || end.Bytes != int64(len(r.raw)) || end.Target != "minimal" || end.Subject != "svc-platform" {
		t.Errorf("end: %+v (the stream was %d bytes)", end, len(r.raw))
	}
	if !end.At.Equal(start.At) || end.LatencyMS < 0 {
		t.Errorf("the two records do not describe one request: %+v %+v", start, end)
	}
	// a call answered in one piece is one record, with no bytes
	h.up.sse = false
	h.callTool(t, platformKey, "minimal__echo")
	if got := h.rec.all(); len(got) != 3 || got[2].Outcome != invocation.OutcomeOK || got[2].Bytes != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestASubscriptionRecordsItsOpeningAndItsEndWithBytes(t *testing.T) {
	a := newRich(t, "alpha")
	h := richHarness(t, richRelease(t, release.NamingPrefixed, a), mustClients(t, `clients: {"api-key:k1": platform}`))
	s := openListen(t, h, operatorKey, `{"toolsListChanged":true,"resourceSubscriptions":["alpha://static"]}`)
	s.next(t, 2*time.Second)
	find := func(outcome string) (invocation.Record, bool) {
		for _, r := range h.rec.all() {
			if r.Method == "subscriptions/listen" && r.Outcome == outcome {
				return r, true
			}
		}
		return invocation.Record{}, false
	}
	eventually(t, func() bool { _, ok := find(invocation.OutcomeStreamStarted); return ok }, "the opening is recorded")
	if open, _ := find(invocation.OutcomeStreamStarted); open.Subject != "op" || open.Decision != invocation.Allow || !strings.Contains(open.Reason, "tools=true") || !strings.Contains(open.Reason, "subscriptions=1") {
		t.Fatalf("%+v", open)
	}
	s.cancel()
	eventually(t, func() bool { _, ok := find(invocation.OutcomeStreamed); return ok }, "the end is recorded")
	if end, _ := find(invocation.OutcomeStreamed); end.Bytes == 0 || end.Tool != invocation.Whole || end.Decision != invocation.Allow {
		t.Fatalf("%+v", end)
	}
	if strings.Contains(h.rec.last().Reason, "alpha://") {
		t.Fatal("the record repeats what the caller subscribed to")
	}
}
