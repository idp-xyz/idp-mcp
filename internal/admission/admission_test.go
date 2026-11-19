package admission

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fullFile = `
clients:
  idp-host: {kind: platform, host: true, rateLimit: 6000}
  idp-workspace: platform
  partner:
    kind: external
    servers: [docs]
    tools: ["wiki__search*"]
hostOnlyTools: ["web__*"]
hostOnlyExcept:
  - {pattern: "web__web_search", reason: "approved by security, ticket SEC-17"}
rateLimits:
  perClient: {requests: 600, window: 1m}
  perSubject: {requests: 60, window: 30s}
`

func parse(t *testing.T, text string) *Clients {
	t.Helper()
	c, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("%v\n%s", err, text)
	}
	return c
}

func TestAFullFileParsesAndRoundTripsItsSettings(t *testing.T) {
	c := parse(t, fullFile)
	if !c.IsHost("idp-host") || c.IsHost("idp-workspace") || c.IsHost("partner") || c.IsHost("") {
		t.Fatal("host flag")
	}
	if got := c.Limits(); got.PerSubject.Requests != 60 || got.PerSubject.Window != 30*time.Second || got.PerClient.Requests != 600 {
		t.Fatalf("%+v", got)
	}
	if len(c.Warnings()) != 0 {
		t.Fatalf("warnings %v", c.Warnings())
	}
}

func TestTheFileMayBeJSON(t *testing.T) {
	c := parse(t, `{"clients": {"idp-host": {"kind": "platform", "host": true}}, "hostOnlyTools": ["web__*"]}`)
	if !c.IsHost("idp-host") {
		t.Fatal("not the host")
	}
}

func TestTheDefaultsApplyWhenTheFileSetsNoLimits(t *testing.T) {
	l := parse(t, `clients: {a: platform}`).Limits()
	if l.PerClient != (Limit{DefaultClientRequests, time.Minute}) || l.PerSubject != (Limit{DefaultSubjectRequests, time.Minute}) {
		t.Fatalf("%+v", l)
	}
}

func TestInvalidFilesAreRefusedWithAMessageThatNamesTheProblem(t *testing.T) {
	for name, c := range map[string]struct{ text, want string }{
		"no clients":             {`hostOnlyTools: ["web__*"]`, "lists no client"},
		"empty clients":          {`clients: {}`, "lists no client"},
		"unknown kind":           {`clients: {a: {kind: friend}}`, "kind must be"},
		"no kind":                {`clients: {a: {host: true}}`, "kind must be"},
		"external without lists": {`clients: {a: {kind: external}}`, "needs servers or tools"},
		"external as one word":   {`clients: {a: external}`, "written as one word"},
		"platform with servers":  {`clients: {a: {kind: platform, servers: [docs]}}`, "belong to an external client"},
		"external host":          {`clients: {a: {kind: external, servers: [docs], host: true}}`, "only a platform client can be the host"},
		"wildcard external":      {`clients: {"*": {kind: external, servers: [docs]}}`, `"*" can only be a platform`},
		"wildcard host":          {`clients: {"*": {kind: platform, host: true}}`, `"*" can only be a platform`},
		"bad server name":        {`clients: {a: {kind: external, servers: ["Docs!"]}}`, "is not a server name"},
		"bad client pattern":     {`clients: {a: {kind: external, tools: ["web__["]}}`, "not a valid tool name pattern"},
		"empty client pattern":   {`clients: {a: {kind: external, tools: [""]}}`, "not a valid tool name pattern"},
		"bad host-only pattern":  {"clients: {a: platform}\nhostOnlyTools: [\"[\"]", "hostOnlyTools"},
		"exception without why":  {"clients: {a: platform}\nhostOnlyExcept: [{pattern: \"web__x\"}]", "needs a reason"},
		"exception blank why":    {"clients: {a: platform}\nhostOnlyExcept: [{pattern: \"web__x\", reason: \"  \"}]", "needs a reason"},
		"exception long why":     {"clients: {a: platform}\nhostOnlyExcept: [{pattern: \"web__x\", reason: \"" + strings.Repeat("x", MaxReason+1) + "\"}]", "longer than"},
		"exception bad pattern":  {"clients: {a: platform}\nhostOnlyExcept: [{pattern: \"[\", reason: \"r\"}]", "hostOnlyExcept"},
		"negative rate limit":    {`clients: {a: {kind: platform, rateLimit: -1}}`, "must be positive"},
		"bad window":             {"clients: {a: platform}\nrateLimits: {perClient: {window: soon}}", "not a duration"},
		"negative requests":      {"clients: {a: platform}\nrateLimits: {perSubject: {requests: -5}}", "must be positive"},
		"misspelt setting":       {"clients: {a: platform}\nhostOnlyTool: [\"web__*\"]", "hostOnlyTool"},
		"misspelt client field":  {`clients: {a: {kind: platform, hosts: true}}`, "hosts"},
		"duplicate client":       {"clients:\n  a: platform\n  a: platform\n", "already defined"},
		"empty file":             {``, "not a valid clients file"},
		"not a mapping":          {`- a`, "not a valid clients file"},
	} {
		_, err := Parse([]byte(c.text))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %v, want it to say %q", name, err, c.want)
		}
	}
}

func TestLoadWithoutAFileNamesTheSettingAndTheDeliberateOptOut(t *testing.T) {
	_, err := Load("")
	if err == nil {
		t.Fatal("no error")
	}
	for _, want := range []string{"IDP_GATEWAY_CLIENTS_FILE", `"*": platform`, "turns client authorization off"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message does not say %q: %v", want, err)
		}
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil || !strings.Contains(err.Error(), "clients file") {
		t.Fatalf("%v", err)
	}
	f := filepath.Join(t.TempDir(), "clients.yaml")
	if err := os.WriteFile(f, []byte(fullFile), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(f); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	_ = os.WriteFile(bad, []byte("clients: {a: friend}"), 0o600)
	if _, err := Load(bad); err == nil || !strings.Contains(err.Error(), bad) {
		t.Fatalf("the error does not name the file: %v", err)
	}
}

func TestTheWildcardIsAWarningAndServesEveryClientIncludingNone(t *testing.T) {
	c := parse(t, `clients: {"*": platform}`)
	if len(c.Warnings()) != 1 || !strings.Contains(c.Warnings()[0], "authorization is off") {
		t.Fatalf("%v", c.Warnings())
	}
	for _, id := range []string{"idp-host", "anything", ""} {
		if v := c.Decide(id, Access{Target: "web", Tool: "web__web_open_url"}); !v.Allowed {
			t.Errorf("client %q: %+v", id, v)
		}
	}
	if c.IsHost("") || c.IsHost("anything") {
		t.Fatal("the wildcard makes nobody the host")
	}
}

func TestAHostOnlyPatternWithNoHostClientIsAWarning(t *testing.T) {
	c := parse(t, "clients: {a: platform}\nhostOnlyTools: [\"web__*\"]")
	if len(c.Warnings()) != 1 || !strings.Contains(c.Warnings()[0], "nobody may call") {
		t.Fatalf("%v", c.Warnings())
	}
}

func TestNothingIsServedWithoutAFile(t *testing.T) {
	var c *Clients // what a gateway built without the setting holds
	if c.Listed("idp-host") || c.Decide("idp-host", Access{Target: "web", Tool: "web__x"}).Allowed || c.IsHost("idp-host") {
		t.Fatal("a nil list serves a client")
	}
	if l, limited := c.ClientLimit("x"); !limited || l.Requests != DefaultClientRequests {
		t.Fatal("a client of a nil list is not limited by the default")
	}
}

func TestDecideCombinesListingAllowListHostOnlyAndExceptions(t *testing.T) {
	c := parse(t, fullFile)
	web := Access{Target: "web", Tool: "web__web_open_url"}
	search := Access{Target: "web", Tool: "web__web_search"}
	docs := Access{Target: "docs", Tool: "docs__read"}
	wiki := Access{Target: "wiki", Tool: "wiki__search_pages"}
	wikiOther := Access{Target: "wiki", Tool: "wiki__delete"}
	prompt := Access{Target: "docs"}
	byClass := Access{Target: "ext", Tool: "ext__call", HostOnly: true}
	for _, tc := range []struct {
		name   string
		client string
		a      Access
		want   Verdict
	}{
		{"unlisted", "stranger", docs, Verdict{Why: NotListed}},
		{"no client", "", docs, Verdict{Why: NotListed}},
		{"platform sees what roles allow", "idp-workspace", docs, Verdict{Allowed: true}},
		{"host reaches a host-only tool", "idp-host", web, Verdict{Allowed: true}},
		{"platform may not", "idp-workspace", web, Verdict{Why: HostOnly}},
		{"external server grant", "partner", docs, Verdict{Allowed: true}},
		{"external prompt by server", "partner", prompt, Verdict{Allowed: true}},
		{"external tool pattern", "partner", wiki, Verdict{Allowed: true}},
		{"external outside both", "partner", wikiOther, Verdict{Why: NotAllowed}},
		{"a tool pattern grants no prompt", "partner", Access{Target: "wiki"}, Verdict{Why: NotAllowed}},
		{"external may not reach host-only", "partner", web, Verdict{Why: HostOnly}},
		{"exception: platform through", "idp-workspace", search, Verdict{Allowed: true, Exception: "approved by security, ticket SEC-17"}},
		{"exception: host uses none", "idp-host", search, Verdict{Allowed: true}},
		{"exception does not outlive its tool", "idp-workspace", web, Verdict{Why: HostOnly}},
		{"exception does not widen an allow-list", "partner", search, Verdict{Why: NotAllowed}},
		{"host-only by the release", "idp-workspace", byClass, Verdict{Why: HostOnly}},
		{"host-only by the release: the host", "idp-host", byClass, Verdict{Allowed: true}},
		{"host-only by the release: a prompt", "idp-workspace", Access{Target: "ext", HostOnly: true}, Verdict{Why: HostOnly}},
	} {
		if got := c.Decide(tc.client, tc.a); got != tc.want {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
		}
	}
	// an exception lifts the release's class source as well, for the tools it names
	lifted := parse(t, "clients: {a: platform}\nhostOnlyExcept: [{pattern: \"ext__call\", reason: \"r\"}]")
	if got := lifted.Decide("a", byClass); !got.Allowed || got.Exception != "r" {
		t.Errorf("%+v", got)
	}
}

func TestTheLimiterSlidesRefusesWithTheWaitAndKeepsKeysApart(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewLimiter(func() time.Time { return now })
	lim := Limit{Requests: 2, Window: time.Minute}
	if l.Allow("a", lim) != 0 {
		t.Fatal("first")
	}
	now = now.Add(10 * time.Second)
	if l.Allow("a", lim) != 0 {
		t.Fatal("second")
	}
	now = now.Add(10 * time.Second)
	if wait := l.Allow("a", lim); wait != 40*time.Second {
		t.Fatalf("wait %v", wait)
	}
	if l.Allow("b", lim) != 0 {
		t.Fatal("another key shares the window")
	}
	// a refused request is not counted: when the first leaves the window one place is free, not none
	now = now.Add(41 * time.Second)
	if l.Allow("a", lim) != 0 {
		t.Fatal("the window did not slide")
	}
	if wait := l.Allow("a", lim); wait != 9*time.Second {
		t.Fatalf("wait %v: the refused request was counted, or the slide is wrong", wait)
	}
}

func TestTheLimiterDropsIdleKeysWithoutDroppingLiveOnes(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewLimiter(func() time.Time { return now })
	long := Limit{Requests: 1, Window: time.Hour}
	l.Allow("live", long)
	for i := 0; i <= maxKeys; i++ {
		l.Allow(string(rune('a'+i%26))+strings.Repeat("x", i/26), Limit{Requests: 1, Window: time.Second})
		if i == maxKeys/2 {
			now = now.Add(2 * time.Second)
		}
	}
	now = now.Add(2 * time.Second)
	l.Allow("trigger", Limit{Requests: 1, Window: time.Second})
	if l.Allow("live", long) == 0 {
		t.Fatal("a key still inside its hour was dropped with the idle ones")
	}
	if len(l.buckets) > maxKeys {
		t.Fatalf("%d keys held", len(l.buckets))
	}
}

func TestPlatformClientsAreNotLimitedUnlessTheFileSaysSoAndOthersAre(t *testing.T) {
	c := parse(t, `
clients:
  idp-host: {kind: platform, host: true, rateLimit: 6000}
  idp-workspace: {kind: platform, subjectRateLimit: 30}
  eer: platform
  partner: {kind: external, servers: [docs]}
  partner2: {kind: external, servers: [docs], rateLimit: 5, subjectRateLimit: 2}
rateLimits: {perClient: {requests: 600, window: 1m}, perSubject: {requests: 120, window: 30s}}
`)
	type want struct {
		limited  bool
		requests int
	}
	for _, tc := range []struct {
		client          string
		perClient, perS want
	}{
		{"idp-host", want{true, 6000}, want{false, 0}},    // its own client limit; its subjects are never limited
		{"idp-workspace", want{false, 0}, want{true, 30}}, // the reverse
		{"eer", want{false, 0}, want{false, 0}},           // a platform client with nothing set: free
		{"partner", want{true, 600}, want{true, 120}},     // an external client: the defaults
		{"partner2", want{true, 5}, want{true, 2}},        // overridden
		{"stranger", want{true, 600}, want{true, 120}},    // not listed: always limited
		{"", want{true, 600}, want{true, 120}},            // no client at all: the same
	} {
		l, ok := c.ClientLimit(tc.client)
		if ok != tc.perClient.limited || (ok && l.Requests != tc.perClient.requests) {
			t.Errorf("%q per client: %+v %v", tc.client, l, ok)
		}
		l, ok = c.SubjectLimit(tc.client)
		if ok != tc.perS.limited || (ok && (l.Requests != tc.perS.requests || l.Window != 30*time.Second)) {
			t.Errorf("%q per subject: %+v %v", tc.client, l, ok)
		}
	}
	// the wildcard is a platform entry: nothing is unlisted under it, and it is not limited either
	if _, ok := parse(t, `clients: {"*": platform}`).ClientLimit("anyone"); ok {
		t.Error("the wildcard limits")
	}
	if _, err := Parse([]byte(`clients: {a: {kind: platform, subjectRateLimit: -1}}`)); err == nil {
		t.Error("a negative subject limit is accepted")
	}
}
