package release

import (
	"encoding/json"
	"strings"
	"testing"

	"idp-mcp/internal/server"
)

func sample() *Document {
	d := &Document{
		SchemaVersion: SchemaVersion, ReleaseID: "r1", TenantID: "t1", GatewayID: "g1",
		CreatedAt: "2026-11-02T10:00:00Z", CreatedBy: "alice", DriftAction: "block", ToolNaming: NamingPrefixed,
		Targets: []Target{{Name: "minimal", ServerID: "s1", Endpoint: "http://minimal:3111/mcp", Network: NetworkPrivate, Capabilities: []string{CapTools},
			Tools: []server.Tool{{Name: "echo", InputSchema: map[string]any{"type": "object", "maxLength": json.Number("512")}},
				{Name: "sum", InputSchema: map[string]any{"type": "object"}}}}},
		Grants: []Grant{{Target: "minimal", Tools: []string{"echo", "sum"}, Roles: []string{"operator"}}},
		Auth:   Auth{Mode: "api-key", APIKeys: []APIKey{{ID: "k1", Subject: "svc", Roles: []string{"operator"}, SHA256: strings.Repeat("a", 64)}}},
	}
	d.Targets[0].SnapshotDigest, _ = CatalogDigest(d.Targets[0].Tools, nil)
	return d
}

func TestCanonicalIsKeyOrderIndependentAndKeepsNumbers(t *testing.T) {
	a, _ := Canonical(json.RawMessage(`{"b":1,"a":{"y":2.50,"x":"<&>"}}`))
	b, _ := Canonical(json.RawMessage(`{ "a" : { "x":"<&>", "y":2.50 }, "b":1 }`))
	if string(a) != string(b) || string(a) != `{"a":{"x":"<&>","y":2.50},"b":1}` {
		t.Fatalf("%s vs %s", a, b)
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	env, err := Seal(sample())
	if err != nil {
		t.Fatal(err)
	}
	// distribution re-encodes the document (whitespace, key order); the digest still holds
	var generic map[string]any
	_ = json.Unmarshal(env.Document, &generic)
	pretty, _ := json.MarshalIndent(generic, "", "  ")
	d, err := Open(&Envelope{Digest: env.Digest, Document: pretty})
	if err != nil {
		t.Fatal(err)
	}
	if d.Targets[0].Tools[0].Name != "echo" || d.Auth.APIKeys[0].Subject != "svc" {
		t.Fatalf("%+v", d)
	}
}

func TestOpenRefusesTampering(t *testing.T) {
	env, _ := Seal(sample())
	tampered := strings.Replace(string(env.Document), `"operator"`, `"admin"`, 1)
	if _, err := Open(&Envelope{Digest: env.Digest, Document: json.RawMessage(tampered)}); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("tampered release opened: %v", err)
	}
	// unknown fields are refused even with a matching digest
	extra := strings.Replace(string(env.Document), `{"auth"`, `{"x":1,"auth"`, 1)
	dg, _ := Digest(json.RawMessage(extra))
	if _, err := Open(&Envelope{Digest: dg, Document: json.RawMessage(extra)}); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestValidateFailsClosed(t *testing.T) {
	cases := map[string]func(d *Document){
		"schema":                           func(d *Document) { d.SchemaVersion = "v0" },
		"drift":                            func(d *Document) { d.DriftAction = "ignore" },
		"target name":                      func(d *Document) { d.Targets[0].Name = "Bad_Name" },
		"endpoint creds":                   func(d *Document) { d.Targets[0].Endpoint = "http://u:p@minimal/mcp" },
		"endpoint scheme":                  func(d *Document) { d.Targets[0].Endpoint = "stdio://cmd" },
		"dup tool":                         func(d *Document) { d.Targets[0].Tools[1].Name = "echo" },
		"no schema":                        func(d *Document) { d.Targets[0].Tools[0].InputSchema = nil },
		"network":                          func(d *Document) { d.Targets[0].Network = "anywhere" },
		"snapshot drift":                   func(d *Document) { d.Targets[0].Tools[0].Description = "changed after approval" },
		"grant target":                     func(d *Document) { d.Grants[0].Target = "nope" },
		"grant tool":                       func(d *Document) { d.Grants[0].Tools = []string{"rm"} },
		"grant roles":                      func(d *Document) { d.Grants[0].Roles = nil },
		"naming":                           func(d *Document) { d.ToolNaming = "" },
		"capability":                       func(d *Document) { d.Targets[0].Capabilities = []string{"sampling"} },
		"prompt grant without prompts":     func(d *Document) { d.Grants[0].Prompts = []string{"*"} },
		"resource grant without resources": func(d *Document) { d.Grants[0].Resources = true },
		"resources without capability": func(d *Document) {
			d.Targets[0].Resources = []server.Resource{{URI: "x://a", Name: "a"}}
			d.Targets[0].SnapshotDigest, _ = d.Targets[0].Catalog().Digest()
		},
		"resource uri without scheme": func(d *Document) {
			d.Targets[0].Capabilities = []string{CapTools, CapResources}
			d.Targets[0].Resources = []server.Resource{{URI: "not-a-uri", Name: "a"}}
			d.Targets[0].SnapshotDigest, _ = d.Targets[0].Catalog().Digest()
		},
		"duplicate resource": func(d *Document) {
			d.Targets[0].Capabilities = []string{CapTools, CapResources}
			d.Targets[0].Resources = []server.Resource{{URI: "x://a", Name: "a"}, {URI: "x://a", Name: "b"}}
			d.Targets[0].SnapshotDigest, _ = d.Targets[0].Catalog().Digest()
		},
		"resource edited after sealing": func(d *Document) {
			d.Targets[0].Capabilities = []string{CapTools, CapResources}
			d.Targets[0].Resources = []server.Resource{{URI: "x://a", Name: "a"}}
			d.Targets[0].SnapshotDigest, _ = d.Targets[0].Catalog().Digest()
			d.Targets[0].Resources[0].Description = "changed"
		},
		"empty grant": func(d *Document) { d.Grants[0].Tools = nil },
		"native collision": func(d *Document) {
			d.ToolNaming = NamingNative
			t2 := d.Targets[0]
			t2.Name, t2.ServerID = "other", "s2"
			d.Targets = append(d.Targets, t2)
		},
		"auth mode":   func(d *Document) { d.Auth.Mode = "none" },
		"key hash":    func(d *Document) { d.Auth.APIKeys[0].SHA256 = "plain-secret" },
		"jwt missing": func(d *Document) { d.Auth = Auth{Mode: "jwt"} },
		"jwt urls": func(d *Document) {
			d.Auth = Auth{Mode: "jwt", JWT: &JWT{Issuer: "x", Resource: "y", JWKSURL: "z", TenantClaim: "t", RolesClaim: "r", AuthorizationServers: []string{"a"}}}
		},
	}
	for name, mutate := range cases {
		d := sample()
		mutate(d)
		if err := d.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := sample().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestNativeNamingAllowsUniqueNames(t *testing.T) {
	d := sample()
	d.ToolNaming = NamingNative
	d.Targets[0].Capabilities = []string{CapTools, CapPrompts, CapResources}
	d.Targets[0].Prompts = []server.Prompt{{Name: "greet"}}
	d.Targets[0].SnapshotDigest, _ = CatalogDigest(d.Targets[0].Tools, d.Targets[0].Prompts)
	d.Grants = append(d.Grants, Grant{Target: "minimal", Prompts: []string{"greet"}, Resources: true, Roles: []string{"reader"}})
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	if d.Expose("minimal", "echo") != "echo" {
		t.Fatal(d.Expose("minimal", "echo"))
	}
}

func TestExposedNames(t *testing.T) {
	if n := ExposedName("minimal", "echo"); n != "minimal__echo" {
		t.Fatal(n)
	}
	for in, want := range map[string][2]string{"minimal__echo": {"minimal", "echo"}, "a__b__c": {"a", "b__c"}} {
		tg, tl, ok := SplitExposedName(in)
		if !ok || tg != want[0] || tl != want[1] {
			t.Errorf("%s -> %s %s %v", in, tg, tl, ok)
		}
	}
	for _, in := range []string{"echo", "__echo", "minimal__", ""} {
		if _, _, ok := SplitExposedName(in); ok {
			t.Errorf("%q split", in)
		}
	}
}

func TestPinnedResourcesRoundTripWithEveryField(t *testing.T) {
	d := sample()
	d.Targets[0].Capabilities = []string{CapTools, CapResources}
	var r server.Resource
	if err := json.Unmarshal([]byte(`{"uri":"x://a","name":"a","mimeType":"text/plain","size":12,"annotations":{"audience":["user"]},"_meta":{"v":1}}`), &r); err != nil {
		t.Fatal(err)
	}
	var tpl server.ResourceTemplate
	_ = json.Unmarshal([]byte(`{"uriTemplate":"x://item/{id}","name":"item","icons":[{"src":"x://i.png"}]}`), &tpl)
	d.Targets[0].Resources, d.Targets[0].ResourceTemplates = []server.Resource{r}, []server.ResourceTemplate{tpl}
	d.Targets[0].SnapshotDigest, _ = d.Targets[0].Catalog().Digest()
	env, err := Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Open(env)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(back.Targets[0].Resources[0])
	for _, want := range []string{`"size":12`, `"audience":["user"]`, `"_meta":{"v":1}`, `"mimeType":"text/plain"`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("%s lost %s", b, want)
		}
	}
	if tb, _ := json.Marshal(back.Targets[0].ResourceTemplates[0]); !strings.Contains(string(tb), `"icons"`) {
		t.Fatalf("%s lost icons", tb)
	}
}
