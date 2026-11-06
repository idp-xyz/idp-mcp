package release

// The published contract idp.telos.mcp 1.1.0 (idp-contracts/idp.telos.mcp/1.1.0) is produced here.
// api/contracts/schema.json is written by hand; these tests prove it describes exactly what this
// package seals and what the gateway records. api/contracts/examples.json is generated from Go
// values (go test ./internal/release -run TestContract -update) and checked on every run, so every
// published example is a document the implementation actually produces.

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"idp-mcp/internal/invocation"
	"idp-mcp/internal/server"
)

var update = flag.Bool("update", false, "regenerate api/contracts/examples.json from the Go values")

const (
	contractDir = "../../api/contracts"
	contractID  = "urn:idp:telos:mcp:1.1.0"
)

type noLoader struct{}

func (noLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("external reference %q is not loaded", url)
}

// contract compiles one definition of the schema (or the root when def is "").
type contract struct {
	t    *testing.T
	c    *jsonschema.Compiler
	defs map[string]*jsonschema.Schema
	raw  map[string]any
}

func loadContract(t *testing.T) *contract {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(contractDir, "schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(noLoader{})
	c.AssertFormat()
	if err := c.AddResource(contractID, doc); err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	_ = json.Unmarshal(b, &raw)
	return &contract{t: t, c: c, defs: map[string]*jsonschema.Schema{}, raw: raw}
}

func (k *contract) schema(def string) *jsonschema.Schema {
	if s := k.defs[def]; s != nil {
		return s
	}
	loc := contractID
	if def != "" {
		loc += "#/$defs/" + def
	}
	s, err := k.c.Compile(loc)
	if err != nil {
		k.t.Fatalf("compile %s: %v", loc, err)
	}
	k.defs[def] = s
	return s
}

// validate checks raw JSON against a definition and against the root (whose oneOf must dispatch
// to the same definition for the three top-level documents).
func (k *contract) validate(def string, raw []byte) error {
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	if err := k.schema(def).Validate(inst); err != nil {
		return fmt.Errorf("%s: %w", def, err)
	}
	if def == "Release" || def == "Envelope" || def == "InvocationRecord" {
		if err := k.schema("").Validate(inst); err != nil {
			return fmt.Errorf("root oneOf rejects a valid %s: %w", def, err)
		}
	}
	return nil
}

func mustJSON(t *testing.T, s string, v any) {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		t.Fatal(err)
	}
}

// exampleDocuments are the two releases published as examples: a complete api-key/prefixed one and
// a jwt/native one with the tasks extension.
func exampleDocuments(t *testing.T) (full, jwt *Document) {
	t.Helper()
	var create, get server.Tool
	mustJSON(t, `{"name":"create_shipment","title":"Create shipment","description":"Creates a shipment and returns its id.",
		"inputSchema":{"type":"object","properties":{"recipient":{"type":"string"},"weightKg":{"type":"number","minimum":0.01}},"required":["recipient","weightKg"],"additionalProperties":false},
		"outputSchema":{"type":"object","properties":{"shipmentId":{"type":"string"}},"required":["shipmentId"]},
		"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":true,"openWorldHint":true}}`, &create)
	mustJSON(t, `{"name":"get_shipment","description":"Reads one shipment.","inputSchema":{"type":"object","properties":{"shipmentId":{"type":"string"}},"required":["shipmentId"]},
		"annotations":{"readOnlyHint":true},"icons":[{"src":"https://parcel.internal.example/icon.png","mimeType":"image/png"}]}`, &get)
	var label server.Prompt
	mustJSON(t, `{"name":"shipping-label","title":"Shipping label","description":"Drafts a label for a shipment.","arguments":[{"name":"shipmentId","description":"Shipment id","required":true}]}`, &label)
	var rates server.Resource
	mustJSON(t, `{"uri":"parcel://rates/current","name":"rates","title":"Current rates","mimeType":"application/json","size":2048}`, &rates)
	var shipment server.ResourceTemplate
	mustJSON(t, `{"uriTemplate":"parcel://shipments/{id}","name":"shipment","mimeType":"application/json"}`, &shipment)
	parcel := Target{Name: "parcel", ServerID: "srv-parcel", Endpoint: "https://parcel.internal.example:8443/mcp", Network: NetworkPrivate,
		Tools: []server.Tool{create, get}, Prompts: []server.Prompt{label}, Resources: []server.Resource{rates}, ResourceTemplates: []server.ResourceTemplate{shipment},
		Capabilities: []string{CapTools, CapPrompts, CapResources, CapCompletions, CapResourcesSubscribe}}
	var err error
	if parcel.SnapshotDigest, err = parcel.Catalog().Digest(); err != nil {
		t.Fatal(err)
	}
	full = &Document{SchemaVersion: SchemaVersion, ReleaseID: "rel-2026-11-03-001", TenantID: "acme", GatewayID: "gw-edge-1",
		CreatedAt: "2026-11-03T08:00:00Z", CreatedBy: "alice", ApprovedBy: "bob", DriftAction: "block", ToolNaming: NamingPrefixed,
		Targets: []Target{parcel},
		Grants: []Grant{{Target: "parcel", Tools: []string{"create_shipment", "get_shipment"}, Prompts: []string{"*"}, Resources: true, Roles: []string{"operator"}},
			{Target: "parcel", Tools: []string{"get_shipment"}, Roles: []string{"viewer"}}},
		Auth: Auth{Mode: "api-key", APIKeys: []APIKey{{ID: "k-agent-1", Subject: "svc-agent", Roles: []string{"operator"}, SHA256: strings.Repeat("0123456789abcdef", 4)}}}}

	var job server.Tool
	mustJSON(t, `{"name":"long_running_job","description":"Starts a job; may answer with a task.","inputSchema":{"type":"object","properties":{"input":{"type":"string"}}},
		"execution":{"taskSupport":"optional"}}`, &job)
	tasks := Target{Name: "tasks", ServerID: "srv-tasks", Endpoint: "http://127.0.0.1:3111/mcp", Network: NetworkLoopback, Identity: IdentityForward,
		Tools: []server.Tool{job}, Capabilities: []string{CapTools, CapTasks}}
	if tasks.SnapshotDigest, err = tasks.Catalog().Digest(); err != nil {
		t.Fatal(err)
	}
	issuer := "https://idp.example/realms/idp"
	jwt = &Document{SchemaVersion: SchemaVersion, ReleaseID: "rel-2026-11-03-002", TenantID: "acme", GatewayID: "gw-dev-1",
		CreatedAt: "2026-11-03T09:30:00Z", CreatedBy: "alice", DriftAction: "report", ToolNaming: NamingNative,
		Targets: []Target{tasks},
		Grants:  []Grant{{Target: "tasks", Tools: []string{"long_running_job"}, Roles: []string{"agent"}}},
		Auth: Auth{Mode: "jwt", JWT: &JWT{Issuer: issuer, Resource: "https://mcp.example/mcp", JWKSURL: issuer + "/protocol/openid-connect/certs",
			AuthorizationServers: []string{issuer}, TenantClaim: "tenant_id", RolesClaim: "roles"}}}
	return full, jwt
}

func exampleRecords(t *testing.T, releaseDigest string) []invocation.Record {
	t.Helper()
	at := time.Date(2026, 11, 3, 10, 15, 0, 0, time.UTC)
	argsDigest, err := Digest(json.RawMessage(`{"recipient":"Example GmbH","weightKg":1.2}`))
	if err != nil {
		t.Fatal(err)
	}
	return []invocation.Record{
		{At: at, ReleaseDigest: releaseDigest, Subject: "svc-agent", AuthMethod: "api-key", Method: "tools/call", Tool: "parcel__create_shipment", Target: "parcel",
			Decision: invocation.Allow, Outcome: invocation.OutcomeOK, LatencyMS: 42, TraceID: "4bf92f3577b34da6a3ce929d0e0e4736", ArgsDigest: argsDigest},
		{At: at.Add(time.Second), ReleaseDigest: releaseDigest, Subject: "alice", Client: "agent-exchange", Actor: "svc-agent", AuthMethod: "jwt",
			Method: "prompts/get", Tool: "parcel__internal-only", Decision: invocation.Deny, Outcome: invocation.OutcomeDenied, LatencyMS: 1},
		{At: at.Add(2 * time.Second), ReleaseDigest: releaseDigest, Subject: "svc-agent", AuthMethod: "api-key", Method: "resources/read", Tool: "parcel://rates/current", Target: "parcel",
			Decision: invocation.Allow, Outcome: invocation.OutcomeNotDelivered, LatencyMS: 3, TraceID: "4bf92f3577b34da6a3ce929d0e0e4737"},
		{At: at.Add(3 * time.Second), ReleaseDigest: releaseDigest, Subject: "alice", Client: "agent-exchange", AuthMethod: "jwt", Method: "tasks/get",
			Tool: "task_01JD7Q3Z8M8T0G3C6N4V9S2A1B", Target: "tasks", Decision: invocation.Allow, Outcome: invocation.OutcomeOK, LatencyMS: 7},
	}
}

type example struct {
	Definition string          `json:"definition"`
	Value      json.RawMessage `json:"value"`
}

type examplesFile struct {
	Description string    `json:"description"`
	GeneratedBy string    `json:"generatedBy"`
	Examples    []example `json:"examples"`
}

func buildExamples(t *testing.T) []byte {
	t.Helper()
	full, jwt := exampleDocuments(t)
	var out []example
	add := func(def string, v any) {
		raw, err := Canonical(v)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, example{Definition: def, Value: raw})
	}
	fullEnv, err := Seal(full)
	if err != nil {
		t.Fatal(err)
	}
	jwtEnv, err := Seal(jwt)
	if err != nil {
		t.Fatal(err)
	}
	add("Release", json.RawMessage(fullEnv.Document))
	add("Release", json.RawMessage(jwtEnv.Document))
	add("Envelope", fullEnv)
	for _, r := range exampleRecords(t, fullEnv.Digest) {
		add("InvocationRecord", r)
	}
	b, err := json.MarshalIndent(examplesFile{
		Description: "idp.telos.mcp 1.1.0 的示例：每一个都是 idp-mcp 实际产出的文档（Release 经 release.Seal 密封，InvocationRecord 是网关写入的记录）。",
		GeneratedBy: "go test ./internal/release -run TestContract -update",
		Examples:    out,
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

// TestContractExamplesAreGeneratedAndValid keeps examples.json equal to what Go produces, and checks
// that every example satisfies the schema and is accepted by the implementation.
func TestContractExamplesAreGeneratedAndValid(t *testing.T) {
	want := buildExamples(t)
	path := filepath.Join(contractDir, "examples.json")
	if *update {
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	have, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(have, want) {
		t.Fatalf("%s is out of date; run: go test ./internal/release -run TestContract -update", path)
	}
	var f examplesFile
	if err := json.Unmarshal(have, &f); err != nil {
		t.Fatal(err)
	}
	k := loadContract(t)
	seen := map[string]int{}
	for i, x := range f.Examples {
		seen[x.Definition]++
		if err := k.validate(x.Definition, x.Value); err != nil {
			t.Errorf("example %d (%s): %v", i, x.Definition, err)
		}
		switch x.Definition {
		case "Release":
			digest, _ := Digest(x.Value)
			if _, err := Open(&Envelope{Digest: digest, Document: x.Value}); err != nil {
				t.Errorf("example %d: the implementation rejects the published Release: %v", i, err)
			}
		case "Envelope":
			var env Envelope
			if err := json.Unmarshal(x.Value, &env); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(&env); err != nil {
				t.Errorf("example %d: the implementation rejects the published Envelope: %v", i, err)
			}
		case "InvocationRecord":
			var rec invocation.Record
			dec := json.NewDecoder(bytes.NewReader(x.Value))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&rec); err != nil {
				t.Errorf("example %d: not a gateway record: %v", i, err)
				continue
			}
			back, _ := Canonical(rec)
			if want, _ := Canonical(x.Value); !bytes.Equal(back, want) {
				t.Errorf("example %d: record does not round-trip through invocation.Record:\n%s\n%s", i, want, back)
			}
		}
	}
	for _, def := range []string{"Release", "Envelope", "InvocationRecord"} {
		if seen[def] == 0 {
			t.Errorf("no example for %s", def)
		}
	}
}

// TestContractAcceptsWhatSealProduces: documents sealed from the unit-test fixtures - including ones
// built with nil collections, as the registry does for servers without prompts - satisfy the schema.
func TestContractAcceptsWhatSealProduces(t *testing.T) {
	k := loadContract(t)
	nilCollections := sample()
	nilCollections.Targets[0].Prompts = nil
	nilCollections.Targets[0].Capabilities = nil
	nilCollections.Grants[0].Prompts = nil
	everyField := sample()
	everyField.Targets[0].Capabilities = []string{CapTools, CapResources, CapPrompts}
	var r server.Resource
	mustJSON(t, `{"uri":"x://a","name":"a","mimeType":"text/plain","size":12,"annotations":{"audience":["user"]},"_meta":{"v":1}}`, &r)
	var tpl server.ResourceTemplate
	mustJSON(t, `{"uriTemplate":"x://item/{id}","name":"item","icons":[{"src":"x://i.png"}]}`, &tpl)
	var p server.Prompt
	mustJSON(t, `{"name":"p","arguments":[{"name":"a","required":false}],"_meta":{"k":"v"}}`, &p)
	everyField.Targets[0].Resources, everyField.Targets[0].ResourceTemplates, everyField.Targets[0].Prompts = []server.Resource{r}, []server.ResourceTemplate{tpl}, []server.Prompt{p}
	everyField.Targets[0].SnapshotDigest, _ = everyField.Targets[0].Catalog().Digest()
	everyField.Grants = append(everyField.Grants, Grant{Target: "minimal", Tools: []string{}, Prompts: []string{"p"}, Roles: []string{"r"}},
		Grant{Target: "minimal", Tools: []string{}, Resources: true, Roles: []string{"r"}})
	_, jwt := exampleDocuments(t)
	for name, d := range map[string]*Document{"sample": sample(), "nil collections": nilCollections, "every field": everyField, "jwt": jwt} {
		env, err := Seal(d)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := k.validate("Release", env.Document); err != nil {
			t.Errorf("%s: sealed document violates the contract: %v\n%s", name, err, env.Document)
		}
		raw, _ := json.Marshal(env)
		if err := k.validate("Envelope", raw); err != nil {
			t.Errorf("%s: envelope violates the contract: %v", name, err)
		}
		if strings.Contains(string(env.Document), "null") {
			t.Errorf("%s: sealed document contains null: %s", name, env.Document)
		}
	}
}

// TestContractFieldsMatchGo: for every closed definition, the schema's properties are exactly the
// struct's JSON fields, required is exactly the fields without omitempty, and additionalProperties
// is false (Open decodes with DisallowUnknownFields). The open MCP definitions keep their required
// fields and allow additional ones, as the pinned Extra fields need.
func TestContractFieldsMatchGo(t *testing.T) {
	k := loadContract(t)
	defs := k.raw["$defs"].(map[string]any)
	strs := func(v any) []string {
		var out []string
		for _, x := range v.([]any) {
			out = append(out, x.(string))
		}
		sort.Strings(out)
		return out
	}
	props := func(def string) []string {
		var out []string
		for name := range defs[def].(map[string]any)["properties"].(map[string]any) {
			out = append(out, name)
		}
		sort.Strings(out)
		return out
	}
	closed := map[string]any{"Release": Document{}, "Target": Target{}, "Grant": Grant{}, "Auth": Auth{}, "APIKey": APIKey{}, "JWT": JWT{},
		"Envelope": Envelope{}, "InvocationRecord": invocation.Record{}}
	for def, zero := range closed {
		d := defs[def].(map[string]any)
		if d["additionalProperties"] != false {
			t.Errorf("%s: additionalProperties must be false", def)
		}
		var fields, required []string
		rt := reflect.TypeOf(zero)
		for i := 0; i < rt.NumField(); i++ {
			tag := rt.Field(i).Tag.Get("json")
			name, opts, _ := strings.Cut(tag, ",")
			fields = append(fields, name)
			if !strings.Contains(opts, "omitempty") {
				required = append(required, name)
			}
		}
		sort.Strings(fields)
		sort.Strings(required)
		if got := props(def); !reflect.DeepEqual(got, fields) {
			t.Errorf("%s: schema properties %v, Go fields %v", def, got, fields)
		}
		if got := strs(d["required"]); !reflect.DeepEqual(got, required) {
			t.Errorf("%s: schema required %v, Go non-omitempty fields %v", def, got, required)
		}
	}
	open := map[string][]string{"Tool": {"inputSchema", "name"}, "Prompt": {"name"}, "Resource": {"name", "uri"}, "ResourceTemplate": {"name", "uriTemplate"}}
	for def, required := range open {
		d := defs[def].(map[string]any)
		if d["additionalProperties"] != true {
			t.Errorf("%s: additionalProperties must be true (Extra fields are pinned verbatim)", def)
		}
		if got := strs(d["required"]); !reflect.DeepEqual(got, required) {
			t.Errorf("%s: required %v, want %v", def, got, required)
		}
	}
	for _, def := range []string{"Release", "Envelope", "InvocationRecord", "Target", "Tool", "Prompt", "Resource", "ResourceTemplate", "Grant", "Auth", "APIKey", "JWT"} {
		d, ok := defs[def].(map[string]any)
		if !ok {
			t.Errorf("definition %s missing", def)
			continue
		}
		for _, key := range []string{"title", "description", "x-idp-telos-owner"} {
			if s, _ := d[key].(string); s == "" {
				t.Errorf("%s: %s missing", def, key)
			}
		}
	}
	if len(defs) != 12 {
		t.Errorf("schema has %d definitions; the registry lists 12", len(defs))
	}
}

func set(m map[string]any, path string, v any) {
	keys := strings.Split(path, ".")
	var cur any = m
	for i, key := range keys {
		last := i == len(keys)-1
		switch node := cur.(type) {
		case map[string]any:
			if last {
				node[key] = v
				return
			}
			cur = node[key]
		case []any:
			var idx int
			fmt.Sscanf(key, "%d", &idx)
			if last {
				node[idx] = v
				return
			}
			cur = node[idx]
		}
	}
}

// TestContractRejectsWhatValidateRejects: for documents the implementation refuses, the schema
// refuses too (where the rule is expressible), so a consumer validating against the contract is not
// told a release is fine that no gateway would run. The schema is necessarily weaker than Validate
// (digests, cross-references); the reverse direction is covered by the examples tests.
func TestContractRejectsWhatValidateRejects(t *testing.T) {
	k := loadContract(t)
	full, _ := exampleDocuments(t)
	env, err := Seal(full)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		path  string
		value any
	}{
		"wrong schemaVersion":      {"schemaVersion", "idp.mcp.release/v2"},
		"unknown driftAction":      {"driftAction", "ignore"},
		"unknown toolNaming":       {"toolNaming", "flat"},
		"empty releaseId":          {"releaseId", ""},
		"target name uppercase":    {"targets.0.name", "Parcel"},
		"target name underscore":   {"targets.0.name", "par_cel"},
		"endpoint not http":        {"targets.0.endpoint", "ftp://parcel/mcp"},
		"endpoint with query":      {"targets.0.endpoint", "https://parcel/mcp?x=1"},
		"endpoint with userinfo":   {"targets.0.endpoint", "https://u:p@parcel/mcp"},
		"unknown network":          {"targets.0.network", "vpn"},
		"malformed snapshotDigest": {"targets.0.snapshotDigest", "sha256:zz"},
		"target without tools":     {"targets.0.tools", []any{}},
		"tool without inputSchema": {"targets.0.tools.0", map[string]any{"name": "x"}},
		"tool name too long":       {"targets.0.tools.0.name", strings.Repeat("a", 129)},
		"unknown capability":       {"targets.0.capabilities", []any{"tools", "magic"}},
		"grant without roles":      {"grants.0.roles", []any{}},
		"grant with nothing":       {"grants.1", map[string]any{"target": "parcel", "tools": []any{}, "roles": []any{"viewer"}}},
		"grant bad role":           {"grants.0.roles", []any{"operator", "bad role"}},
		"api-key plus jwt":         {"auth.jwt", map[string]any{"issuer": "https://i", "resource": "https://r", "jwksUrl": "https://j", "authorizationServers": []any{"https://i"}, "tenantClaim": "t", "rolesClaim": "r"}},
		"api-key without keys":     {"auth.apiKeys", []any{}},
		"short sha256":             {"auth.apiKeys.0.sha256", "abc"},
		"unknown auth mode":        {"auth.mode", "none"},
		"unknown top-level field":  {"extra", true},
		"unknown target field":     {"targets.0.extra", true},
	}
	for name, c := range cases {
		var m map[string]any
		mustJSON(t, string(env.Document), &m)
		set(m, c.path, c.value)
		raw, _ := Canonical(m)
		if err := k.validate("Release", raw); err == nil {
			t.Errorf("%s: schema accepts it", name)
		}
		digest, _ := Digest(json.RawMessage(raw))
		if _, err := Open(&Envelope{Digest: digest, Document: raw}); err == nil {
			t.Errorf("%s: the implementation accepts it", name)
		}
	}

	rec := exampleRecords(t, env.Digest)[0]
	recCases := map[string]struct {
		path  string
		value any
	}{
		"unknown decision":     {"decision", "MAYBE"},
		"unknown outcome":      {"outcome", "FINE"},
		"negative latency":     {"latencyMs", -1},
		"fractional latency":   {"latencyMs", 1.5},
		"bad traceId":          {"traceId", "xyz"},
		"unknown authMethod":   {"authMethod", "basic"},
		"unlisted method":      {"method", "tools/list"},
		"empty subject":        {"subject", ""},
		"bad releaseDigest":    {"releaseDigest", "sha1:abc"},
		"bad argsDigest":       {"argsDigest", "abc"},
		"unknown record field": {"arguments", map[string]any{"recipient": "x"}},
	}
	for name, c := range recCases {
		b, _ := json.Marshal(rec)
		var m map[string]any
		mustJSON(t, string(b), &m)
		set(m, c.path, c.value)
		raw, _ := Canonical(m)
		if err := k.validate("InvocationRecord", raw); err == nil {
			t.Errorf("record %s: schema accepts it", name)
		}
	}
	// A record with an unknown field is also not something the registry would have received from
	// this gateway: Record has no such field.
	dec := json.NewDecoder(strings.NewReader(`{"at":"2026-11-03T10:15:00Z","arguments":{}}`))
	dec.DisallowUnknownFields()
	var r invocation.Record
	if err := dec.Decode(&r); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("expected unknown-field error, got %v", err)
	}
}
