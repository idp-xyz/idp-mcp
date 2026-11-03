package policy

import (
	"encoding/json"
	"strings"
	"testing"

	"idp-mcp/internal/server"
)

func schemaOf(t *testing.T, s string) map[string]any {
	var tool server.Tool
	if err := json.Unmarshal([]byte(`{"name":"x","inputSchema":`+s+`}`), &tool); err != nil {
		t.Fatal(err)
	}
	return tool.InputSchema
}

func compile(t *testing.T, s string) (*ArgumentSchemas, error) {
	return CompileToolSchemas([]server.Tool{{Name: "x", InputSchema: schemaOf(t, s)}}, func(n string) string { return n })
}

func TestArgumentsAreValidatedAgainstThePinnedSchema(t *testing.T) {
	a, err := compile(t, `{"type":"object","properties":{"text":{"type":"string","maxLength":5}},"required":["text"],"additionalProperties":false}`)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Validate("x", json.RawMessage(`{"text":"hi"}`)); err != nil {
		t.Fatal(err)
	}
	for args, want := range map[string]string{
		`{"text":"far too long"}`:            "/text: maxLength",
		`{}`:                                 "required",
		`{"text":"hi","path":"/etc/passwd"}`: "additionalProperties",
		`{"text":7}`:                         "/text: type",
		``:                                   "required", // absent arguments are {}
		`[1]`:                                "type",
	} {
		err := a.Validate("x", json.RawMessage(args))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v (want %q)", args, err, want)
		}
		if err != nil && (strings.Contains(err.Error(), "passwd") || strings.Contains(err.Error(), "far too long")) {
			t.Errorf("error echoes argument values: %v", err)
		}
	}
	if err := a.Validate("unknown", nil); err != ErrNoSchema {
		t.Fatal("unknown tool must fail closed")
	}
}

func TestDialectsAndInternalRefs(t *testing.T) {
	// the Everything server's 2020-12 keyword tool: $defs/$ref, if/then/else, anyOf
	a, err := compile(t, `{"$schema":"https://json-schema.org/draft/2020-12/schema","$defs":{"addr":{"type":"object","properties":{"city":{"type":"string"}}}},
		"type":"object","properties":{"address":{"$ref":"#/$defs/addr"},"contactMethod":{"enum":["phone","email"]},"phone":{"type":"string"},"email":{"type":"string"}},
		"if":{"properties":{"contactMethod":{"const":"phone"}},"required":["contactMethod"]},"then":{"required":["phone"]},"else":{"required":["email"]},
		"additionalProperties":false}`)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Validate("x", json.RawMessage(`{"contactMethod":"phone","phone":"1","address":{"city":"B"}}`)); err != nil {
		t.Fatal(err)
	}
	if err := a.Validate("x", json.RawMessage(`{"contactMethod":"phone","email":"a@b"}`)); err == nil {
		t.Fatal("if/then not applied")
	}
	if err := a.Validate("x", json.RawMessage(`{"email":"a@b","address":{"city":1}}`)); err == nil {
		t.Fatal("$ref not applied")
	}
	// draft-07 is honoured when declared
	if _, err := compile(t, `{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"a":{"type":"number"}}}`); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteRefsAreNeverLoaded(t *testing.T) {
	for _, s := range []string{
		`{"type":"object","properties":{"a":{"$ref":"https://evil.example/schema.json"}}}`,
		`{"type":"object","properties":{"a":{"$ref":"file:///etc/passwd"}}}`,
	} {
		if _, err := compile(t, s); err == nil || !strings.Contains(err.Error(), "does not compile") {
			t.Errorf("%s: %v", s, err)
		}
	}
	if _, err := compile(t, `{"type":"nonsense"}`); err == nil {
		t.Error("invalid schema compiled")
	}
}
