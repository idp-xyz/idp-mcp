package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"idp-mcp/internal/server"
)

// Argument validation (M3): every tools/call's arguments must satisfy the pinned inputSchema of the
// tool before the call leaves the gateway. Parameters the reviewer never saw - an extra "path" or
// "recipient" - are refused when the schema says so, and malformed values never reach the upstream.
// Schemas are compiled once per release. Only references inside the schema itself resolve: no
// remote or file $ref is ever loaded (a schema must not make the gateway fetch URLs). Dialect is the
// schema's $schema, JSON Schema 2020-12 by default; "format" is an annotation, as 2020-12 specifies.

type noLoader struct{}

func (noLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("external schema reference %q is not loaded", url)
}

// ArgumentSchemas validates tool arguments against pinned input schemas.
type ArgumentSchemas struct {
	byTool map[string]*jsonschema.Schema
}

func toDoc(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return jsonschema.UnmarshalJSON(bytes.NewReader(b))
}

// CompileToolSchemas compiles the input schemas of a target's tools. key(tool) names the entry.
func CompileToolSchemas(tools []server.Tool, key func(string) string) (*ArgumentSchemas, error) {
	out := &ArgumentSchemas{byTool: map[string]*jsonschema.Schema{}}
	if err := out.Add(tools, key); err != nil {
		return nil, err
	}
	return out, nil
}

// Add compiles more tools into the set.
func (a *ArgumentSchemas) Add(tools []server.Tool, key func(string) string) error {
	if a.byTool == nil {
		a.byTool = map[string]*jsonschema.Schema{}
	}
	for _, t := range tools {
		c := jsonschema.NewCompiler()
		c.DefaultDraft(jsonschema.Draft2020)
		c.UseLoader(noLoader{})
		doc, err := toDoc(t.InputSchema)
		if err != nil {
			return fmt.Errorf("tool %s: inputSchema: %w", t.Name, err)
		}
		loc := "urn:idp-mcp:tool:" + t.Name
		if err := c.AddResource(loc, doc); err != nil {
			return fmt.Errorf("tool %s: inputSchema: %w", t.Name, err)
		}
		sch, err := c.Compile(loc)
		if err != nil {
			return fmt.Errorf("tool %s: inputSchema does not compile: %s", t.Name, firstLine(err.Error()))
		}
		a.byTool[key(t.Name)] = sch
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// ErrNoSchema means the tool has no compiled schema (fail closed).
var ErrNoSchema = errors.New("no input schema")

// Validate checks raw arguments (absent arguments are the empty object). The returned error lists
// the failing locations and keywords, never the offending values, so it can be shown to the caller
// and logged without leaking argument content.
func (a *ArgumentSchemas) Validate(tool string, raw json.RawMessage) error {
	sch := a.byTool[tool]
	if sch == nil {
		return ErrNoSchema
	}
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		raw = json.RawMessage("{}")
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return errors.New("arguments are not valid JSON")
	}
	if err := sch.Validate(inst); err != nil {
		var ve *jsonschema.ValidationError
		if errors.As(err, &ve) {
			return errors.New(summarize(ve))
		}
		return errors.New("arguments do not match the input schema")
	}
	return nil
}

// summarize reports up to five leaf failures as "<instance location>: <keyword>".
func summarize(ve *jsonschema.ValidationError) string {
	var leaves []string
	var walk func(e *jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(e.Causes) == 0 {
			loc := "/" + strings.Join(e.InstanceLocation, "/")
			kw := "schema"
			if e.ErrorKind != nil {
				if p := e.ErrorKind.KeywordPath(); len(p) > 0 {
					kw = strings.Join(p, "/")
				}
			}
			leaves = append(leaves, loc+": "+kw)
			return
		}
		for _, c := range e.Causes {
			walk(c)
		}
	}
	walk(ve)
	sort.Strings(leaves)
	if len(leaves) > 5 {
		leaves = append(leaves[:5], fmt.Sprintf("... %d more", len(leaves)-5))
	}
	return "arguments do not match the input schema: " + strings.Join(leaves, "; ")
}
