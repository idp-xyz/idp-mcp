package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Tool is an MCP tool definition as listed to clients. Fields the gateway does not interpret
// (icons, execution, _meta, future additions) are kept verbatim in Extra, so the pinned definition
// is the complete definition the reviewer approved.
type Tool struct {
	Name         string
	Title        string
	Description  string
	InputSchema  map[string]any
	OutputSchema map[string]any
	Annotations  map[string]any
	Extra        map[string]any
}

var toolKnown = map[string]bool{"name": true, "title": true, "description": true, "inputSchema": true, "outputSchema": true, "annotations": true}

// MarshalJSON writes the known fields plus Extra.
func (t Tool) MarshalJSON() ([]byte, error) {
	m := make(map[string]any, len(t.Extra)+6)
	for k, v := range t.Extra {
		if !toolKnown[k] {
			m[k] = v
		}
	}
	m["name"] = t.Name
	m["inputSchema"] = t.InputSchema
	if t.Title != "" {
		m["title"] = t.Title
	}
	if t.Description != "" {
		m["description"] = t.Description
	}
	if t.OutputSchema != nil {
		m["outputSchema"] = t.OutputSchema
	}
	if t.Annotations != nil {
		m["annotations"] = t.Annotations
	}
	return json.Marshal(m)
}

// UnmarshalJSON reads a tool object; numbers are kept as written.
func (t *Tool) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil {
		return errors.New("tool must be a JSON object")
	}
	*t = Tool{}
	str := func(k string) (string, error) {
		v, ok := m[k]
		if !ok || v == nil {
			return "", nil
		}
		s, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("tool %s must be a string", k)
		}
		return s, nil
	}
	obj := func(k string) (map[string]any, error) {
		v, ok := m[k]
		if !ok || v == nil {
			return nil, nil
		}
		o, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("tool %s must be an object", k)
		}
		return o, nil
	}
	var err error
	if t.Name, err = str("name"); err != nil {
		return err
	}
	if t.Title, err = str("title"); err != nil {
		return err
	}
	if t.Description, err = str("description"); err != nil {
		return err
	}
	if t.InputSchema, err = obj("inputSchema"); err != nil {
		return err
	}
	if t.OutputSchema, err = obj("outputSchema"); err != nil {
		return err
	}
	if t.Annotations, err = obj("annotations"); err != nil {
		return err
	}
	for k, v := range m {
		if !toolKnown[k] {
			if t.Extra == nil {
				t.Extra = map[string]any{}
			}
			t.Extra[k] = v
		}
	}
	return nil
}

// ServerInfo names the gateway in discovery results.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// complete returns the 2026-07-28 result fields every gateway-built result carries: the result is
// complete, never cached across principals (the catalog is filtered per caller).
func complete(fields map[string]any, info ServerInfo) map[string]any {
	fields["resultType"] = "complete"
	fields["ttlMs"] = 0
	fields["cacheScope"] = "private"
	fields["_meta"] = map[string]any{MetaServerInfo: info}
	return fields
}

// DiscoverResult is a server/discover answer that offers tools only.
func DiscoverResult(info ServerInfo) map[string]any {
	return DiscoverResultWith(info, map[string]any{"tools": map[string]any{"listChanged": false}})
}

// DiscoverResultWith is the gateway's server/discover answer with the capabilities it federates.
func DiscoverResultWith(info ServerInfo, capabilities map[string]any) map[string]any {
	return complete(map[string]any{"supportedVersions": []string{ProtocolVersion}, "capabilities": capabilities}, info)
}

// Complete adds the gateway's result fields (resultType, ttlMs, cacheScope, serverInfo) to a result
// the gateway assembled itself.
func Complete(fields map[string]any, info ServerInfo) map[string]any { return complete(fields, info) }

// ToolsListResult lists the (already filtered) tools; the gateway never paginates.
func ToolsListResult(tools []Tool, info ServerInfo) map[string]any {
	if tools == nil {
		tools = []Tool{}
	}
	return complete(map[string]any{"tools": tools}, info)
}

// UnknownTool is the single answer for a tool that does not exist AND for one the caller may not
// use, so the catalog cannot be enumerated by probing (ADR-0001 D5).
func UnknownTool(name string) *Error {
	return &Error{Code: CodeInvalidParams, Message: "Unknown tool: " + name}
}

// MethodNotFound answers methods the gateway does not federate.
func MethodNotFound(method string) *Error {
	return &Error{Code: CodeMethodNotFound, Message: "Method not found: " + method}
}

// Prompt is an MCP prompt definition (prompts/list entry). As with Tool, fields the gateway does not
// interpret (icons, _meta, ...) are kept in Extra and pinned with the rest.
type Prompt struct {
	Name        string
	Title       string
	Description string
	Arguments   []any
	Extra       map[string]any
}

var promptKnown = map[string]bool{"name": true, "title": true, "description": true, "arguments": true}

// MarshalJSON writes the known fields plus Extra.
func (p Prompt) MarshalJSON() ([]byte, error) {
	m := make(map[string]any, len(p.Extra)+4)
	for k, v := range p.Extra {
		if !promptKnown[k] {
			m[k] = v
		}
	}
	m["name"] = p.Name
	if p.Title != "" {
		m["title"] = p.Title
	}
	if p.Description != "" {
		m["description"] = p.Description
	}
	if p.Arguments != nil {
		m["arguments"] = p.Arguments
	}
	return json.Marshal(m)
}

// UnmarshalJSON reads a prompt object; numbers are kept as written.
func (p *Prompt) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil {
		return errors.New("prompt must be a JSON object")
	}
	*p = Prompt{}
	for _, f := range []struct {
		key string
		dst *string
	}{{"name", &p.Name}, {"title", &p.Title}, {"description", &p.Description}} {
		if v, ok := m[f.key]; ok && v != nil {
			s, ok := v.(string)
			if !ok {
				return fmt.Errorf("prompt %s must be a string", f.key)
			}
			*f.dst = s
		}
	}
	if v, ok := m["arguments"]; ok && v != nil {
		args, ok := v.([]any)
		if !ok {
			return errors.New("prompt arguments must be an array")
		}
		for _, a := range args {
			obj, ok := a.(map[string]any)
			if !ok {
				return errors.New("prompt argument must be an object")
			}
			if n, _ := obj["name"].(string); n == "" {
				return errors.New("prompt argument needs a name")
			}
		}
		p.Arguments = args
	}
	for k, v := range m {
		if !promptKnown[k] {
			if p.Extra == nil {
				p.Extra = map[string]any{}
			}
			p.Extra[k] = v
		}
	}
	return nil
}

// PromptsListResult lists the (already filtered) prompts.
func PromptsListResult(prompts []Prompt, info ServerInfo) map[string]any {
	if prompts == nil {
		prompts = []Prompt{}
	}
	return complete(map[string]any{"prompts": prompts}, info)
}

// decodeKnown reads a JSON object into the named string fields; every other field is returned as
// Extra. Numbers are kept as written.
func decodeKnown(b []byte, what string, strs map[string]*string) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil {
		return nil, errors.New(what + " must be a JSON object")
	}
	var extra map[string]any
	for k, v := range m {
		if ptr, known := strs[k]; known {
			if v == nil {
				continue
			}
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("%s %s must be a string", what, k)
			}
			*ptr = s
			continue
		}
		if extra == nil {
			extra = map[string]any{}
		}
		extra[k] = v
	}
	return extra, nil
}

func encodeKnown(strs map[string]string, required []string, extra map[string]any) ([]byte, error) {
	m := make(map[string]any, len(extra)+len(strs))
	for k, v := range extra {
		if _, known := strs[k]; !known {
			m[k] = v
		}
	}
	req := map[string]bool{}
	for _, k := range required {
		req[k] = true
	}
	for k, v := range strs {
		if v != "" || req[k] {
			m[k] = v
		}
	}
	return json.Marshal(m)
}

// Resource is a resources/list entry, pinned like a tool (M5): uri, name, title, description and
// mimeType are interpreted; everything else (size, annotations, icons, _meta) rides in Extra.
type Resource struct {
	URI, Name, Title, Description, MIMEType string
	Extra                                   map[string]any
}

// MarshalJSON writes the known fields plus Extra.
func (r Resource) MarshalJSON() ([]byte, error) {
	return encodeKnown(map[string]string{"uri": r.URI, "name": r.Name, "title": r.Title, "description": r.Description, "mimeType": r.MIMEType},
		[]string{"uri", "name"}, r.Extra)
}

// UnmarshalJSON reads a resource object.
func (r *Resource) UnmarshalJSON(b []byte) error {
	*r = Resource{}
	extra, err := decodeKnown(b, "resource", map[string]*string{"uri": &r.URI, "name": &r.Name, "title": &r.Title, "description": &r.Description, "mimeType": &r.MIMEType})
	r.Extra = extra
	return err
}

// ResourceTemplate is a resources/templates/list entry, pinned like a resource.
type ResourceTemplate struct {
	URITemplate, Name, Title, Description, MIMEType string
	Extra                                           map[string]any
}

// MarshalJSON writes the known fields plus Extra.
func (r ResourceTemplate) MarshalJSON() ([]byte, error) {
	return encodeKnown(map[string]string{"uriTemplate": r.URITemplate, "name": r.Name, "title": r.Title, "description": r.Description, "mimeType": r.MIMEType},
		[]string{"uriTemplate", "name"}, r.Extra)
}

// UnmarshalJSON reads a resource template object.
func (r *ResourceTemplate) UnmarshalJSON(b []byte) error {
	*r = ResourceTemplate{}
	extra, err := decodeKnown(b, "resource template", map[string]*string{"uriTemplate": &r.URITemplate, "name": &r.Name, "title": &r.Title, "description": &r.Description, "mimeType": &r.MIMEType})
	r.Extra = extra
	return err
}
