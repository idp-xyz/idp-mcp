package server

import (
	"encoding/json"
	"strings"
	"testing"
)

const meta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}`

func body(method, params string) []byte {
	if params == "" {
		params = "{" + meta + "}"
	}
	return []byte(`{"jsonrpc":"2.0","id":7,"method":"` + method + `","params":` + params + `}`)
}

func TestAdmitAcceptsAValidModernRequest(t *testing.T) {
	req, rej := Admit(body("tools/list", ""), ProtocolVersion, "tools/list")
	if rej != nil {
		t.Fatalf("rejected: %+v", rej.Err)
	}
	if req.Method != "tools/list" || string(req.ID) != "7" {
		t.Fatalf("unexpected request %+v", req)
	}
}

func TestAdmitRejections(t *testing.T) {
	cases := []struct {
		name          string
		body          []byte
		version, mthd string
		status, code  int
		msg           string
	}{
		{"parse error", []byte(`{nope`), ProtocolVersion, "", 400, CodeParseError, "Parse error"},
		{"batch", []byte(`[` + string(body("ping", "")) + `]`), ProtocolVersion, "", 400, CodeInvalidRequest, "batches"},
		{"not jsonrpc 2.0", []byte(`{"jsonrpc":"1.0","id":1,"method":"ping"}`), ProtocolVersion, "", 400, CodeInvalidRequest, "Invalid JSON-RPC"},
		{"bool id", []byte(`{"jsonrpc":"2.0","id":true,"method":"ping","params":{` + meta + `}}`), ProtocolVersion, "", 400, CodeInvalidRequest, "id must be"},
		{"float id", []byte(`{"jsonrpc":"2.0","id":1.5,"method":"ping","params":{` + meta + `}}`), ProtocolVersion, "", 400, CodeInvalidRequest, "id must be"},
		{"missing version header", body("ping", ""), "", "", 400, CodeUnsupportedVersion, "Unsupported"},
		{"old version header", body("ping", ""), "2025-06-18", "", 400, CodeUnsupportedVersion, "Unsupported"},
		{"legacy initialize", body("initialize", ""), ProtocolVersion, "", 404, CodeMethodNotFound, "initialize"},
		{"method header mismatch", body("tools/list", ""), ProtocolVersion, "tools/call", 400, CodeVersionMismatch, "Mcp-Method"},
		{"params not object", body("tools/list", `[]`), ProtocolVersion, "", 400, CodeInvalidParams, "params must be an object"},
		{"no params", []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`), ProtocolVersion, "", 400, CodeInvalidParams, "params must be an object"},
		{"no _meta", body("tools/list", `{}`), ProtocolVersion, "", 400, CodeInvalidParams, "_meta must be an object"},
		{"no meta version", body("tools/list", `{"_meta":{"io.modelcontextprotocol/clientCapabilities":{}}}`), ProtocolVersion, "", 400, CodeInvalidParams, "protocolVersion"},
		{"meta version differs", body("tools/list", `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-06-18","io.modelcontextprotocol/clientCapabilities":{}}}`), ProtocolVersion, "", 400, CodeVersionMismatch, "mismatch"},
		{"no capabilities", body("tools/list", `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`), ProtocolVersion, "", 400, CodeInvalidParams, "clientCapabilities"},
		{"capabilities not object", body("tools/list", `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":[]}}`), ProtocolVersion, "", 400, CodeInvalidParams, "must be an object"},
		{"tools/call without name", body("tools/call", "{"+meta+"}"), ProtocolVersion, "", 400, CodeInvalidParams, "params.name"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, rej := Admit(c.body, c.version, c.mthd)
			if rej == nil {
				t.Fatal("admitted")
			}
			if rej.HTTPStatus != c.status || rej.Err.Code != c.code || !strings.Contains(rej.Err.Message, c.msg) {
				t.Fatalf("got %d %d %q", rej.HTTPStatus, rej.Err.Code, rej.Err.Message)
			}
		})
	}
}

func TestAdmitTooLarge(t *testing.T) {
	big := make([]byte, MaxRequestBody+1)
	_, rej := Admit(big, ProtocolVersion, "")
	if rej == nil || rej.HTTPStatus != 413 {
		t.Fatalf("got %+v", rej)
	}
}

func TestRejectionEchoesValidIDAndNullsInvalid(t *testing.T) {
	_, rej := Admit([]byte(`{"jsonrpc":"2.0","id":"abc","method":"tools/list","params":{`+meta+`}}`), "x", "")
	if string(rej.ID) != `"abc"` {
		t.Fatalf("id %s", rej.ID)
	}
	_, rej = Admit([]byte(`{"jsonrpc":"2.0","id":{"x":1},"method":"ping"}`), ProtocolVersion, "")
	if string(rej.ID) != "null" {
		t.Fatalf("id %s", rej.ID)
	}
}

func TestNotificationsAndUnknownMethodsSkipEnvelopeChecks(t *testing.T) {
	if _, rej := Admit([]byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}`), ProtocolVersion, ""); rej != nil {
		t.Fatalf("notification rejected: %+v", rej.Err)
	}
	req, rej := Admit([]byte(`{"jsonrpc":"2.0","id":3,"method":"vendor/thing"}`), ProtocolVersion, "")
	if rej != nil || req.Method != "vendor/thing" {
		t.Fatalf("unknown method should reach dispatch: %+v", rej)
	}
}

func TestNameHeaderMustRepeatTheToolName(t *testing.T) {
	req, rej := Admit(body("tools/call", `{"name":"a__echo",`+meta+`}`), ProtocolVersion, "tools/call")
	if rej != nil {
		t.Fatal(rej.Err)
	}
	if req.CheckNameHeader("a__echo") != nil {
		t.Fatal("matching header refused")
	}
	for _, h := range []string{"", "a__sum"} {
		if r := req.CheckNameHeader(h); r == nil || r.Err.Code != CodeVersionMismatch {
			t.Fatalf("header %q accepted", h)
		}
	}
}

func TestResultsCarryModernFields(t *testing.T) {
	b, _ := json.Marshal(DiscoverResult(ServerInfo{Name: "g", Version: "1"}))
	for _, want := range []string{`"supportedVersions":["2026-07-28"]`, `"resultType":"complete"`, `"cacheScope":"private"`, `"tools":{"listChanged":false}`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("%s missing %s", b, want)
		}
	}
	b, _ = json.Marshal(ToolsListResult(nil, ServerInfo{}))
	if !strings.Contains(string(b), `"tools":[]`) {
		t.Fatalf("nil tools must list as []: %s", b)
	}
}
