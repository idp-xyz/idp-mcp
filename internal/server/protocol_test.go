package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
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
			// the cases are about something other than the Mcp-Method header unless they say so: they send the
			// body's own method in it (the header is required; TestAdmitRequiresTheMethodHeader covers its absence)
			mthd := c.mthd
			if mthd == "" {
				var b struct{ Method string }
				_ = json.Unmarshal(c.body, &b)
				mthd = b.Method
			}
			_, rej := Admit(c.body, c.version, mthd)
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
	_, rej := Admit(big, ProtocolVersion, "tools/list")
	if rej == nil || rej.HTTPStatus != 413 {
		t.Fatalf("got %+v", rej)
	}
}

func TestRejectionEchoesValidIDAndNullsInvalid(t *testing.T) {
	_, rej := Admit([]byte(`{"jsonrpc":"2.0","id":"abc","method":"tools/list","params":{`+meta+`}}`), "x", "tools/list")
	if string(rej.ID) != `"abc"` {
		t.Fatalf("id %s", rej.ID)
	}
	_, rej = Admit([]byte(`{"jsonrpc":"2.0","id":{"x":1},"method":"ping"}`), ProtocolVersion, "ping")
	if string(rej.ID) != "null" {
		t.Fatalf("id %s", rej.ID)
	}
}

func TestNotificationsAndUnknownMethodsSkipEnvelopeChecks(t *testing.T) {
	if _, rej := Admit([]byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}`), ProtocolVersion, "notifications/cancelled"); rej != nil {
		t.Fatalf("notification rejected: %+v", rej.Err)
	}
	req, rej := Admit([]byte(`{"jsonrpc":"2.0","id":3,"method":"vendor/thing"}`), ProtocolVersion, "vendor/thing")
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

func TestAdmitRequiresTheMethodHeaderOnEveryRequest(t *testing.T) {
	// 2026-07-28 transport: Mcp-Method is required; a request without it is refused with 400 / -32020,
	// notifications and methods the gateway does not know included
	for _, b := range [][]byte{body("tools/list", ""), []byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}`),
		[]byte(`{"jsonrpc":"2.0","id":3,"method":"vendor/thing"}`)} {
		_, rej := Admit(b, ProtocolVersion, "")
		if rej == nil || rej.HTTPStatus != 400 || rej.Err.Code != CodeVersionMismatch || !strings.Contains(rej.Err.Message, "required") {
			t.Fatalf("%s admitted without Mcp-Method: %+v", b, rej)
		}
	}
}

func TestNameHeaderMayBeInItsBase64Form(t *testing.T) {
	const name = "caf\u00e9 \u540d\u524d"
	req, rej := Admit(body("tools/call", `{"name":"`+name+`",`+meta+`}`), ProtocolVersion, "tools/call")
	if rej != nil {
		t.Fatal(rej.Err)
	}
	b64 := func(s string) string { return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(s)) + "?=" }
	if r := req.CheckNameHeader(b64(name)); r != nil {
		t.Fatalf("the Base64 form of the name was refused: %+v", r.Err)
	}
	for _, h := range []string{b64("other"), "=?base64?!!!?=", "=?base64?/w==?="} { // wrong name, not Base64, not UTF-8
		if r := req.CheckNameHeader(h); r == nil || r.Err.Code != CodeVersionMismatch {
			t.Fatalf("header %q accepted", h)
		}
	}
}

func TestHeaderValuesAreEncodedOnlyWhenTheyCannotBePlain(t *testing.T) {
	for v, plain := range map[string]bool{"a__echo": true, "file:///a b/c": true, "caf\u00e9": false, " lead": false, "trail ": false, "a\tb": false,
		"a\nb": false, "=?base64?QQ==?=": false} {
		got := EncodeHeaderValue(v)
		if (got == v) != plain {
			t.Errorf("%q encoded as %q", v, got)
		}
		if back, ok := DecodeHeaderValue(got); !ok || back != v {
			t.Errorf("%q does not round-trip: %q %v", v, back, ok)
		}
	}
}

func TestParamHeadersAreCollectedAndBounded(t *testing.T) {
	h := http.Header{}
	h.Set("Mcp-Param-Region", "us-west1")
	h.Set("mcp-param-note", "=?base64?w6k=?=")
	h.Set("Authorization", "Bearer x")
	h.Set("Cookie", "s=1")
	h.Set("Mcp-Name", "tool")
	got, rej := ParamHeaders(h, nil)
	if rej != nil || len(got) != 2 || got.Get("Mcp-Param-Region") != "us-west1" || got.Get("Mcp-Param-Note") != "=?base64?w6k=?=" {
		t.Fatalf("%v %+v", got, rej)
	}
	many := http.Header{}
	for i := 0; i <= MaxParamHeaders; i++ {
		many.Set("Mcp-Param-P"+strings.Repeat("x", i), "v")
	}
	big := http.Header{"Mcp-Param-Big": {strings.Repeat("a", MaxParamHeaderValue+1)}}
	longName := http.Header{"Mcp-Param-" + strings.Repeat("n", MaxParamHeaderName+1): {"v"}}
	for name, bad := range map[string]http.Header{"too many": many, "too large": big, "name too long": longName, "empty name": {"Mcp-Param-": {"v"}}} {
		if _, rej := ParamHeaders(bad, nil); rej == nil || rej.HTTPStatus != 400 || rej.Err.Code != CodeVersionMismatch {
			t.Errorf("%s: %+v", name, rej)
		}
	}
}
