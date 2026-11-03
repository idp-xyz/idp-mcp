package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"idp-mcp/internal/policy"
	"idp-mcp/internal/server"
)

func devPolicy() *policy.Upstream {
	return &policy.Upstream{AllowedHosts: map[string]bool{"127.0.0.1": true}, PrivateHosts: map[string]bool{}, DevMode: true}
}

func upstream(t *testing.T, h func(method string, params map[string]any) (int, string, string)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		_ = json.Unmarshal(b, &req)
		if r.Header.Get(server.HeaderProtocolVersion) != server.ProtocolVersion || r.Header.Get(server.HeaderMethod) != req.Method {
			w.WriteHeader(400)
			return
		}
		if meta, _ := req.Params["_meta"].(map[string]any); meta[server.MetaProtocolVersion] != server.ProtocolVersion {
			w.WriteHeader(400)
			return
		}
		status, ct, body := h(req.Method, req.Params)
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newClient() *Client {
	return &Client{HTTP: NewHTTPClient(devPolicy(), 5*time.Second), Info: server.ServerInfo{Name: "test", Version: "0"}}
}

func TestDiscoverAndPagedToolsList(t *testing.T) {
	srv := upstream(t, func(method string, params map[string]any) (int, string, string) {
		switch method {
		case "server/discover":
			return 200, "application/json", `{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":["2026-07-28"],"capabilities":{"tools":{}},"resultType":"complete","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"up","version":"1"}}}}`
		case "tools/list":
			if params["cursor"] == "p2" {
				return 200, "text/event-stream", "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"b\",\"inputSchema\":{}}]}}\n\n"
			}
			return 200, "application/json", `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a","inputSchema":{}}],"nextCursor":"p2"}}`
		}
		return 404, "application/json", `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`
	})
	c := newClient()
	d, err := c.Discover(context.Background(), srv.URL+"/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if d.ServerInfo()["name"] != "up" {
		t.Fatalf("%+v", d.ServerInfo())
	}
	tools, err := c.ListTools(context.Background(), srv.URL+"/mcp")
	if err != nil || len(tools) != 2 {
		t.Fatalf("%d %v", len(tools), err)
	}
	_, err = c.Call(context.Background(), srv.URL+"/mcp", "ping", nil)
	var rpc *RPCError
	if !errors.As(err, &rpc) || rpc.RPC.Code != server.CodeMethodNotFound {
		t.Fatalf("got %v", err)
	}
}

func TestDiscoverRefusesNonModernServers(t *testing.T) {
	for _, result := range []string{
		`{"supportedVersions":["2025-06-18","2026-07-28"],"capabilities":{"tools":{}},"resultType":"complete"}`,
		`{"supportedVersions":["2026-07-28"],"capabilities":{"tools":{}}}`,
		`{"supportedVersions":["2026-07-28"],"capabilities":{"prompts":{}},"resultType":"complete"}`,
	} {
		srv := upstream(t, func(string, map[string]any) (int, string, string) {
			return 200, "application/json", `{"jsonrpc":"2.0","id":1,"result":` + result + `}`
		})
		if _, err := newClient().Discover(context.Background(), srv.URL+"/mcp"); err == nil {
			t.Errorf("accepted %s", result)
		}
	}
}

func TestDialTimePolicyAndNoRedirects(t *testing.T) {
	srv := upstream(t, func(string, map[string]any) (int, string, string) { return 200, "application/json", "{}" })
	strict := &Client{HTTP: NewHTTPClient(&policy.Upstream{DevMode: false}, time.Second)}
	_, err := strict.Call(context.Background(), srv.URL+"/mcp", "ping", nil)
	if err == nil || !errors.Is(err, policy.ErrBlocked) {
		t.Fatalf("loopback dial outside dev mode: %v", err)
	}
	redirect := httptest.NewServer(http.RedirectHandler(srv.URL+"/mcp", http.StatusTemporaryRedirect))
	defer redirect.Close()
	if _, err := newClient().Call(context.Background(), redirect.URL+"/mcp", "ping", nil); err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("redirect followed or misreported: %v", err)
	}
}

func TestEnvironmentProxyIsIgnored(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	srv := upstream(t, func(string, map[string]any) (int, string, string) {
		return 200, "application/json", `{"jsonrpc":"2.0","id":1,"result":{}}`
	})
	if _, err := newClient().Call(context.Background(), srv.URL+"/mcp", "ping", nil); err != nil {
		t.Fatalf("proxy used: %v", err)
	}
}

func TestRedact(t *testing.T) {
	if got := Redact("https://u:p@h:1/x/mcp?k=v#f"); got != "https://h:1/x/mcp" {
		t.Fatal(got)
	}
}
