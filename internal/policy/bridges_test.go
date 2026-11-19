package policy

import "testing"

func TestBridgeAddressesMatchByHostOrByURLPrefix(t *testing.T) {
	e, err := ParseEndpoints(" bridge.idp.svc , Bridge2:8443, https://gw.example/connections/ ")
	if err != nil {
		t.Fatal(err)
	}
	for endpoint, want := range map[string]bool{
		"http://bridge.idp.svc/c/x/mcp":           true,
		"https://BRIDGE.idp.svc:9000/mcp":         true, // a host without a port is every port
		"https://bridge2:8443/mcp":                true,
		"https://bridge2:9443/mcp":                false, // a host with a port is that port
		"https://gw.example/connections/a/mcp":    true,
		"https://gw.example/connections/mcp":      true,
		"https://gw.example/connectionsx/mcp":     false, // a prefix ends on a path boundary
		"https://gw.example/other/mcp":            false,
		"http://gw.example/connections/a/mcp":     false, // the scheme is part of the prefix
		"https://notbridge.idp.svc/mcp":           false,
		"https://sandbox.idp.svc/mcp":             false,
		"https://bridge.idp.svc.evil.example/mcp": false,
		"://bad": false,
	} {
		if got := e.Matches(endpoint); got != want {
			t.Errorf("%s: %v, want %v", endpoint, got, want)
		}
	}
	if (Endpoints{}).Matches("http://bridge.idp.svc/mcp") || !(Endpoints{}).Empty() {
		t.Error("the zero value names nothing")
	}
	if none, err := ParseEndpoints(""); err != nil || !none.Empty() {
		t.Error("empty by default")
	}
	for _, bad := range []string{"ftp://x/y", "host/path", "https://user@host/x", "https://host/x?q=1", "a b"} {
		if _, err := ParseEndpoints(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
