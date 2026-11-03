package policy

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

var dns = map[string][]string{
	"mcp.example.com":  {"93.184.216.34"},
	"mcp-internal":     {"10.20.0.5"},
	"mcp-ula":          {"fd12:3456::7"},
	"meta.corp":        {"169.254.169.254"},
	"meta6.corp":       {"fd00:ec2::254"},
	"mapped-meta.corp": {"::ffff:169.254.169.254"},
	"loop.corp":        {"127.0.0.1"},
	"cgnat.corp":       {"100.64.0.9"},
	"multicast.corp":   {"224.0.0.251"},
	"zero.corp":        {"0.0.0.0"},
	"ll6.corp":         {"fe80::1"},
	"mixed.corp":       {"10.20.0.5", "169.254.169.254"},
	"testnet.corp":     {"192.0.2.1"},
	"localhost":        {"127.0.0.1"},
	"reserved.corp":    {"240.0.0.1"},
}

func resolver(_ context.Context, host string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, s := range dns[host] {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, nil
}

func pol(dev bool, allowed []string, private ...string) *Upstream {
	p := &Upstream{AllowedHosts: map[string]bool{}, PrivateHosts: map[string]bool{}, DevMode: dev, Resolver: resolver}
	for _, h := range allowed {
		p.AllowedHosts[h] = true
	}
	for _, h := range private {
		p.PrivateHosts[h] = true
	}
	return p
}

func TestPermittedEndpoints(t *testing.T) {
	ok := []struct {
		p   *Upstream
		url string
	}{
		{pol(false, []string{"mcp.example.com"}), "https://mcp.example.com/mcp"},
		{pol(false, []string{"mcp.example.com"}), "https://mcp.example.com/v1/mcp"},
		{pol(false, []string{"mcp-internal"}, "mcp-internal"), "https://mcp-internal/mcp"},
		{pol(false, []string{"mcp-ula"}, "mcp-ula"), "https://mcp-ula:8443/mcp"},
		{pol(true, []string{"localhost"}), "http://localhost:3111/mcp"},
		{pol(true, []string{"mcp-internal"}, "mcp-internal"), "http://mcp-internal:3111/mcp"},
	}
	for _, c := range ok {
		if _, err := c.p.CheckEndpoint(context.Background(), c.url); err != nil {
			t.Errorf("%s refused: %v", c.url, err)
		}
	}
}

func TestRefusedEndpoints(t *testing.T) {
	bad := []struct {
		p      *Upstream
		url    string
		reason string
	}{
		{pol(false, nil), "https://mcp.example.com/mcp", "allowlist"},
		{pol(false, []string{"mcp.example.com"}), "http://mcp.example.com/mcp", "https is required"},
		{pol(false, []string{"mcp.example.com"}), "https://mcp.example.com/api", "/mcp"},
		{pol(false, []string{"mcp.example.com"}), "https://mcp.example.com/mcp?x=1", "/mcp"},
		{pol(false, []string{"mcp.example.com"}), "https://u:p@mcp.example.com/mcp", "malformed"},
		{pol(false, []string{"mcp-internal"}), "https://mcp-internal/mcp", "restricted"}, // private, not listed
		{pol(false, []string{"localhost"}, "localhost"), "https://localhost/mcp", "development-only"},
		{pol(true, []string{"loop.corp"}, "loop.corp"), "http://loop.corp/mcp", "restricted"}, // private list never unlocks loopback
		{pol(false, []string{"meta.corp"}, "meta.corp"), "https://meta.corp/mcp", "restricted"},
		{pol(false, []string{"meta6.corp"}, "meta6.corp"), "https://meta6.corp/mcp", "restricted"},
		{pol(false, []string{"mapped-meta.corp"}, "mapped-meta.corp"), "https://mapped-meta.corp/mcp", "restricted"},
		{pol(false, []string{"cgnat.corp"}, "cgnat.corp"), "https://cgnat.corp/mcp", "restricted"},
		{pol(false, []string{"multicast.corp"}, "multicast.corp"), "https://multicast.corp/mcp", "restricted"},
		{pol(false, []string{"zero.corp"}, "zero.corp"), "https://zero.corp/mcp", "restricted"},
		{pol(false, []string{"ll6.corp"}, "ll6.corp"), "https://ll6.corp/mcp", "restricted"},
		{pol(false, []string{"mixed.corp"}, "mixed.corp"), "https://mixed.corp/mcp", "restricted"},
		{pol(false, []string{"testnet.corp"}), "https://testnet.corp/mcp", "restricted"},
		{pol(false, []string{"reserved.corp"}), "https://reserved.corp/mcp", "restricted"},
		{pol(false, []string{"nowhere"}), "https://nowhere/mcp", "does not resolve"},
	}
	for _, c := range bad {
		_, err := c.p.CheckEndpoint(context.Background(), c.url)
		if err == nil || !errors.Is(err, ErrBlocked) || !strings.Contains(err.Error(), c.reason) {
			t.Errorf("%s: got %v, want %q", c.url, err, c.reason)
		}
	}
}

func TestDialControlRechecksTheConnectedAddress(t *testing.T) {
	p := pol(false, []string{"mcp-internal"}, "mcp-internal")
	ctl := p.DialControl("mcp-internal")
	if err := ctl("tcp", "10.20.0.5:443", nil); err != nil {
		t.Fatalf("listed private address refused: %v", err)
	}
	// DNS rebinding after registration: the same name now points at metadata or loopback
	for _, addr := range []string{"169.254.169.254:80", "127.0.0.1:443", "[::ffff:169.254.169.254]:80"} {
		if err := ctl("tcp", addr, nil); !errors.Is(err, ErrBlocked) {
			t.Errorf("dial %s allowed", addr)
		}
	}
	if err := pol(false, []string{"x"}).DialControl("x")("tcp", "10.0.0.1:443", nil); !errors.Is(err, ErrBlocked) {
		t.Error("unlisted host dialed a private address")
	}
}
