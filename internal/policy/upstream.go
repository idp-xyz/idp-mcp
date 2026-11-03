// Package policy holds the infrastructure's network and access policies that are not per-request
// authorization: which upstream endpoints may be registered and which addresses may be dialed.
package policy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
)

// Upstream is the endpoint policy for registered MCP servers, applied at registration (with DNS
// resolution) and again on every connection the gateway opens (ADR-0001 D8):
//
//	public    host on AllowedHosts, https, every address global unicast
//	loopback  dev mode only: localhost / 127.0.0.1 / ::1
//	private   host also on PrivateHosts: may resolve to RFC 1918 / ULA addresses, never to
//	          loopback, link-local (incl. cloud metadata), multicast, CGNAT, unspecified or reserved
type Upstream struct {
	AllowedHosts map[string]bool
	PrivateHosts map[string]bool
	DevMode      bool
	Resolver     func(ctx context.Context, host string) ([]netip.Addr, error)
}

// ErrBlocked wraps every policy refusal.
var ErrBlocked = errors.New("upstream blocked")

func blocked(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrBlocked, fmt.Sprintf(format, a...))
}

var metadataV6 = netip.MustParsePrefix("fd00:ec2::254/128")
var cgnat = netip.MustParsePrefix("100.64.0.0/10")
var benchmarking = netip.MustParsePrefix("198.18.0.0/15")
var testNets = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32")}

func isLoopbackName(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }

// AddressClass is the class of a resolved address under this policy.
type AddressClass int

const (
	ClassRestricted AddressClass = iota
	ClassGlobal
	ClassPrivate
	ClassLoopback
)

// Classify puts one address in a policy class.
func Classify(a netip.Addr) AddressClass {
	a = a.Unmap()
	switch {
	case a.IsLoopback():
		return ClassLoopback
	case a.IsUnspecified(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(), a.IsMulticast(),
		a.IsInterfaceLocalMulticast(), metadataV6.Contains(a), cgnat.Contains(a), benchmarking.Contains(a):
		return ClassRestricted
	}
	for _, p := range testNets {
		if p.Contains(a) {
			return ClassRestricted
		}
	}
	if a.Is4() && a.As4()[0] >= 240 { // 240.0.0.0/4 reserved, incl. broadcast
		return ClassRestricted
	}
	if a.IsPrivate() {
		return ClassPrivate
	}
	if a.IsGlobalUnicast() {
		return ClassGlobal
	}
	return ClassRestricted
}

// ForTargets is the dial policy of a running release: only the release's target hosts, each limited
// to the network class the registry approved; loopback only when the gateway itself runs in
// development mode.
func ForTargets(hostsByNetwork map[string]string, devMode bool) *Upstream {
	p := &Upstream{AllowedHosts: map[string]bool{}, PrivateHosts: map[string]bool{}, DevMode: devMode}
	for host, network := range hostsByNetwork {
		host = strings.ToLower(host)
		p.AllowedHosts[host] = true
		if network == "private" {
			p.PrivateHosts[host] = true
		}
	}
	return p
}

// NetworkOf returns the network class ("public", "private", "loopback") an endpoint that passed
// CheckEndpoint belongs to.
func (p *Upstream) NetworkOf(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	switch {
	case isLoopbackName(host):
		return "loopback"
	case p.PrivateHosts[host]:
		return "private"
	}
	return "public"
}

// permits reports whether host may connect to address a.
func (p *Upstream) permits(host string, a netip.Addr) bool {
	switch Classify(a) {
	case ClassGlobal:
		return true
	case ClassLoopback:
		return p.DevMode && isLoopbackName(host)
	case ClassPrivate:
		return p.PrivateHosts[host] && !isLoopbackName(host)
	}
	return false
}

// CheckEndpoint validates an MCP endpoint URL and resolves it; every address must be permitted.
func (p *Upstream) CheckEndpoint(ctx context.Context, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, blocked("malformed endpoint")
	}
	if !strings.HasSuffix(u.Path, "/mcp") || u.RawQuery != "" {
		return nil, blocked("endpoint must end in /mcp and have no query")
	}
	host := strings.ToLower(u.Hostname())
	if !p.AllowedHosts[host] {
		return nil, blocked("host %q is not on the allowlist", host)
	}
	private := p.PrivateHosts[host] && !isLoopbackName(host)
	if u.Scheme == "http" && !(p.DevMode && (isLoopbackName(host) || private)) {
		return nil, blocked("https is required outside development mode")
	}
	if !p.DevMode && isLoopbackName(host) {
		return nil, blocked("loopback endpoints are development-only")
	}
	addrs, err := p.resolve(ctx, host)
	if err != nil || len(addrs) == 0 {
		return nil, blocked("endpoint does not resolve")
	}
	for _, a := range addrs {
		if !p.permits(host, a) {
			return nil, blocked("%s resolves to a restricted network (%s)", host, a)
		}
	}
	return u, nil
}

func (p *Upstream) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if p.Resolver != nil {
		return p.Resolver(ctx, host)
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a}, nil
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// DialControl is a net.Dialer.Control hook: the gateway re-checks the address it actually connects
// to, so a name that resolved to a permitted address at registration cannot rebind elsewhere.
// host is the upstream host the connection is for (set per transport).
func (p *Upstream) DialControl(host string) func(network, address string, _ syscall.RawConn) error {
	host = strings.ToLower(host)
	return func(network, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return blocked("unparseable dial address %q", address)
		}
		if !p.AllowedHosts[host] {
			return blocked("dial for %s refused: host is not allowed", host)
		}
		if !p.permits(host, ap.Addr()) {
			return blocked("dial to %s for %s refused", ap.Addr(), host)
		}
		return nil
	}
}
