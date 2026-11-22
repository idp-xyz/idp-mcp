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
//	public    host on AllowedHosts, https, every address globally reachable (not in a block the IANA
//	          special-purpose registries mark otherwise, see notGloballyReachable)
//	loopback  dev mode only: localhost / 127.0.0.1 / ::1
//	private   host also on PrivateHosts: may resolve to RFC 1918 / ULA addresses, never to
//	          loopback, link-local (incl. cloud metadata), multicast, CGNAT, unspecified, reserved or one of the
//	          other special-purpose blocks (NAT64, 6to4, Teredo, documentation, ...)
type Upstream struct {
	AllowedHosts map[string]bool
	PrivateHosts map[string]bool
	DevMode      bool
	Resolver     func(ctx context.Context, host string) ([]netip.Addr, error)
	// Bridges are the addresses of the bridge's endpoints (IDP_BRIDGE_ENDPOINTS, D50). The bridge has one endpoint per connection,
	// <base>/mcp/<id>, which does not end in /mcp: an endpoint at one of these addresses is exempt from that rule and from nothing
	// else (it is external, which the registry enforces separately, and it goes through every other check here).
	Bridges Endpoints
}

// ErrBlocked wraps every policy refusal.
var ErrBlocked = errors.New("upstream blocked")

func blocked(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrBlocked, fmt.Sprintf(format, a...))
}

// metadataV6 is the AWS IPv6 metadata address; it lies inside the unique-local range, which is otherwise the
// private class, so it is refused before that range is considered.
var metadataV6 = netip.MustParsePrefix("fd00:ec2::254/128")

// notGloballyReachable is every block that is never a public upstream address. It is not a list someone
// remembered: it is the IANA IPv4 Special-Purpose Address Registry and the IANA IPv6 Special-Purpose Address
// Registry as of 2026-11-19, every entry with "Globally Reachable: False" (or "N/A"), plus the blocks that are not
// in those tables but are not unicast destinations either (multicast, the reserved 224.0.0.0/3, site-local
// fec0::/10). It is the table the sandbox's egress proxy uses (idp-sandbox D22) after a review found that an
// earlier hand-made list missed most of 0.0.0.0/8, 192.0.0.0/24, 240.0.0.0/4 and every IPv6 block that carries an
// IPv4 address; this package's rule had the same gaps (ADR-0001 D8, note of 2026-11-19).
//
// A block with small globally reachable exceptions is refused whole: 192.0.0.0/24 (192.0.0.9 and 192.0.0.10) and
// 2001::/23 (PCP and TURN anycast, AMT, AS112, drone remote ID). No upstream lives there, and one rule without
// holes is easier to check than a rule with them. The other globally reachable special-purpose blocks
// (192.31.196.0/24, 192.52.193.0/24, 192.175.48.0/24, 2620:4f:8000::/48) are left alone: public anycast.
//
// IPv6 blocks that embed an IPv4 address (IPv4-compatible, SIIT and NAT64, 6to4, Teredo) are refused whole, for
// the address they would reach, whatever it is: 64:ff9b::7f00:1 and 2002:7f00:1:: reach 127.0.0.1 where such
// translation exists. An IPv4-mapped address is the exception: it is judged as the IPv4 address it carries (Classify
// unmaps it first). The private ranges (RFC 1918, fc00::/7) and loopback are in this table because they are not
// public, but Classify names them before it asks the table.
var notGloballyReachable = func() []netip.Prefix {
	var out []netip.Prefix
	for _, c := range []string{
		// IPv4 Special-Purpose Address Registry
		"0.0.0.0/8",       // "this network" (RFC 791)
		"10.0.0.0/8",      // private use (RFC 1918)
		"100.64.0.0/10",   // shared address space, carrier-grade NAT (RFC 6598)
		"127.0.0.0/8",     // loopback (RFC 1122)
		"169.254.0.0/16",  // link local, which holds the cloud metadata address 169.254.169.254 (RFC 3927)
		"172.16.0.0/12",   // private use (RFC 1918)
		"192.0.0.0/24",    // IETF protocol assignments, DS-Lite, NAT64 discovery, whole (RFC 6890)
		"192.0.2.0/24",    // documentation TEST-NET-1 (RFC 5737)
		"192.88.99.0/24",  // deprecated 6to4 relay anycast (RFC 7526); refused as a transition block
		"192.168.0.0/16",  // private use (RFC 1918)
		"198.18.0.0/15",   // benchmarking (RFC 2544)
		"198.51.100.0/24", // documentation TEST-NET-2 (RFC 5737)
		"203.0.113.0/24",  // documentation TEST-NET-3 (RFC 5737)
		"224.0.0.0/3",     // multicast 224.0.0.0/4 and reserved 240.0.0.0/4 with limited broadcast 255.255.255.255 (RFC 1112, RFC 919)
		// IPv6 Special-Purpose Address Registry
		"::/8",          // reserved by IETF: unspecified ::, loopback ::1, IPv4-compatible ::/96, IPv4-mapped ::ffff:0:0/96, SIIT ::ffff:0:0:0/96, NAT64 64:ff9b::/96 and 64:ff9b:1::/48
		"100::/64",      // discard-only (RFC 6666)
		"2001::/23",     // IETF protocol assignments, whole: Teredo 2001::/32, benchmarking 2001:2::/48, ORCHID, PCP, AMT, AS112 (RFC 6890)
		"2001:db8::/32", // documentation (RFC 3849)
		"2002::/16",     // 6to4 (RFC 3056)
		"3fff::/20",     // documentation (RFC 9637)
		"5f00::/16",     // segment routing SIDs (RFC 9602)
		"fc00::/7",      // unique local (RFC 4193)
		"fe80::/10",     // link local (RFC 4291)
		"fec0::/10",     // deprecated site-local (RFC 3879)
		"ff00::/8",      // multicast (RFC 4291)
	} {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}()

// globallyReachable reports whether a is outside every block of notGloballyReachable.
func globallyReachable(a netip.Addr) bool {
	for _, p := range notGloballyReachable {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

func isLoopbackName(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }

// AddressClass is the class of a resolved address under this policy.
type AddressClass int

const (
	ClassRestricted AddressClass = iota
	ClassGlobal
	ClassPrivate
	ClassLoopback
)

// Classify puts one address in a policy class. Loopback and the private ranges are named first; everything else is
// global only if the IANA special-purpose registries do not mark it as not globally reachable. An IPv4-mapped IPv6
// address is judged as the IPv4 address it carries.
func Classify(a netip.Addr) AddressClass {
	// A zone names a local interface, and netip.Prefix.Contains is false for a zoned address, so a zoned address would
	// pass every entry of the table: refuse it outright. No upstream is addressed that way.
	if !a.IsValid() || a.Zone() != "" {
		return ClassRestricted
	}
	a = a.Unmap()
	switch {
	case a.IsLoopback():
		return ClassLoopback
	case metadataV6.Contains(a):
		return ClassRestricted
	case a.IsPrivate():
		return ClassPrivate
	case globallyReachable(a):
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
	if !(strings.HasSuffix(u.Path, "/mcp") || p.Bridges.Matches(raw)) || u.RawQuery != "" {
		return nil, blocked("endpoint must end in /mcp (a bridge's endpoint may be /mcp/<connection>) and have no query")
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
