package policy

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// The addresses the sandbox's egress proxy let through until a review found them (idp-sandbox D22) and this
// package's rule let through too: every block the IANA special-purpose registries mark as not globally reachable,
// and the IPv6 blocks that carry an IPv4 address.
var notPublic = []string{
	"0.1.2.3", "0.255.255.255", "240.0.0.1", "250.1.1.1", "255.255.255.254", "255.255.255.255", // 0.0.0.0/8 beyond 0.0.0.0, 240.0.0.0/4
	"198.18.0.1", "198.19.255.254", "192.0.0.1", "192.0.0.9", "192.0.0.170", // benchmarking, IETF protocol assignments
	"192.0.2.1", "198.51.100.7", "203.0.113.20", "2001:db8::1", "2001:db8:ffff::1", // documentation
	"192.88.99.1",                                                           // deprecated 6to4 relay anycast
	"64:ff9b::7f00:1", "64:ff9b::a00:1", "64:ff9b::808:808", "64:ff9b:1::1", // NAT64
	"2002:7f00:1::", "2002:a00:1::1", "2002:808:808::", // 6to4
	"2001:0:4136:e378:8000:63bf:3fff:fdd2",                    // Teredo
	"2001:10::1", "2001:2::1", "100::1", "5f00::1", "3fff::1", // ORCHID, benchmarking, discard-only, SRv6, documentation
	"fec0::1", "ff02::1", "::ffff:0:102:304", "::102:304", "2001:1::1", "2001:20::1", // site-local, multicast, translated and compatible, inside 2001::/23
	"0.0.0.0", "::", "100.64.0.1", "169.254.169.254", "fe80::1", "fd00:ec2::254", "::ffff:169.254.169.254", "224.0.0.1", // what was refused before stays refused
}

// A public address next to a special-purpose block must stay public.
var public = []string{"1.1.1.1", "8.8.8.8", "9.255.255.255", "11.0.0.1", "93.184.216.34", "100.63.255.255", "100.128.0.1", "126.255.255.255", "128.0.0.1",
	"172.15.255.255", "172.32.0.1", "192.0.1.1", "192.0.3.1", "192.88.98.1", "192.167.255.255", "192.169.0.1", "198.17.255.255", "198.20.0.1",
	"198.51.99.1", "198.51.101.1", "203.0.112.1", "203.0.114.1", "223.255.255.255",
	"2606:4700:4700::1111", "2a00:1450:4001::1", "2001:4860:4860::8888", "2620:fe::fe", "2001:200::1", "192.31.196.1", "192.52.193.1", "192.175.48.1",
	"2400:cb00::1", "2a03:2880::1", "::ffff:8.8.8.8"}

func TestEveryAddressTheIANARegistriesMarkNotGloballyReachableIsNotPublic(t *testing.T) {
	for _, s := range notPublic {
		if c := Classify(netip.MustParseAddr(s)); c != ClassRestricted {
			t.Errorf("%s was classified %d, want restricted", s, c)
		}
	}
}

func TestPublicAddressesNextToTheSpecialPurposeBlocksStayPublic(t *testing.T) {
	for _, s := range public {
		if c := Classify(netip.MustParseAddr(s)); c != ClassGlobal {
			t.Errorf("%s was classified %d, want global", s, c)
		}
	}
}

// A zone names a local interface; netip.Prefix.Contains is false for a zoned address, so a table lookup alone would
// let every zoned address through. None is a legitimate upstream address.
func TestEveryZonedAddressIsRestricted(t *testing.T) {
	for _, s := range []string{"fe80::1%eth0", "fd00::5%eth0", "::1%lo", "ff02::1%eth0", "2606:4700:4700::1111%eth0", "2001:db8::1%eth0", "64:ff9b::7f00:1%eth0"} {
		if c := Classify(netip.MustParseAddr(s)); c != ClassRestricted {
			t.Errorf("%s was classified %d, want restricted", s, c)
		}
	}
}

// The classes the policy distinguishes are as they were: only the notion of "public" changed.
func TestLoopbackAndPrivateClassesAreUnchanged(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "127.9.9.9", "::1", "::ffff:127.0.0.1"} {
		if c := Classify(netip.MustParseAddr(s)); c != ClassLoopback {
			t.Errorf("%s: %d, want loopback", s, c)
		}
	}
	for _, s := range []string{"10.20.0.5", "172.16.0.1", "172.31.255.255", "192.168.1.1", "fd12:3456::7", "fc00::1", "::ffff:10.0.0.1"} {
		if c := Classify(netip.MustParseAddr(s)); c != ClassPrivate {
			t.Errorf("%s: %d, want private", s, c)
		}
	}
}

// Registration and the dial-time check judge an address by the same function, so a name that resolves to one of the
// addresses above is refused at registration, and a connection to it is refused at dial time, also for a host on the
// private list (which may reach RFC 1918 / ULA addresses and nothing else that is not public).
func TestRegistrationAndDialTimeRefuseTheSameAddresses(t *testing.T) {
	for _, s := range notPublic {
		a := netip.MustParseAddr(s)
		for _, dev := range []bool{false, true} {
			p := pol(dev, []string{"h.corp"}, "h.corp")
			p.Resolver = func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{a}, nil }
			if _, err := p.CheckEndpoint(context.Background(), "https://h.corp/mcp"); !errors.Is(err, ErrBlocked) {
				t.Errorf("registration accepted %s (dev=%v): %v", s, dev, err)
			}
			if err := p.DialControl("h.corp")("tcp", netip.AddrPortFrom(a, 443).String(), nil); !errors.Is(err, ErrBlocked) {
				t.Errorf("dial to %s allowed (dev=%v)", s, dev)
			}
		}
	}
	for _, s := range public {
		a := netip.MustParseAddr(s)
		p := pol(false, []string{"h.example"})
		p.Resolver = func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{a}, nil }
		if _, err := p.CheckEndpoint(context.Background(), "https://h.example/mcp"); err != nil {
			t.Errorf("registration refused %s: %v", s, err)
		}
		if err := p.DialControl("h.example")("tcp", netip.AddrPortFrom(a, 443).String(), nil); err != nil {
			t.Errorf("dial to %s refused: %v", s, err)
		}
	}
}
