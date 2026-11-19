package policy

import (
	"fmt"
	"net/url"
	"strings"
)

// Endpoints names addresses by host or by URL prefix: the bridge endpoints of the interop decision
// (ADR-0001 D50), whose upstreams are the third parties' servers. A registration at one of them must be of class
// external, so that the class cannot be forgotten for the one kind of upstream that is known to be external. The
// zero value names nothing.
type Endpoints struct {
	hosts    map[string]bool // "bridge.idp.svc" or "bridge.idp.svc:8443": any path
	prefixes []string        // "https://bridge.idp.svc/connections/": a path prefix on a path boundary
}

// ParseEndpoints reads a comma-separated list of entries, each a host (with an optional port) or an http(s) URL
// taken as a path prefix. A host entry without a port matches that host on every port.
func ParseEndpoints(list string) (Endpoints, error) {
	e := Endpoints{hosts: map[string]bool{}}
	for _, entry := range strings.Split(list, ",") {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "://") {
			u, err := url.Parse(entry)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
				return Endpoints{}, fmt.Errorf("bridge endpoint %q: want a host or an http(s) URL without credentials, query or fragment", entry)
			}
			e.prefixes = append(e.prefixes, u.Scheme+"://"+u.Host+strings.TrimSuffix(u.Path, "/"))
			continue
		}
		if strings.ContainsAny(entry, "/?#@ ") {
			return Endpoints{}, fmt.Errorf("bridge endpoint %q: want a host or an http(s) URL", entry)
		}
		e.hosts[entry] = true
	}
	return e, nil
}

// Matches reports whether endpoint is at one of the addresses.
func (e Endpoints) Matches(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return false
	}
	host := strings.ToLower(u.Host)
	if e.hosts[host] || e.hosts[strings.ToLower(u.Hostname())] {
		return true
	}
	full := u.Scheme + "://" + host + strings.TrimSuffix(u.Path, "/")
	for _, p := range e.prefixes {
		if full == p || strings.HasPrefix(full, p+"/") {
			return true
		}
	}
	return false
}

// Empty reports whether no address is named.
func (e Endpoints) Empty() bool { return len(e.hosts) == 0 && len(e.prefixes) == 0 }
