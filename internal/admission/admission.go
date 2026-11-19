// Package admission decides which OAuth clients the gateway serves and what each of them may reach
// (ADR-0001 D46 to D49). Authorization by role says what a member may do; this package adds what the
// program asking on the member's behalf may do, because the controls that make an outward tool safe
// (the member's confirmation, the sensitivity ceiling, the untrusted marking of its results) live in the
// agent runtime, and a client that talks to the gateway directly has none of them.
//
// The rule is fail closed: a client that is not listed is authenticated but is granted nothing, and the
// gateway does not start without the list.
package admission

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Wildcard is the client id that stands for every client, listed or not. An operator who writes it has
// switched client authorization off on purpose.
const Wildcard = "*"

// Client kinds.
const (
	KindPlatform = "platform"
	KindExternal = "external"
)

// Defaults of the rate limits (D49) when the file does not set them.
const (
	DefaultClientRequests  = 600
	DefaultSubjectRequests = 120
	DefaultWindow          = time.Minute
)

// MaxReason bounds an exception's reason, which is copied into every audit record that uses it.
const MaxReason = 256

var serverRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$`)

// Client is one entry of the clients file.
type Client struct {
	// Kind is KindPlatform (sees what its user's roles allow) or KindExternal (sees that, restricted to
	// Servers and Tools).
	Kind string `yaml:"kind"`
	// Host marks the agent runtime: the only client that may call host-only tools (D48).
	Host bool `yaml:"host"`
	// Servers are release target names whose tools, prompts and resources the client may use.
	Servers []string `yaml:"servers"`
	// Tools are patterns (path.Match syntax, over exposed tool names such as "docs__search*") of single tools
	// the client may use. They grant tools only, never prompts or resources.
	Tools []string `yaml:"tools"`
	// RateLimit is the request limit of this client per window; SubjectRateLimit the limit of each subject asking
	// through it. Unset, an external client gets the defaults of rateLimits and a platform client gets no limit:
	// the platform itself (the HOST carries every member's calls, a service account runs many executions under one
	// subject) must not be throttled by a limit meant for clients that are opened to others (ADR-0001 D49).
	RateLimit        int `yaml:"rateLimit"`
	SubjectRateLimit int `yaml:"subjectRateLimit"`
}

// Exception lifts host-only for the tools a pattern names; the reason is audited at every use.
type Exception struct {
	Pattern string `yaml:"pattern"`
	Reason  string `yaml:"reason"`
}

// Limit is a sliding-window request limit.
type Limit struct {
	Requests int           `yaml:"requests"`
	Window   time.Duration `yaml:"window"`
}

// RateLimits are the limits per client and per subject (D49).
type RateLimits struct {
	PerClient  Limit `yaml:"perClient"`
	PerSubject Limit `yaml:"perSubject"`
}

// Clients is the validated content of the clients file.
type Clients struct {
	clients       map[string]Client
	hostOnly      []string
	hostOnlyExcep []Exception
	limits        RateLimits
	warnings      []string
}

// file is the clients file as written.
type file struct {
	Clients        map[string]yaml.Node `yaml:"clients"`
	HostOnlyTools  []string             `yaml:"hostOnlyTools"`
	HostOnlyExcept []Exception          `yaml:"hostOnlyExcept"`
	RateLimits     struct {
		PerClient  rawLimit `yaml:"perClient"`
		PerSubject rawLimit `yaml:"perSubject"`
	} `yaml:"rateLimits"`
}

type rawLimit struct {
	Requests int    `yaml:"requests"`
	Window   string `yaml:"window"`
}

// ErrNotConfigured is returned when the gateway is started without a clients file. The message names the
// setting and the deliberate way out, because an operator meets it as the reason the gateway stops.
var ErrNotConfigured = errors.New("IDP_GATEWAY_CLIENTS_FILE is required: the file lists the OAuth clients this gateway serves, " +
	`and a client that is not listed is granted nothing; to serve every client as before, write the entry "*": platform ` +
	"in it on purpose, which turns client authorization off (idp-mcp ADR-0001 D46)")

// Load reads and validates the clients file at path.
func Load(path string) (*Clients, error) {
	if path == "" {
		return nil, ErrNotConfigured
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("clients file: %w", err)
	}
	c, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("clients file %s: %w", path, err)
	}
	return c, nil
}

// Parse validates the clients file's content (YAML; JSON is accepted). Unknown fields are errors: a
// misspelt "hostOnlyTool" must not leave the control off.
func Parse(b []byte) (*Clients, error) {
	var f file
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("not a valid clients file: %w", err)
	}
	c := &Clients{clients: map[string]Client{}, hostOnly: f.HostOnlyTools, hostOnlyExcep: f.HostOnlyExcept}
	if len(f.Clients) == 0 {
		return nil, errors.New(`"clients" lists no client; list at least one, or write "*": platform to serve every client`)
	}
	for id, node := range f.Clients {
		cl, err := parseClient(id, node)
		if err != nil {
			return nil, fmt.Errorf("client %q: %w", id, err)
		}
		c.clients[id] = cl
	}
	if err := c.validatePatterns(); err != nil {
		return nil, err
	}
	var err error
	if c.limits.PerClient, err = limit("perClient", f.RateLimits.PerClient, DefaultClientRequests); err != nil {
		return nil, err
	}
	if c.limits.PerSubject, err = limit("perSubject", f.RateLimits.PerSubject, DefaultSubjectRequests); err != nil {
		return nil, err
	}
	if _, ok := c.clients[Wildcard]; ok {
		c.warnings = append(c.warnings, `the entry "*" serves every client: client authorization is off`)
	}
	if len(c.hostOnly) > 0 && !c.hasHost() {
		c.warnings = append(c.warnings, "hostOnlyTools is set but no client has host: true, so nobody may call those tools")
	}
	return c, nil
}

func parseClient(id string, node yaml.Node) (Client, error) {
	if strings.TrimSpace(id) == "" {
		return Client{}, errors.New("the client id is empty")
	}
	var cl Client
	if node.Kind == yaml.ScalarNode { // the short form: "*": platform
		if err := node.Decode(&cl.Kind); err != nil || cl.Kind != KindPlatform {
			return cl, fmt.Errorf("a client written as one word must be %q; an external client needs servers or tools", KindPlatform)
		}
	} else {
		raw, err := yaml.Marshal(&node)
		if err != nil {
			return cl, err
		}
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		dec.KnownFields(true)
		if err := dec.Decode(&cl); err != nil {
			return cl, err
		}
	}
	switch cl.Kind {
	case KindPlatform:
		if len(cl.Servers) > 0 || len(cl.Tools) > 0 {
			return cl, errors.New("a platform client sees what its user's roles allow; servers and tools belong to an external client")
		}
	case KindExternal:
		if cl.Host {
			return cl, errors.New("only a platform client can be the host")
		}
		if len(cl.Servers) == 0 && len(cl.Tools) == 0 {
			return cl, errors.New("an external client needs servers or tools: it sees nothing else")
		}
	default:
		return cl, fmt.Errorf("kind must be %q or %q", KindPlatform, KindExternal)
	}
	if id == Wildcard && (cl.Kind != KindPlatform || cl.Host) {
		return cl, errors.New(`the entry "*" can only be a platform client that is not the host`)
	}
	for _, s := range cl.Servers {
		if !serverRE.MatchString(s) {
			return cl, fmt.Errorf("server %q is not a server name", s)
		}
	}
	for _, p := range cl.Tools {
		if err := validPattern(p); err != nil {
			return cl, fmt.Errorf("tools: %w", err)
		}
	}
	if cl.RateLimit < 0 || cl.SubjectRateLimit < 0 {
		return cl, errors.New("rateLimit and subjectRateLimit must be positive")
	}
	return cl, nil
}

// validPattern is the platform's tool-name pattern check, the one the agent runtime applies to
// externalTools and confirmTools: path.Match syntax, not empty.
func validPattern(p string) error {
	if _, err := path.Match(p, ""); p == "" || err != nil {
		return fmt.Errorf("%q is not a valid tool name pattern", p)
	}
	return nil
}

func (c *Clients) validatePatterns() error {
	for _, p := range c.hostOnly {
		if err := validPattern(p); err != nil {
			return fmt.Errorf("hostOnlyTools: %w", err)
		}
	}
	for _, e := range c.hostOnlyExcep {
		if err := validPattern(e.Pattern); err != nil {
			return fmt.Errorf("hostOnlyExcept: %w", err)
		}
		if strings.TrimSpace(e.Reason) == "" {
			return fmt.Errorf("hostOnlyExcept: the exception for %q needs a reason; it is written to the audit at every use", e.Pattern)
		}
		if len(e.Reason) > MaxReason {
			return fmt.Errorf("hostOnlyExcept: the reason of the exception for %q is longer than %d characters", e.Pattern, MaxReason)
		}
	}
	return nil
}

func limit(name string, r rawLimit, defRequests int) (Limit, error) {
	l := Limit{Requests: r.Requests, Window: DefaultWindow}
	if l.Requests == 0 {
		l.Requests = defRequests
	}
	if l.Requests < 0 {
		return l, fmt.Errorf("rateLimits.%s.requests must be positive", name)
	}
	if r.Window != "" {
		d, err := time.ParseDuration(r.Window)
		if err != nil || d <= 0 {
			return l, fmt.Errorf("rateLimits.%s.window %q is not a duration such as 1m", name, r.Window)
		}
		l.Window = d
	}
	return l, nil
}

func (c *Clients) hasHost() bool {
	for _, cl := range c.clients {
		if cl.Host {
			return true
		}
	}
	return false
}

// Unrestricted is the configuration of the deliberate opt-out, for tests and for callers that run the
// gateway in-process: every client is a platform client and nothing is host-only.
func Unrestricted() *Clients {
	c, _ := Parse([]byte(`clients: {"*": platform}`))
	return c
}

// Warnings are things an operator should know at start-up that are not errors.
func (c *Clients) Warnings() []string { return c.warnings }

// Limits are the configured rate limits.
func (c *Clients) Limits() RateLimits {
	if c == nil {
		return RateLimits{PerClient: Limit{DefaultClientRequests, DefaultWindow}, PerSubject: Limit{DefaultSubjectRequests, DefaultWindow}}
	}
	return c.limits
}

// ClientLimit is the request limit of one client and whether it has one. A client that is not listed is always
// limited, by the default: it is granted nothing, but it is not free to hammer the gateway or its audit. An
// external client has its own limit, else the default; a platform client has one only if its entry sets it.
func (c *Clients) ClientLimit(id string) (Limit, bool) {
	l := c.Limits().PerClient
	cl, ok := c.lookup(id)
	switch {
	case !ok:
		return l, true
	case cl.RateLimit > 0:
		l.Requests = cl.RateLimit
		return l, true
	}
	return l, cl.Kind == KindExternal
}

// SubjectLimit is the limit of each subject asking through the client, by the same rule as ClientLimit.
func (c *Clients) SubjectLimit(id string) (Limit, bool) {
	l := c.Limits().PerSubject
	cl, ok := c.lookup(id)
	switch {
	case !ok:
		return l, true
	case cl.SubjectRateLimit > 0:
		l.Requests = cl.SubjectRateLimit
		return l, true
	}
	return l, cl.Kind == KindExternal
}

// lookup finds the entry for a client id: its own, else the wildcard. A missing id is never listed by
// name, so only the wildcard can serve it.
func (c *Clients) lookup(id string) (Client, bool) {
	if c == nil {
		return Client{}, false
	}
	if id != "" {
		if cl, ok := c.clients[id]; ok {
			return cl, true
		}
	}
	cl, ok := c.clients[Wildcard]
	return cl, ok
}

// Listed reports whether the gateway serves the client at all.
func (c *Clients) Listed(id string) bool {
	_, ok := c.lookup(id)
	return ok
}

// IsHost reports whether the client is the agent runtime.
func (c *Clients) IsHost(id string) bool {
	if c == nil || id == "" {
		return false
	}
	cl, ok := c.clients[id]
	return ok && cl.Host
}

// Access names what a client asks to use. Tool is the exposed tool name; it is empty for a server's
// prompts and resources, which only a server grant covers. HostOnly is a source of host-only-ness that
// the gateway knows from the release rather than from the file (ADR-0001 D48: every tool of an upstream
// of class external); the patterns of the file are applied here.
type Access struct {
	Target   string
	Tool     string
	HostOnly bool
}

// Why a request was refused.
const (
	NotListed  = "client not listed"
	NotAllowed = "client not allowed"
	HostOnly   = "host-only"
)

// Verdict is the decision on one Access. Why names the cause of a refusal; Exception is the reason of
// the operator's exception that let a non-host client through a host-only tool, set only when it did.
type Verdict struct {
	Allowed   bool
	Why       string
	Exception string
}

// Decide reports whether the client may use what is asked. A tool is visible and callable when the role
// allows it and this allows it; the role is the caller's business.
func (c *Clients) Decide(id string, a Access) Verdict {
	cl, ok := c.lookup(id)
	if !ok {
		return Verdict{Why: NotListed}
	}
	var exception string
	if hostOnly := a.HostOnly || (a.Tool != "" && matchAny(c.hostOnly, a.Tool)); hostOnly && !c.IsHost(id) {
		if reason, ok := c.exception(a.Tool); ok {
			exception = reason
		} else {
			return Verdict{Why: HostOnly}
		}
	}
	if cl.Kind == KindExternal {
		ok := false
		for _, s := range cl.Servers {
			ok = ok || s == a.Target
		}
		if a.Tool != "" && matchAny(cl.Tools, a.Tool) {
			ok = true
		}
		if !ok {
			return Verdict{Why: NotAllowed}
		}
	}
	return Verdict{Allowed: true, Exception: exception}
}

func (c *Clients) exception(tool string) (string, bool) {
	if tool == "" {
		return "", false
	}
	for _, e := range c.hostOnlyExcep {
		if ok, err := path.Match(e.Pattern, tool); err == nil && ok {
			return e.Reason, true
		}
	}
	return "", false
}

func matchAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if ok, err := path.Match(p, name); err == nil && ok {
			return true
		}
	}
	return false
}
