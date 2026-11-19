package gateway

// The conformance vectors of the caller assertion (ADR-0001 D44): the assertions this gateway signs and the ones its
// upstreams must refuse, with the outcome each upstream has to reach. idp-sandbox and idp-web run the same file against
// their verifiers; the platform publishes it as idp-contracts/vectors/caller-assertion/v1.json (format and
// vocabulary: the README next to it). The three copies are kept byte-identical by idp-contracts/tools/validate.py.
//
// Everything the signer can produce is produced by CallerSigner through stampCaller, the path a forwarded request takes.
// What it cannot produce (an assertion of 5 minutes, a wrong algorithm, a forged signature) is made by the test's own
// code. The key pair is created when the file is generated and only its public half is written; the private half
// exists in this process and nowhere else, so nobody can sign a vector later and the file never needs a secret.
//
//	go test ./internal/gateway -run TestCallerVectors -update
//
// Without -update the committed file is checked against this package's own code: the digest every assertion carries,
// the signatures and headers of the ones the signer made, and the caller the file expects of them.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"idp-mcp/internal/authorization"
	"idp-mcp/internal/release"
)

var updateVectors = flag.Bool("update", false, "regenerate internal/gateway/testdata/caller-assertion-v1.json with fresh keys and signatures")

const (
	vectorsPath   = "testdata/caller-assertion-v1.json"
	vectorsFormat = "idp.telos.caller-assertion-vectors/v1"
	vectorsBy     = "go test ./internal/gateway -run TestCallerVectors -update (idp-mcp)"
	// the audience of every vector: the endpoint idp-sandbox is registered under in idp-mcp's examples
	vectorsAudience = "http://sandbox:8570/mcp"
	// the request the vectors are about; it is the one pinned in TestRequestDigestIsTheOneUpstreamsCompute
	vectorsRequest = `{"name":"sandbox_run","arguments":{"workspaceId":"0123456789abcdef0123456789abcdef","language":"python","code":"print('<a> & é')","timeoutSeconds":5.0},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}`
)

// The reasons a case may expect. They name the rule that refused, not a message: each verifier maps them onto its own
// errors.
var vectorReasons = map[string]bool{
	"no_assertion": true, "malformed": true, "header": true, "unknown_key": true, "bad_signature": true, "audience": true,
	"expired": true, "issued_in_future": true, "lifetime": true, "missing_claim": true, "request_mismatch": true, "replay": true,
}

type vectorFile struct {
	Format      string       `json:"format"`
	GeneratedBy string       `json:"generatedBy"`
	Audience    string       `json:"audience"`
	Keys        []vectorKey  `json:"keys"`
	Cases       []vectorCase `json:"cases"`
}

type vectorKey struct {
	Name  string `json:"name"`
	KeyID string `json:"kid"`
	PEM   string `json:"pem"`
}

type vectorCase struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Origin      string       `json:"origin"` // "gateway": made by CallerSigner; "forged": made by this test
	Steps       []vectorStep `json:"steps"`
}

type vectorStep struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	// SignedRequest is the request the assertion was made for, where that is not the one presented (changed params,
	// another method). Verifiers ignore it; it lets this package check the digest of what the signer signed.
	SignedRequest *vectorRequest `json:"signedRequest,omitempty"`
	Now           string         `json:"now"`
	Expect        vectorExpect   `json:"expect"`
}

type vectorRequest struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type vectorExpect struct {
	Outcome string        `json:"outcome"`
	Caller  *vectorCaller `json:"caller,omitempty"`
	Reason  string        `json:"reason,omitempty"`
}

type vectorCaller struct {
	Subject string   `json:"subject"`
	Tenant  string   `json:"tenant"`
	Roles   []string `json:"roles"`
	Client  string   `json:"client"`
	Actor   string   `json:"actor"`
}

type vectorBuilder struct {
	t                *testing.T
	t0               time.Time // the moment the gateway signs
	keyA, keyB, keyC *ecdsa.PrivateKey
	signerA, signerB *CallerSigner
	kidA, kidB, kidC string
	jti              int
	cases            []vectorCase
}

func (b *vectorBuilder) key() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.t.Fatal(err)
	}
	return k
}

func (b *vectorBuilder) signerFor(k *ecdsa.PrivateKey) *CallerSigner {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		b.t.Fatal(err)
	}
	s, err := NewCallerSigner(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), "idp-mcp-gateway:g1")
	if err != nil {
		b.t.Fatal(err)
	}
	s.now = func() time.Time { return b.t0 }
	return s
}

func parseParams(t *testing.T, doc string) map[string]json.RawMessage {
	t.Helper()
	var p map[string]json.RawMessage
	if err := json.Unmarshal([]byte(doc), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// signed is what a forwarding target receives: the request with the gateway's stamp (the caller and its assertion), made
// by the real stampCaller and the real signer. endpoint and method are what the gateway signs for; the request may be
// presented to another one by the step.
func (b *vectorBuilder) signed(s *CallerSigner, pr authorization.Principal, endpoint, method string, params map[string]json.RawMessage) map[string]json.RawMessage {
	out, err := stampCaller(params, release.IdentityForward, pr, true, s, endpoint, method)
	if err != nil {
		b.t.Fatal(err)
	}
	return out
}

func (b *vectorBuilder) request() map[string]json.RawMessage { return parseParams(b.t, vectorsRequest) }

var operator = authorization.Principal{Subject: "svc-operator", Tenant: "t1", Roles: []string{"operator"}, Client: "idp-host", Actor: "idp-host"}

func callerOf(pr authorization.Principal) *vectorCaller {
	roles := pr.Roles
	if roles == nil {
		roles = []string{}
	}
	return &vectorCaller{Subject: pr.Subject, Tenant: pr.Tenant, Roles: roles, Client: pr.Client, Actor: pr.Actor}
}

// withAssertion is params as a client of the gateway's upstream would see them with this assertion in place of whatever
// they carried: the unsigned caller stays, as it does on the wire.
func (b *vectorBuilder) withAssertion(params map[string]json.RawMessage, assertion string) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(params))
	for k, v := range params {
		out[k] = v
	}
	var meta map[string]json.RawMessage
	_ = json.Unmarshal(out["_meta"], &meta)
	if meta == nil {
		meta = map[string]json.RawMessage{}
	}
	if _, ok := meta[MetaCaller]; !ok {
		meta[MetaCaller] = mustJSON(b.t, callerOf(operator))
	}
	if assertion != "" {
		meta[MetaCallerAssertion] = mustJSON(b.t, assertion)
	}
	out["_meta"] = mustJSON(b.t, meta)
	return out
}

func (b *vectorBuilder) digest(method string, params map[string]json.RawMessage) string {
	d, err := RequestDigest(method, params)
	if err != nil {
		b.t.Fatal(err)
	}
	return d
}

func (b *vectorBuilder) claims(req string, change func(map[string]any)) map[string]any {
	b.jti++
	c := map[string]any{"iss": "idp-mcp-gateway:g1", "aud": vectorsAudience, "iat": b.t0.Unix(), "exp": b.t0.Add(CallerAssertionTTL).Unix(),
		"jti": fmt.Sprintf("forged-%02d", b.jti), "sub": operator.Subject, "tenant_id": operator.Tenant, "roles": operator.Roles,
		"client": operator.Client, "actor": operator.Actor, "req": req}
	if change != nil {
		change(c)
	}
	return c
}

func (b *vectorBuilder) header(kid string) map[string]any {
	return map[string]any{"alg": "ES256", "typ": CallerAssertionType, "kid": kid}
}

func b64(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func (b *vectorBuilder) compact(header, claims map[string]any) string {
	return b64(mustJSON(b.t, header)) + "." + b64(mustJSON(b.t, claims))
}

// signInput signs a JWS signing input with ES256 under key k: r || s, 32 bytes each.
func (b *vectorBuilder) signInput(k *ecdsa.PrivateKey, input string) string {
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, k, sum[:])
	if err != nil {
		b.t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + b64(sig)
}

// forge signs with ES256 under key k, whatever the header and claims say.
func (b *vectorBuilder) forge(k *ecdsa.PrivateKey, header, claims map[string]any) string {
	return b.signInput(k, b.compact(header, claims))
}

func (b *vectorBuilder) at(d time.Duration) time.Time { return b.t0.Add(d) }

func (b *vectorBuilder) step(method string, params map[string]json.RawMessage, now time.Time, expect vectorExpect) vectorStep {
	return vectorStep{Method: method, Params: mustJSON(b.t, params), Now: now.UTC().Format(time.RFC3339), Expect: expect}
}

func accept(pr authorization.Principal) vectorExpect {
	return vectorExpect{Outcome: "accept", Caller: callerOf(pr)}
}

func refuse(reason string) vectorExpect { return vectorExpect{Outcome: "refuse", Reason: reason} }

func (b *vectorBuilder) add(name, origin, description string, steps ...vectorStep) {
	b.cases = append(b.cases, vectorCase{Name: name, Description: description, Origin: origin, Steps: steps})
}

// forgedOne is a case of one step: a forged assertion over the request, presented as it was signed unless the claims say
// otherwise.
func (b *vectorBuilder) forgedOne(name, description string, expect vectorExpect, assertion string, now time.Time) {
	b.add(name, "forged", description, b.step("tools/call", b.withAssertion(b.request(), assertion), now, expect))
}

func (b *vectorBuilder) build() []vectorCase {
	t := b.t
	req := b.request()
	good := b.digest("tools/call", req)
	ok := b.at(20 * time.Second) // twenty seconds after the gateway signed

	// --- the gateway's own assertions, and what a verifier must accept of them
	goodParams := b.signed(b.signerA, operator, vectorsAudience, "tools/call", req)
	b.add("good", "gateway", "The assertion the gateway signs for a forwarded call, presented twenty seconds later.",
		b.step("tools/call", goodParams, ok, accept(operator)))

	// the same request spelled differently from the one that was signed: other spacing, key order and escapes
	meta, _ := json.Marshal(json.RawMessage(req["_meta"]))
	respelled := `{ "arguments": {"timeoutSeconds":5.0, "code":"print('<a> & é')", "language":"python", "workspaceId":"0123456789abcdef0123456789abcdef"}, "_meta":` + string(meta) + `, "name":"sandbox_run"}`
	rp := parseParams(t, respelled)
	rp["_meta"] = goodParams["_meta"]
	b.add("good-params-spelled-differently", "gateway", "The digest is of the JSON value, not of its bytes: the same request with other spacing, key order and string escapes is accepted.",
		b.step("tools/call", rp, ok, accept(operator)))

	bare := authorization.Principal{Subject: "svc-bare", Tenant: "t2"}
	b.add("good-without-roles-client-and-actor", "gateway", "A caller with no roles, no client and no actor: roles is an empty list, client and actor are empty.",
		b.step("tools/call", b.signed(b.signerA, bare, vectorsAudience, "tools/call", req), ok, accept(bare)))

	b.add("good-signed-with-the-second-key", "gateway", "A verifier holding both keys (one is being rotated out) accepts an assertion of either, chosen by kid.",
		b.step("tools/call", b.signed(b.signerB, operator, vectorsAudience, "tools/call", req), ok, accept(operator)))

	b.add("good-expired-within-the-skew", "gateway", "30 seconds after exp the assertion is still accepted: the clocks may differ by that much.",
		b.step("tools/call", goodParams, b.at(CallerAssertionTTL+30*time.Second), accept(operator)))

	b.add("good-issued-in-the-future-within-the-skew", "gateway", "An assertion made 30 seconds ahead of the verifier's clock is accepted.",
		b.step("tools/call", b.signed(b.signerA, operator, vectorsAudience, "tools/call", req), b.at(-30*time.Second), accept(operator)))

	b.forgedOne("good-audience-as-a-list", "aud may be a list; it is accepted when it contains this server's endpoint.", accept(operator),
		b.forge(b.keyA, b.header(b.kidA), b.claims(good, func(c map[string]any) { c["aud"] = []string{"http://another:9000/mcp", vectorsAudience} })), ok)

	b.forgedOne("good-lifetime-of-exactly-5-minutes", "The longest lifetime a verifier accepts, although the gateway itself makes one of a minute.", accept(operator),
		b.forge(b.keyA, b.header(b.kidA), b.claims(good, func(c map[string]any) { c["exp"] = b.t0.Add(5 * time.Minute).Unix() })), ok)

	// pad the claims with an unknown claim until the compact form is as long as a verifier reads: 8192 bytes, the
	// signature (86 characters) included
	padded := func(n int) map[string]any {
		return b.claims(good, func(c map[string]any) { c["pad"] = strings.Repeat("a", n) })
	}
	n := 0
	for len(b.compact(b.header(b.kidA), padded(n)))+1+86 < 8192 {
		n++
	}
	exact := b.forge(b.keyA, b.header(b.kidA), padded(n))
	if len(exact) != 8192 {
		t.Fatalf("the padded assertion is %d bytes long, not 8192", len(exact))
	}
	b.forgedOne("good-assertion-of-exactly-8192-bytes", "The longest assertion a verifier reads: 8192 bytes of compact JWS.", accept(operator), exact, ok)

	// --- refusals: nothing to verify
	b.add("refused-no-assertion", "forged", "A call with the unsigned caller of a gateway without a key, or of anyone on the network, and no assertion.",
		b.step("tools/call", b.withAssertion(b.request(), ""), ok, refuse("no_assertion")))

	// --- refusals: the assertion is not a JWS this verifier reads
	b.forgedOne("refused-not-a-jws", "Something that is not a compact JWS.", refuse("malformed"), "attachment:1", ok)
	b.forgedOne("refused-not-base64url", "Three parts that are not base64url.", refuse("malformed"), "a!b.c!d.e!f", ok)
	b.forgedOne("refused-over-8192-bytes", "Longer than a verifier reads (over 8192 bytes), validly signed.", refuse("malformed"),
		b.forge(b.keyA, b.header(b.kidA), padded(n+3)), ok)
	b.forgedOne("refused-claims-are-not-an-object", "A correctly signed JWS whose payload is a list.", refuse("malformed"),
		b.signInput(b.keyA, b64(mustJSON(t, b.header(b.kidA)))+"."+b64([]byte(`[]`))), ok)

	// --- refusals: the header
	b.forgedOne("refused-alg-none", "alg none with a gateway kid and an empty signature.", refuse("header"),
		b.compact(map[string]any{"alg": "none", "typ": CallerAssertionType, "kid": b.kidA}, b.claims(good, nil))+".", ok)
	pubDER, _ := x509.MarshalPKIXPublicKey(&b.keyA.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	hsInput := b.compact(map[string]any{"alg": "HS256", "typ": CallerAssertionType, "kid": b.kidA}, b.claims(good, nil))
	mac := hmac.New(sha256.New, pubPEM)
	mac.Write([]byte(hsInput))
	b.forgedOne("refused-alg-hs256-keyed-with-the-public-key", "The classic confusion: an HMAC made with the gateway's public key (its PEM text) as the secret.", refuse("header"),
		hsInput+"."+b64(mac.Sum(nil)), ok)
	b.forgedOne("refused-another-typ", "typ JWT: an access token, not a caller assertion, signed by a held key.", refuse("header"),
		b.forge(b.keyA, map[string]any{"alg": "ES256", "typ": "JWT", "kid": b.kidA}, b.claims(good, nil)), ok)
	k384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b.forgedOne("refused-signed-with-p384-and-es384", "A P-384 key signing ES384, as someone with a different curve would.", refuse("header"),
		b.forgeP384(k384, map[string]any{"alg": "ES384", "typ": CallerAssertionType, "kid": b.kidA}, b.claims(good, nil)), ok)
	b.forgedOne("refused-signed-with-p384-under-an-es256-header", "A P-384 signature (96 bytes) under an ES256 header and a held kid: the signature has the wrong size.", refuse("bad_signature"),
		b.forgeP384(k384, b.header(b.kidA), b.claims(good, nil)), ok)

	// --- refusals: the key and the signature
	b.forgedOne("refused-unknown-kid", "Signed by a key the verifier does not hold, under that key's own kid.", refuse("unknown_key"),
		b.forge(b.keyC, b.header(b.kidC), b.claims(good, nil)), ok)
	b.forgedOne("refused-bad-signature-under-a-known-kid", "Signed by another key under the gateway's kid.", refuse("bad_signature"),
		b.forge(b.keyC, b.header(b.kidA), b.claims(good, nil)), ok)
	parts := strings.Split(goodParamsAssertion(t, goodParams), ".")
	b.forgedOne("refused-claims-swapped-after-signing", "The gateway's header and signature with other claims.", refuse("bad_signature"),
		parts[0]+"."+b64([]byte(`{"sub":"admin"}`))+"."+parts[2], ok)
	b.forgedOne("refused-signature-of-the-wrong-size", "A signature of three bytes.", refuse("bad_signature"), parts[0]+"."+parts[1]+".AAAA", ok)

	// --- refusals: the audience
	b.add("refused-wrong-audience", "gateway", "Signed by the gateway for another upstream's endpoint.",
		b.step("tools/call", b.signed(b.signerA, operator, "http://another-server:9000/mcp", "tools/call", req), ok, refuse("audience")))
	b.forgedOne("refused-audience-list-without-this-server", "aud as a list that does not contain this server's endpoint.", refuse("audience"),
		b.forge(b.keyA, b.header(b.kidA), b.claims(good, func(c map[string]any) { c["aud"] = []string{"http://another:9000/mcp"} })), ok)

	// --- refusals: the time
	b.add("refused-expired", "gateway", "31 seconds after exp: beyond the 30 seconds of clock skew.",
		b.step("tools/call", goodParams, b.at(CallerAssertionTTL+31*time.Second), refuse("expired")))
	b.add("refused-issued-in-the-future", "gateway", "Made 31 seconds ahead of the verifier's clock: beyond the skew.",
		b.step("tools/call", b.signed(b.signerA, operator, vectorsAudience, "tools/call", req), b.at(-31*time.Second), refuse("issued_in_future")))
	b.forgedOne("refused-lifetime-over-5-minutes", "exp is 5 minutes and a second after iat.", refuse("lifetime"),
		b.forge(b.keyA, b.header(b.kidA), b.claims(good, func(c map[string]any) { c["exp"] = b.t0.Add(5*time.Minute + time.Second).Unix() })), ok)
	b.forgedOne("refused-exp-before-iat", "exp one second before iat (not yet expired at the time of presentation).", refuse("lifetime"),
		b.forge(b.keyA, b.header(b.kidA), b.claims(good, func(c map[string]any) { c["exp"] = b.t0.Add(-time.Second).Unix() })), ok)
	b.forgedOne("refused-no-expiry", "No exp claim.", refuse("expired"),
		b.forge(b.keyA, b.header(b.kidA), b.claims(good, func(c map[string]any) { delete(c, "exp") })), ok)
	b.forgedOne("refused-no-issued-at", "No iat claim.", refuse("issued_in_future"),
		b.forge(b.keyA, b.header(b.kidA), b.claims(good, func(c map[string]any) { delete(c, "iat") })), ok)

	// --- refusals: the claims
	b.forgedOne("refused-empty-subject", "sub is the empty string.", refuse("missing_claim"),
		b.forge(b.keyA, b.header(b.kidA), b.claims(good, func(c map[string]any) { c["sub"] = "" })), ok)
	b.forgedOne("refused-empty-jti", "jti is the empty string.", refuse("missing_claim"),
		b.forge(b.keyA, b.header(b.kidA), b.claims(good, func(c map[string]any) { c["jti"] = "" })), ok)
	b.forgedOne("refused-no-jti", "No jti claim.", refuse("missing_claim"),
		b.forge(b.keyA, b.header(b.kidA), b.claims(good, func(c map[string]any) { delete(c, "jti") })), ok)
	b.forgedOne("refused-no-request-digest", "No req claim.", refuse("request_mismatch"),
		b.forge(b.keyA, b.header(b.kidA), b.claims(good, func(c map[string]any) { delete(c, "req") })), ok)

	// --- refusals: the request
	changed := b.request()
	changed["arguments"] = json.RawMessage(`{"workspaceId":"0123456789abcdef0123456789abcdef","language":"python","code":"exfiltrate('<a> & é')","timeoutSeconds":5.0}`)
	step := b.step("tools/call", b.withAssertion(changed, goodParamsAssertion(t, goodParams)), ok, refuse("request_mismatch"))
	step.SignedRequest = &vectorRequest{Method: "tools/call", Params: mustJSON(t, req)}
	b.add("refused-params-changed-after-signing", "gateway", "The gateway's assertion presented with other arguments than the ones it signed.", step)

	step = b.step("tools/call", b.signed(b.signerA, operator, vectorsAudience, "resources/read", req), ok, refuse("request_mismatch"))
	step.SignedRequest = &vectorRequest{Method: "resources/read", Params: mustJSON(t, req)}
	b.add("refused-another-method-than-signed", "gateway", "An assertion the gateway made for resources/read, presented on tools/call with the same params.", step)

	// --- refusals: replay
	b.add("refused-replay", "gateway", "The same assertion presented twice: the first is accepted, the second is refused.",
		b.step("tools/call", goodParams, ok, accept(operator)),
		b.step("tools/call", goodParams, b.at(25*time.Second), refuse("replay")))
	other := b.request()
	other["arguments"] = json.RawMessage(`{"workspaceId":"0123456789abcdef0123456789abcdef","language":"python","code":"print(2)","timeoutSeconds":5.0}`)
	reused := b.claims(good, func(c map[string]any) { c["jti"] = "forged-reused" })
	reused2 := b.claims(b.digest("tools/call", other), func(c map[string]any) { c["jti"] = "forged-reused" })
	b.add("refused-replay-of-an-id-on-another-request", "forged", "A jti is spent for every request: a second assertion with the same jti is refused although it is for a different request.",
		b.step("tools/call", b.withAssertion(b.request(), b.forge(b.keyA, b.header(b.kidA), reused)), ok, accept(operator)),
		b.step("tools/call", b.withAssertion(other, b.forge(b.keyA, b.header(b.kidA), reused2)), b.at(25*time.Second), refuse("replay")))
	return b.cases
}

// forgeP384 signs ES384 (r || s, 48 bytes each) with a P-384 key.
func (b *vectorBuilder) forgeP384(k *ecdsa.PrivateKey, header, claims map[string]any) string {
	input := b.compact(header, claims)
	sum := sha512.Sum384([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, k, sum[:])
	if err != nil {
		b.t.Fatal(err)
	}
	sig := make([]byte, 96)
	r.FillBytes(sig[:48])
	s.FillBytes(sig[48:])
	return input + "." + b64(sig)
}

func goodParamsAssertion(t *testing.T, params map[string]json.RawMessage) string {
	t.Helper()
	var meta map[string]json.RawMessage
	var a string
	if json.Unmarshal(params["_meta"], &meta) != nil || json.Unmarshal(meta[MetaCallerAssertion], &a) != nil || a == "" {
		t.Fatal("no assertion in the params")
	}
	return a
}

func encodePEM(t *testing.T, k *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func generateVectors(t *testing.T) []byte {
	t.Helper()
	b := &vectorBuilder{t: t, t0: time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)}
	b.keyA, b.keyB, b.keyC = b.key(), b.key(), b.key()
	b.signerA, b.signerB = b.signerFor(b.keyA), b.signerFor(b.keyB)
	b.kidA, b.kidB, b.kidC = b.signerA.KeyID(), b.signerB.KeyID(), ""
	b.kidC, _ = KeyID(&b.keyC.PublicKey)
	f := vectorFile{Format: vectorsFormat, GeneratedBy: vectorsBy, Audience: vectorsAudience,
		Keys:  []vectorKey{{"gateway", b.kidA, encodePEM(t, &b.keyA.PublicKey)}, {"gateway-next", b.kidB, encodePEM(t, &b.keyB.PublicKey)}},
		Cases: b.build()}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestCallerVectorsAreGeneratedAndTheSignerMadeTheirGoodCases(t *testing.T) {
	if *updateVectors {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorsPath, generateVectors(t), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("%v; run: go test ./internal/gateway -run TestCallerVectors -update", err)
	}
	if bytes.Contains(raw, []byte("PRIVATE")) {
		t.Fatal("the vector file holds a private key")
	}
	var f vectorFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Format != vectorsFormat || f.Audience == "" || len(f.Keys) < 2 || len(f.Cases) == 0 {
		t.Fatalf("format %q audience %q keys %d cases %d", f.Format, f.Audience, len(f.Keys), len(f.Cases))
	}
	keys := map[string]*ecdsa.PublicKey{}
	for _, k := range f.Keys {
		block, _ := pem.Decode([]byte(k.PEM))
		if block == nil || block.Type != "PUBLIC KEY" {
			t.Fatalf("key %s is not a PEM public key", k.Name)
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		ec, ok := pub.(*ecdsa.PublicKey)
		if err != nil || !ok {
			t.Fatalf("key %s: %v", k.Name, err)
		}
		if kid, _ := KeyID(ec); kid != k.KeyID {
			t.Fatalf("key %s has kid %s, the file says %s", k.Name, kid, k.KeyID)
		}
		keys[k.KeyID] = ec
	}

	seen := map[string]bool{}
	gateway := 0
	for _, c := range f.Cases {
		if seen[c.Name] || c.Name == "" || c.Description == "" || len(c.Steps) == 0 || (c.Origin != "gateway" && c.Origin != "forged") {
			t.Fatalf("case %q is not well formed", c.Name)
		}
		seen[c.Name] = true
		for i, s := range c.Steps {
			where := fmt.Sprintf("%s step %d", c.Name, i+1)
			if _, err := time.Parse(time.RFC3339, s.Now); err != nil || s.Method == "" {
				t.Fatalf("%s: method %q now %q", where, s.Method, s.Now)
			}
			switch s.Expect.Outcome {
			case "accept":
				if s.Expect.Caller == nil || s.Expect.Reason != "" || s.Expect.Caller.Roles == nil {
					t.Fatalf("%s: an acceptance names the caller, with roles as a list, and no reason", where)
				}
			case "refuse":
				if !vectorReasons[s.Expect.Reason] || s.Expect.Caller != nil {
					t.Fatalf("%s: a refusal has one of the known reasons and no caller, not %q", where, s.Expect.Reason)
				}
			default:
				t.Fatalf("%s: outcome %q", where, s.Expect.Outcome)
			}
			if c.Origin != "gateway" {
				continue
			}
			gateway++
			checkGatewayStep(t, where, s, keys, f.Audience)
		}
	}
	if gateway == 0 {
		t.Fatal("no case was made by the gateway")
	}
}

// checkGatewayStep holds the signer to what the file says of it: the signature verifies under the key of its kid, the
// header and the lifetime are the signer's, req is RequestDigest of the request it signed, and the caller the file
// expects is the one it put in the claims.
func checkGatewayStep(t *testing.T, where string, s vectorStep, keys map[string]*ecdsa.PublicKey, audience string) {
	t.Helper()
	params := map[string]json.RawMessage{}
	if err := json.Unmarshal(s.Params, &params); err != nil {
		t.Fatalf("%s: %v", where, err)
	}
	var meta map[string]json.RawMessage
	var assertion string
	if json.Unmarshal(params["_meta"], &meta) != nil || json.Unmarshal(meta[MetaCallerAssertion], &assertion) != nil || assertion == "" {
		t.Fatalf("%s: a gateway case carries its assertion", where)
	}
	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(assertion, claims, func(tk *jwt.Token) (any, error) {
		kid, _ := tk.Header["kid"].(string)
		if keys[kid] == nil {
			return nil, fmt.Errorf("kid %q is not in the file", kid)
		}
		return keys[kid], nil
	}, jwt.WithValidMethods([]string{"ES256"}), jwt.WithoutClaimsValidation())
	if err != nil || !tok.Valid {
		t.Fatalf("%s: the signature does not verify: %v", where, err)
	}
	if tok.Header["typ"] != CallerAssertionType {
		t.Fatalf("%s: header %v", where, tok.Header)
	}
	iat, exp := int64(claims["iat"].(float64)), int64(claims["exp"].(float64))
	if exp-iat != int64(CallerAssertionTTL/time.Second) || claims["jti"] == "" || claims["iss"] != "idp-mcp-gateway:g1" {
		t.Fatalf("%s: claims %v", where, claims)
	}
	signed := vectorRequest{Method: s.Method, Params: s.Params}
	if s.SignedRequest != nil {
		signed = *s.SignedRequest
	}
	signedParams := map[string]json.RawMessage{}
	if err := json.Unmarshal(signed.Params, &signedParams); err != nil {
		t.Fatalf("%s: %v", where, err)
	}
	if want, err := RequestDigest(signed.Method, signedParams); err != nil || claims["req"] != want {
		t.Fatalf("%s: req %v, RequestDigest of the request it was made for is %s (%v)", where, claims["req"], want, err)
	}
	if s.SignedRequest == nil {
		// presented as signed: when it names an audience that is this file's, the file expects what the claims say
		if s.Expect.Outcome == "accept" {
			got := vectorCaller{Subject: str(claims["sub"]), Tenant: str(claims["tenant_id"]), Roles: []string{}, Client: str(claims["client"]), Actor: str(claims["actor"])}
			if rs, _ := claims["roles"].([]any); rs != nil {
				for _, r := range rs {
					got.Roles = append(got.Roles, str(r))
				}
			}
			if claims["aud"] != audience || !reflect.DeepEqual(got, *s.Expect.Caller) {
				t.Fatalf("%s: the assertion names %+v for %v, the file expects %+v", where, got, claims["aud"], *s.Expect.Caller)
			}
		}
	}
}

func str(v any) string { s, _ := v.(string); return s }
