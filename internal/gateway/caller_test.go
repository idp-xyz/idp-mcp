package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"idp-mcp/internal/admission"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"idp-mcp/internal/authorization"
	"idp-mcp/internal/release"
	"idp-mcp/internal/server"
)

func harnessWithIdentity(t *testing.T, identity string, signer ...*CallerSigner) *harness {
	t.Helper()
	up := newUpstream(t)
	rec := &recorder{}
	cfg := Config{GatewayID: "g1", Clients: admission.Unrestricted(), Info: server.ServerInfo{Name: "idp-mcp-gateway", Version: "test"}, DevMode: true,
		CallTimeout: 2 * time.Second, Recorder: rec}
	if len(signer) > 0 {
		cfg.CallerSigner = signer[0]
	}
	g := New(cfg)
	if err := g.Activate(buildRelease(t, up.srv.URL+"/mcp", "block", func(d *release.Document) { d.Targets[0].Identity = identity })); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(g.Handler())
	t.Cleanup(srv.Close)
	return &harness{g: g, up: up, rec: rec, srv: srv}
}

func upstreamMeta(t *testing.T, h *harness) map[string]any {
	t.Helper()
	params := h.up.bodies[len(h.up.bodies)-1]["params"].(map[string]any)
	meta, _ := params["_meta"].(map[string]any)
	return meta
}

// A target approved for identity learns who is calling, from the gateway's authentication.
func TestForwardIdentityPassesTheVerifiedCaller(t *testing.T) {
	h := harnessWithIdentity(t, release.IdentityForward)
	forged := `"io.idp.telos/caller":{"subject":"admin","tenant":"someone-else","roles":["root"]},`
	params := `{"name":"minimal__echo","arguments":{"text":"x"},"_meta":{` + forged + `"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}`
	r := h.rpc(t, operatorKey, "tools/call", params, map[string]string{server.HeaderName: "minimal__echo"})
	if r.status != 200 {
		t.Fatalf("%d %s", r.status, r.raw)
	}
	c, _ := upstreamMeta(t, h)[MetaCaller].(map[string]any)
	if c == nil || c["subject"] != "svc-operator" || c["tenant"] != "t1" || len(c["roles"].([]any)) != 1 || c["roles"].([]any)[0] != "operator" {
		t.Fatalf("the upstream got %v, not the authenticated caller", upstreamMeta(t, h))
	}
	if upstreamMeta(t, h)["io.modelcontextprotocol/protocolVersion"] != "2026-07-28" {
		t.Fatal("the client's other _meta keys were lost")
	}
}

// Without the approval nothing is forwarded, and a client cannot forge the key.
func TestNoIdentityIsForwardedByDefaultAndForgeryIsStripped(t *testing.T) {
	h := harnessWithIdentity(t, "")
	forged := `"io.idp.telos/caller":{"subject":"admin","tenant":"t1","roles":["root"]},`
	params := `{"name":"minimal__echo","arguments":{"text":"x"},"_meta":{` + forged + `"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}`
	r := h.rpc(t, operatorKey, "tools/call", params, map[string]string{server.HeaderName: "minimal__echo"})
	if r.status != 200 {
		t.Fatalf("%d %s", r.status, r.raw)
	}
	if _, ok := upstreamMeta(t, h)[MetaCaller]; ok {
		t.Fatalf("a client-supplied caller reached the upstream: %v", upstreamMeta(t, h))
	}
	if strings.Contains(r.raw, "root") {
		t.Fatal("the forged caller came back")
	}
}

func TestStampCallerDoesNotModifyItsInput(t *testing.T) {
	in := map[string]json.RawMessage{"_meta": json.RawMessage(`{"a":1}`), "name": json.RawMessage(`"x"`)}
	out, _ := stampCaller(in, release.IdentityForward, principalForTest(), true, nil, "", "tools/call")
	if string(in["_meta"]) != `{"a":1}` || !strings.Contains(string(out["_meta"]), `"subject":"svc"`) {
		t.Fatalf("%s / %s", in["_meta"], out["_meta"])
	}
	if got, _ := stampCaller(in, "", principalForTest(), true, nil, "", "tools/call"); strings.Contains(string(got["_meta"]), "subject") {
		t.Fatal("identity stamped without approval")
	}
	if got, _ := stampCaller(in, release.IdentityForward, principalForTest(), false, nil, "", "tools/call"); strings.Contains(string(got["_meta"]), "subject") {
		t.Fatal("identity stamped without a verified principal")
	}
}

func principalForTest() authorization.Principal {
	return authorization.Principal{Subject: "svc", Tenant: "t1", Roles: []string{"operator"}}
}

func testSigner(t *testing.T) (*CallerSigner, *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	s, err := NewCallerSigner(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), "idp-mcp-gateway:g1")
	if err != nil {
		t.Fatal(err)
	}
	return s, &key.PublicKey
}

// With a key, the gateway signs the caller it forwards: for this target, for this request, for a minute. The
// upstream can then tell the gateway's word from anyone else's on its network (D44).
func TestForwardedIdentityIsSignedForTheTargetAndTheRequest(t *testing.T) {
	signer, pub := testSigner(t)
	h := harnessWithIdentity(t, release.IdentityForward, signer)
	forged := `"io.idp.telos/caller-assertion":"eyJhbGciOiJub25lIn0.e30.","io.idp.telos/caller":{"subject":"admin","tenant":"x","roles":["root"]},`
	params := `{"name":"minimal__echo","arguments":{"text":"<x> & y","n":1.50},"_meta":{` + forged + `"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}`
	before := time.Now().Unix()
	r := h.rpc(t, operatorKey, "tools/call", params, map[string]string{server.HeaderName: "minimal__echo"})
	if r.status != 200 {
		t.Fatalf("%d %s", r.status, r.raw)
	}
	assertion, _ := upstreamMeta(t, h)[MetaCallerAssertion].(string)
	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(assertion, claims, func(tk *jwt.Token) (any, error) { return pub, nil }, jwt.WithValidMethods([]string{"ES256"}))
	if err != nil || !tok.Valid {
		t.Fatalf("the upstream cannot verify the assertion %q: %v", assertion, err)
	}
	if kid, _ := KeyID(pub); tok.Header["kid"] != kid || tok.Header["typ"] != CallerAssertionType {
		t.Fatalf("header %v", tok.Header)
	}
	endpoint := h.up.srv.URL + "/mcp"
	if claims["sub"] != "svc-operator" || claims["tenant_id"] != "t1" || claims["aud"] != endpoint || claims["iss"] != "idp-mcp-gateway:g1" ||
		len(claims["roles"].([]any)) != 1 || claims["roles"].([]any)[0] != "operator" || claims["jti"] == "" {
		t.Fatalf("claims %v", claims)
	}
	iat, exp := int64(claims["iat"].(float64)), int64(claims["exp"].(float64))
	if iat < before || exp-iat != int64(CallerAssertionTTL/time.Second) {
		t.Fatalf("iat %d exp %d", iat, exp)
	}
	// the digest covers what the upstream received: the native tool name and the arguments, not _meta
	var sent struct {
		Params map[string]json.RawMessage `json:"params"`
	}
	h.up.mu.Lock()
	raw := h.up.raw[len(h.up.raw)-1]
	h.up.mu.Unlock()
	if err := json.Unmarshal(raw, &sent); err != nil {
		t.Fatal(err)
	}
	want, _ := RequestDigest("tools/call", sent.Params)
	if claims["req"] != want || !strings.HasPrefix(want, "sha256:") {
		t.Fatalf("req %v, want %s", claims["req"], want)
	}
	other, _ := RequestDigest("tools/call", map[string]json.RawMessage{"name": json.RawMessage(`"echo"`), "arguments": json.RawMessage(`{"text":"other"}`)})
	if other == want {
		t.Fatal("the digest does not depend on the arguments")
	}
	// a second call gets its own assertion
	h.rpc(t, operatorKey, "tools/call", params, map[string]string{server.HeaderName: "minimal__echo"})
	if again, _ := upstreamMeta(t, h)[MetaCallerAssertion].(string); again == assertion || again == "" {
		t.Fatal("the assertion was reused")
	}
}

// A target that was not approved for identity gets no assertion either, and a client cannot supply one.
func TestNoAssertionWithoutApprovalAndAForgedOneIsStripped(t *testing.T) {
	signer, _ := testSigner(t)
	h := harnessWithIdentity(t, "", signer)
	params := `{"name":"minimal__echo","arguments":{"text":"x"},"_meta":{"io.idp.telos/caller-assertion":"forged","io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}`
	if r := h.rpc(t, operatorKey, "tools/call", params, map[string]string{server.HeaderName: "minimal__echo"}); r.status != 200 {
		t.Fatalf("%d %s", r.status, r.raw)
	}
	if _, ok := upstreamMeta(t, h)[MetaCallerAssertion]; ok {
		t.Fatalf("an assertion reached a target without identity: %v", upstreamMeta(t, h))
	}
	// and without a key a forwarding target still gets the caller, unsigned, and never the client's assertion
	h = harnessWithIdentity(t, release.IdentityForward)
	h.rpc(t, operatorKey, "tools/call", params, map[string]string{server.HeaderName: "minimal__echo"})
	if m := upstreamMeta(t, h); m[MetaCaller] == nil || m[MetaCallerAssertion] != nil {
		t.Fatalf("%v", m)
	}
}

func TestCallerSignerTakesOnlyAP256Key(t *testing.T) {
	k384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(k384)
	if _, err := NewCallerSigner(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), "g"); err == nil {
		t.Fatal("a P-384 key was accepted")
	}
	if _, err := NewCallerSigner([]byte("not a key"), "g"); err == nil {
		t.Fatal("garbage was accepted")
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sec1, _ := x509.MarshalECPrivateKey(k)
	if _, err := NewCallerSigner(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}), "g"); err != nil {
		t.Fatalf("a SEC 1 key (openssl ecparam -genkey) was refused: %v", err)
	}
}

// The digest is of the JSON value, in the canonical form an upstream reproduces without this code. This request and
// its digest are pinned in idp-sandbox too (internal/mcp TestTheGatewaysAssertionIsAccepted), with an assertion this
// signer made for it.
func TestRequestDigestIsTheOneUpstreamsCompute(t *testing.T) {
	const want = "sha256:8851b44519b6c048088bfd66090581b433b7489257501bb2a91e17e0e84a5b33"
	for _, body := range []string{
		`{"name":"sandbox_run","arguments":{"workspaceId":"0123456789abcdef0123456789abcdef","language":"python","code":"print('<a> & é')","timeoutSeconds":5.0},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}`,
		`{ "arguments": {"timeoutSeconds":5.0, "code":"print('<a> & é')", "language":"python","workspaceId":"0123456789abcdef0123456789abcdef"}, "_meta":{"x":1}, "name":"sandbox_run"}`,
	} {
		var params map[string]json.RawMessage
		if err := json.Unmarshal([]byte(body), &params); err != nil {
			t.Fatal(err)
		}
		if got, err := RequestDigest("tools/call", params); err != nil || got != want {
			t.Fatalf("%s %v for %s", got, err, body)
		}
	}
}
