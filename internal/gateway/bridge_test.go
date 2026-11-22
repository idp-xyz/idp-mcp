package gateway

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"idp-mcp/internal/invocation"
	"idp-mcp/internal/server"
	"idp-mcp/tests/fixtures/hostileserver"
)

// The tests of ADR-0001 D51 a as revised: a target of class external at a bridge address (IDP_BRIDGE_ENDPOINTS) gets
// the gateway's signed caller assertion and nothing else of the caller; any other external target gets nothing; and
// the platform's own keys of a result are removed unless the answer comes from a bridge.

// verifyAssertion holds an assertion to the rules of the shared vectors (idp-contracts/vectors/caller-assertion):
// ES256 under the gateway's key, typ and kid, aud = the endpoint, a lifetime of a minute, a jti, and req = the digest
// of the method and the params as the upstream received them, without _meta. It returns the claims.
func verifyAssertion(t *testing.T, signer *CallerSigner, got hostileserver.Received, endpoint string) jwt.MapClaims {
	t.Helper()
	meta, _ := got.Params["_meta"].(map[string]any)
	assertion, _ := meta[MetaCallerAssertion].(string)
	if assertion == "" {
		t.Fatalf("no assertion in %v", meta)
	}
	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(assertion, claims, func(*jwt.Token) (any, error) { return &signer.key.PublicKey, nil },
		jwt.WithValidMethods([]string{"ES256"}), jwt.WithAudience(endpoint), jwt.WithIssuer("idp-mcp-gateway:g1"), jwt.WithExpirationRequired())
	if err != nil || !tok.Valid {
		t.Fatalf("the bridge cannot verify the assertion: %v", err)
	}
	if tok.Header["typ"] != CallerAssertionType || tok.Header["kid"] != signer.kid {
		t.Fatalf("header %v", tok.Header)
	}
	iat, exp := int64(claims["iat"].(float64)), int64(claims["exp"].(float64))
	if exp-iat != int64(CallerAssertionTTL.Seconds()) || claims["jti"] == "" {
		t.Fatalf("claims %v", claims)
	}
	var sent struct {
		Params map[string]json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(got.Body, &sent); err != nil {
		t.Fatal(err)
	}
	if want, _ := RequestDigest("tools/call", sent.Params); claims["req"] != want {
		t.Fatalf("req %v, want %s", claims["req"], want)
	}
	return claims
}

func TestABridgeTargetReceivesTheSignedAssertionAndNothingElseOfTheCaller(t *testing.T) {
	signer, _ := testSigner(t)
	h := newExtHarness(t, extOptions{signer: signer, bridgeExt: true})
	r := h.call(t, hostKey, "ext__search", `{"query":"acme"}`, map[string]string{"traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"})
	if !isOK(r) {
		t.Fatalf("%s", r.raw)
	}
	calls := h.ext.Calls()
	if len(calls) != 1 {
		t.Fatalf("%d calls", len(calls))
	}
	claims := verifyAssertion(t, signer, calls[0], h.ext.URL())
	if claims["sub"] != "svc-host" || claims["tenant_id"] != "t1" || len(claims["roles"].([]any)) != 1 || claims["roles"].([]any)[0] != "operator" {
		t.Fatalf("claims %v", claims)
	}
	// the _meta is the allow-list and the assertion, nothing more
	meta, _ := calls[0].Params["_meta"].(map[string]any)
	keys := map[string]bool{}
	for k := range meta {
		keys[k] = true
	}
	want := map[string]bool{server.MetaProtocolVersion: true, server.MetaClientCapabilities: true, MetaProgressToken: true, MetaCallerAssertion: true}
	if fmt.Sprint(keys) != fmt.Sprint(want) {
		t.Errorf("_meta keys %v, want %v", keys, want)
	}
	for hd := range calls[0].Header {
		if k := strings.ToLower(hd); strings.Contains(k, "trace") || k == "authorization" || k == "cookie" {
			t.Errorf("header %s reached the bridge", hd)
		}
	}
	// the plain caller, the client's own keys and the rest of the client's _meta are still not sent: the only place
	// the subject may appear is inside the signed assertion
	body := string(calls[0].Body)
	body = strings.Replace(body, meta[MetaCallerAssertion].(string), "", 1)
	for _, secret := range []string{"svc-host", "t1", "operator", "io.idp.telos/caller\"", "forged", "idp-host-test-client", "9.9", "0af7651916cd43dd8448eb211c80319c", "secret-session-id", "sampling", "clientInfo"} {
		if strings.Contains(body, secret) {
			t.Errorf("the bridge received %q beside the assertion", secret)
		}
	}
	// every call has its own assertion
	h.call(t, hostKey, "ext__search", `{"query":"again"}`, nil)
	again := h.ext.Calls()[1]
	if a, _ := again.Params["_meta"].(map[string]any)[MetaCallerAssertion].(string); a == "" || a == meta[MetaCallerAssertion] {
		t.Error("the assertion was reused or missing")
	}
	// an internal target next to it behaves as before: no assertion without the identity mode
	h.call(t, hostKey, "int__search", `{"query":"acme"}`, nil)
	if h.in.Saw("caller-assertion") {
		t.Error("an internal target without identity was sent an assertion")
	}
}

func TestABridgeTargetIsNotCalledWithoutASignerAndCarriesNoIdentityThen(t *testing.T) {
	h := newExtHarness(t, extOptions{bridgeExt: true}) // no caller key
	r := h.call(t, hostKey, "ext__search", `{"query":"acme"}`, nil)
	if isOK(r) || len(h.ext.Calls()) != 0 {
		t.Fatalf("a bridge call went out without a signature: %s", r.raw)
	}
	if rec := h.rec.last(); rec.Outcome != invocation.OutcomeNotDelivered {
		t.Fatalf("outcome %s", rec.Outcome)
	}
}

func TestAnExternalTargetThatIsNotAtABridgeAddressStillReceivesNoAssertion(t *testing.T) {
	signer, _ := testSigner(t)
	h := newExtHarness(t, extOptions{signer: signer, bridges: "bridge.idp.svc"})
	if r := h.call(t, hostKey, "ext__search", `{"query":"acme"}`, nil); !isOK(r) {
		t.Fatalf("%s", r.raw)
	}
	if h.ext.Saw("caller-assertion") || h.ext.Saw("svc-host") || h.ext.Saw("tenant") {
		t.Fatal("a third party's server was sent the caller")
	}
}

func TestTheKeysOfThePlatformAreRemovedFromAnExternalResultButNotFromABridges(t *testing.T) {
	signer, _ := testSigner(t)
	for _, b := range []hostileserver.Behavior{hostileserver.Marked, hostileserver.MarkedStream} {
		t.Run(fmt.Sprint(b), func(t *testing.T) {
			third := newExtHarness(t, extOptions{signer: signer, bridges: "bridge.idp.svc"})
			third.ext.SetBehavior(b, 0, 0)
			r := third.call(t, hostKey, "ext__search", `{"query":"x"}`, nil)
			if !strings.Contains(r.raw, `"rows":3`) || !strings.Contains(r.raw, "com.example/k") {
				t.Fatalf("the keys that are not ours were lost: %s", r.raw)
			}
			if strings.Contains(r.raw, "io.idp.telos/") || strings.Contains(r.raw, "authorizationRequired") {
				t.Fatalf("a key of the platform reached the client from a third party: %s", r.raw)
			}
			ours := newExtHarness(t, extOptions{signer: signer, bridgeExt: true})
			ours.ext.SetBehavior(b, 0, 0)
			r = ours.call(t, hostKey, "ext__search", `{"query":"x"}`, nil)
			if !strings.Contains(r.raw, `"io.idp.telos/authorizationRequired":{"connection":"evil"}`) || !strings.Contains(r.raw, `"io.idp.telos/external":false`) {
				t.Fatalf("the bridge's keys did not pass: %s", r.raw)
			}
			// an internal target is not touched either
			third.in.SetBehavior(b, 0, 0)
			r = third.call(t, hostKey, "int__search", `{"query":"x"}`, nil)
			if !strings.Contains(r.raw, "io.idp.telos/authorizationRequired") {
				t.Fatalf("an internal target's result was changed: %s", r.raw)
			}
		})
	}
}

func TestStripOurKeysLeavesAnythingElseAsItWas(t *testing.T) {
	plain := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[],"structuredContent":{"a":1},"_meta":{"b":2}}}`)
	if got := stripOurKeys(plain); string(got) != string(plain) {
		t.Fatalf("%s", got)
	}
	if got := stripOurKeys([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"io.idp.telos/x"}}`)); !strings.Contains(string(got), "io.idp.telos/x") {
		t.Fatal("an error was changed")
	}
	got := stripOurKeys([]byte(`{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"io.idp.telos/a":1,"b":2},"_meta":{"io.idp.telos/c":1,"io.idp.telos/d":2}}}`))
	if string(got) != `{"id":1,"jsonrpc":"2.0","result":{"_meta":{},"structuredContent":{"b":2}}}` {
		t.Fatalf("%s", got)
	}
}
