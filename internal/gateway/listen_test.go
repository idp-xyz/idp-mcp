package gateway

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"idp-mcp/internal/release"
	"idp-mcp/internal/server"
)

type stream struct {
	frames chan map[string]any
	cancel context.CancelFunc
}

func openListen(t *testing.T, h *harness, key, filter string) *stream {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	body := `{"jsonrpc":"2.0","id":"sub-1","method":"subscriptions/listen","params":{"notifications":` + filter + `,` + metaJSON + `}}`
	req, _ := http.NewRequestWithContext(ctx, "POST", h.srv.URL+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set(server.HeaderProtocolVersion, server.ProtocolVersion)
	req.Header.Set(server.HeaderMethod, "subscriptions/listen")
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		cancel()
		t.Fatalf("listen: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	s := &stream{frames: make(chan map[string]any, 32), cancel: cancel}
	go func() {
		defer resp.Body.Close()
		defer close(s.frames)
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if line := sc.Text(); strings.HasPrefix(line, "data: ") {
				var m map[string]any
				_ = json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &m)
				s.frames <- m
			}
		}
	}()
	t.Cleanup(cancel)
	return s
}

func (s *stream) next(t *testing.T, within time.Duration) map[string]any {
	t.Helper()
	select {
	case f, ok := <-s.frames:
		if !ok {
			t.Fatal("stream ended")
		}
		return f
	case <-time.After(within):
		t.Fatal("no frame in time")
	}
	return nil
}

func (s *stream) quiet(t *testing.T, within time.Duration) {
	t.Helper()
	select {
	case f, ok := <-s.frames:
		if ok {
			t.Fatalf("unexpected frame %v", f)
		}
	case <-time.After(within):
	}
}

func subID(f map[string]any) any {
	p, _ := f["params"].(map[string]any)
	m, _ := p["_meta"].(map[string]any)
	return m[MetaSubscriptionID]
}

func TestListenAcknowledgesAndNotifiesOnReleaseChange(t *testing.T) {
	a := newRich(t, "alpha")
	h := richHarness(t, richRelease(t, release.NamingPrefixed, a))
	s := openListen(t, h, operatorKey, `{"toolsListChanged":true}`)
	ack := s.next(t, 2*time.Second)
	if ack["method"] != "notifications/subscriptions/acknowledged" || subID(ack) != "sub-1" {
		t.Fatalf("ack %v", ack)
	}
	honoured := ack["params"].(map[string]any)["notifications"].(map[string]any)
	if honoured["toolsListChanged"] != true || honoured["promptsListChanged"] != nil {
		t.Fatalf("honoured %v", honoured)
	}
	// an upstream list change is drift, not a gateway list change: nothing on the stream
	a.events <- `{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{}}`
	s.quiet(t, 300*time.Millisecond)
	// a new release is: tools/list_changed, tagged; prompts were not requested
	env := richRelease(t, release.NamingPrefixed, a)
	if err := h.g.Activate(withReleaseID(t, env, "r2")); err != nil {
		t.Fatal(err)
	}
	n := s.next(t, 2*time.Second)
	if n["method"] != "notifications/tools/list_changed" || subID(n) != "sub-1" {
		t.Fatalf("%v", n)
	}
	s.quiet(t, 300*time.Millisecond)
}

func TestListenRelaysOnlySubscribedResourcesTheCallerMayRead(t *testing.T) {
	a := newRich(t, "alpha")
	h := richHarness(t, richRelease(t, release.NamingPrefixed, a))
	s := openListen(t, h, operatorKey, `{"resourcesListChanged":true,"resourceSubscriptions":["alpha://static"]}`)
	ack := s.next(t, 2*time.Second)
	honoured := ack["params"].(map[string]any)["notifications"].(map[string]any)
	if honoured["resourcesListChanged"] != true || len(honoured["resourceSubscriptions"].([]any)) != 1 {
		t.Fatalf("honoured %v", honoured)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(a.listenParams()) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	a.events <- `{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"alpha://other"}}`
	a.events <- `{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"alpha://static"}}`
	a.events <- `{"jsonrpc":"2.0","method":"notifications/resources/list_changed","params":{}}`
	got := []map[string]any{s.next(t, 2*time.Second), s.next(t, 2*time.Second)}
	if got[0]["method"] != "notifications/resources/updated" || got[0]["params"].(map[string]any)["uri"] != "alpha://static" || subID(got[0]) != "sub-1" {
		t.Fatalf("%v", got[0])
	}
	if got[1]["method"] != "notifications/resources/list_changed" || subID(got[1]) != "sub-1" {
		t.Fatalf("%v", got[1])
	}
	s.quiet(t, 300*time.Millisecond) // alpha://other was never subscribed
}

func TestListenNeverExtendsAccess(t *testing.T) {
	a := newRich(t, "alpha")
	h := richHarness(t, richRelease(t, release.NamingPrefixed, a))
	// the viewer may not read resources: subscriptions are dropped and no relay is opened
	s := openListen(t, h, viewerKey, `{"resourcesListChanged":true,"resourceSubscriptions":["alpha://static"],"toolsListChanged":true}`)
	honoured := s.next(t, 2*time.Second)["params"].(map[string]any)["notifications"].(map[string]any)
	if _, ok := honoured["resourceSubscriptions"]; ok || honoured["resourcesListChanged"] != nil {
		t.Fatalf("viewer honoured %v", honoured)
	}
	time.Sleep(200 * time.Millisecond)
	if n := len(a.listenParams()); n != 0 {
		t.Fatalf("%d relays opened for a caller without resource grants", n)
	}
	// unauthenticated listen is refused like any request
	if r := h.rpc(t, "", "subscriptions/listen", `{"notifications":{"toolsListChanged":true},`+metaJSON+`}`, nil); r.status != 401 {
		t.Fatalf("anonymous listen: %d", r.status)
	}
}

func TestListenEndsWhenTheCredentialIsGone(t *testing.T) {
	a := newRich(t, "alpha")
	h := richHarness(t, richRelease(t, release.NamingPrefixed, a))
	s := openListen(t, h, viewerKey, `{"promptsListChanged":true}`)
	s.next(t, 2*time.Second)
	// the next release drops the viewer's key: the stream ends with its result
	env := richRelease(t, release.NamingPrefixed, a)
	var d release.Document
	_ = json.Unmarshal(env.Document, &d)
	d.ReleaseID = "r2"
	d.Auth.APIKeys = d.Auth.APIKeys[:1]
	env2, err := release.Seal(&d)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.g.Activate(env2); err != nil {
		t.Fatal(err)
	}
	end := s.next(t, 2*time.Second)
	if end["id"] != "sub-1" || end["result"] == nil {
		t.Fatalf("expected the final result, got %v", end)
	}
	if _, ok := <-s.frames; ok {
		t.Fatal("stream continued after the credential was revoked")
	}
	if h.g.ListenStreams() != 0 {
		t.Fatalf("%d streams still registered", h.g.ListenStreams())
	}
}

func TestShutdownEndsListenStreams(t *testing.T) {
	a := newRich(t, "alpha")
	h := richHarness(t, richRelease(t, release.NamingPrefixed, a))
	s := openListen(t, h, operatorKey, `{"toolsListChanged":true}`)
	s.next(t, 2*time.Second)
	h.g.Shutdown()
	if end := s.next(t, 2*time.Second); end["result"] == nil {
		t.Fatalf("%v", end)
	}
}

func TestJWTListenEndsAtExpiry(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	}))
	defer jwks.Close()
	a := newRich(t, "alpha")
	env := richRelease(t, release.NamingPrefixed, a)
	var d release.Document
	_ = json.Unmarshal(env.Document, &d)
	d.Auth = release.Auth{Mode: "jwt", JWT: &release.JWT{Issuer: "http://127.0.0.1/idp", Resource: "http://127.0.0.1/mcp", JWKSURL: jwks.URL,
		AuthorizationServers: []string{"http://127.0.0.1/idp"}, TenantClaim: "tenant_id", RolesClaim: "roles"}}
	jenv, err := release.Seal(&d)
	if err != nil {
		t.Fatal(err)
	}
	h := richHarness(t, jenv)
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": "http://127.0.0.1/idp", "aud": "http://127.0.0.1/mcp", "sub": "agent",
		"tenant_id": "t1", "roles": []string{"operator"}, "exp": time.Now().Add(2 * time.Second).Unix()})
	tok.Header["kid"] = "k1"
	signed, _ := tok.SignedString(key)
	start := time.Now()
	s := openListen(t, h, signed, `{"toolsListChanged":true}`)
	s.next(t, 2*time.Second) // acknowledged
	end := s.next(t, 5*time.Second)
	if end["result"] == nil || end["id"] != "sub-1" {
		t.Fatalf("expected the final result at expiry, got %v", end)
	}
	if el := time.Since(start); el < time.Second || el > 4*time.Second {
		t.Fatalf("stream ended after %s, token lifetime was 2s", el)
	}
}

func withReleaseID(t *testing.T, env *release.Envelope, id string) *release.Envelope {
	var d release.Document
	_ = json.Unmarshal(env.Document, &d)
	d.ReleaseID = id
	e, err := release.Seal(&d)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
