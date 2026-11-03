package transport

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"idp-mcp/internal/transport/tlstest"
)

func serve(t *testing.T, cfg *tls.Config) *httptest.Server {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "id="+GatewayIdentity(r.TLS))
	}))
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, cfg *tls.Config, url string) (string, error) {
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, Proxy: nil}}
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), nil
}

func TestMutualTLSIdentity(t *testing.T) {
	ca := tlstest.NewCA(t, "idp")
	other := tlstest.NewCA(t, "other")
	sc, sk := ca.Issue(t, "registry", true)
	srvCfg, err := ServerTLS(sc, sk, ca.File)
	if err != nil {
		t.Fatal(err)
	}
	srv := serve(t, srvCfg)

	// no client certificate: allowed by the listener, but no identity
	plain, _ := ClientTLS(ca.File, "", "")
	if body, err := get(t, plain, srv.URL); err != nil || body != "id=" {
		t.Fatalf("%q %v", body, err)
	}
	// gateway certificate from the trusted CA: identity from the URI SAN
	gc, gk := ca.Issue(t, "gw1", false, GatewayURI("gw-1"))
	mtls, err := ClientTLS(ca.File, gc, gk)
	if err != nil {
		t.Fatal(err)
	}
	if body, err := get(t, mtls, srv.URL); err != nil || body != "id=gw-1" {
		t.Fatalf("%q %v", body, err)
	}
	// a certificate from another CA: Go clients do not even send it (its issuer is not among the
	// server's acceptable CAs), so there is no identity ...
	oc, ok := other.Issue(t, "gw1", false, GatewayURI("gw-1"))
	rogue, _ := ClientTLS(ca.File, oc, ok)
	if body, err := get(t, rogue, srv.URL); err != nil || body != "id=" {
		t.Fatalf("untrusted certificate yielded %q %v", body, err)
	}
	// ... and a client that sends it anyway fails the handshake
	pair, _ := tls.LoadX509KeyPair(oc, ok)
	forced, _ := ClientTLS(ca.File, "", "")
	forced.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &pair, nil }
	if _, err := get(t, forced, srv.URL); err == nil {
		t.Fatal("certificate of an untrusted CA accepted in the handshake")
	}
	// the server certificate must chain to the configured CA
	sys, _ := ClientTLS("", "", "")
	if _, err := get(t, sys, srv.URL); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("unknown server CA accepted: %v", err)
	}
	// two gateway URIs: ambiguous, no identity
	tc, tk := ca.Issue(t, "two", false, GatewayURI("a"), GatewayURI("b"))
	two, _ := ClientTLS(ca.File, tc, tk)
	if body, _ := get(t, two, srv.URL); body != "id=" {
		t.Fatalf("ambiguous identity accepted: %q", body)
	}
}

func TestClientTLSNeedsCertAndKeyTogether(t *testing.T) {
	if _, err := ClientTLS("", "cert.pem", ""); err == nil {
		t.Fatal("cert without key accepted")
	}
	if _, err := ClientTLS("/nonexistent/ca.pem", "", ""); err == nil {
		t.Fatal("missing CA file accepted")
	}
}
