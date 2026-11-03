package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// GatewayURIPrefix is the URI SAN prefix of gateway client certificates:
// spiffe://idp-mcp/gateway/<gateway id>.
const GatewayURIPrefix = "spiffe://idp-mcp/gateway/"

func pool(caFile string) (*x509.CertPool, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if caFile == "" {
		return roots, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s: no PEM certificates", caFile)
	}
	return roots, nil
}

// ClientTLS is the TLS configuration of an outbound client: system roots plus caFile (if any), and
// a client certificate for mutual TLS when certFile/keyFile are set. TLS 1.2 is the minimum.
func ClientTLS(caFile, certFile, keyFile string) (*tls.Config, error) {
	roots, err := pool(caFile)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	if (certFile == "") != (keyFile == "") {
		return nil, errors.New("client certificate and key must be set together")
	}
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

// ServerTLS is the TLS configuration of a listener. With clientCAFile, client certificates signed
// by that CA are verified when presented (VerifyClientCertIfGiven); handlers that require one check
// r.TLS themselves, so one listener can serve both the admin API (no client certificate) and the
// gateway-facing API (mutual TLS).
func ServerTLS(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if clientCAFile != "" {
		pem, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, err
		}
		cas := x509.NewCertPool()
		if !cas.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: no PEM certificates", clientCAFile)
		}
		cfg.ClientCAs = cas
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return cfg, nil
}

// GatewayIdentity returns the gateway id of a verified client certificate chain (from its
// spiffe://idp-mcp/gateway/<id> URI SAN), or "" if there is none or more than one.
func GatewayIdentity(state *tls.ConnectionState) string {
	if state == nil || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return ""
	}
	var ids []string
	for _, u := range state.PeerCertificates[0].URIs {
		if s := u.String(); strings.HasPrefix(s, GatewayURIPrefix) {
			ids = append(ids, strings.TrimPrefix(s, GatewayURIPrefix))
		}
	}
	if len(ids) != 1 || ids[0] == "" || strings.Contains(ids[0], "/") {
		return ""
	}
	return ids[0]
}

// GatewayURI is the URI SAN for a gateway's client certificate.
func GatewayURI(gatewayID string) *url.URL {
	u, _ := url.Parse(GatewayURIPrefix + gatewayID)
	return u
}
