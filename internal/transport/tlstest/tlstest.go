// Package tlstest issues throwaway certificates for tests: a CA, server certificates for loopback,
// and gateway client certificates with the spiffe://idp-mcp/gateway/<id> URI SAN.
package tlstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CA is a test certificate authority.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	Dir  string
	File string // CA certificate PEM
}

func write(t testing.TB, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// NewCA creates a CA in a temporary directory.
func NewCA(t testing.TB, name string) *CA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	dir := t.TempDir()
	ca := &CA{cert: cert, key: key, Dir: dir, File: filepath.Join(dir, name+"-ca.pem")}
	write(t, ca.File, "CERTIFICATE", der)
	return ca
}

var serial int64 = 100

// Issue writes a leaf certificate and key; returns their paths.
func (ca *CA) Issue(t testing.TB, name string, server bool, uris ...*url.URL) (certFile, keyFile string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial++
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, URIs: uris}
	if server {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		tpl.DNSNames = []string{"localhost"}
	} else {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(ca.Dir, name+".pem"), filepath.Join(ca.Dir, name+"-key.pem")
	write(t, certFile, "CERTIFICATE", der)
	kder, _ := x509.MarshalECPrivateKey(key)
	write(t, keyFile, "EC PRIVATE KEY", kder)
	return certFile, keyFile
}
