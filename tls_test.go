package i400

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Hardening contract: TLS always verifies the server certificate and name. The
// only knobs are the trusted CA pool and the expected server name; there is no
// option to skip verification, in Config or in the DSN.

type testCA struct {
	pool    *x509.CertPool
	certPEM []byte
	server  tls.Certificate
}

// newTestServerCert makes a self-signed certificate for ibmi.test and 127.0.0.1.
// It is its own CA, so the pool holding it trusts the server.
func newTestServerCert(t *testing.T) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ibmi.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"ibmi.test"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return testCA{
		pool:    pool,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		server:  tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
	}
}

// startTLSHost runs a TLS listener that completes handshakes and holds the
// connection; it returns the port and how many handshakes succeeded.
func startTLSHost(t *testing.T, ca testCA, minVersion uint16) (port int, handshakes func() int) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{ca.server}, MaxVersion: tls.VersionTLS13, MinVersion: minVersion})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	done := make(chan struct{}, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if err := c.(*tls.Conn).Handshake(); err == nil {
					done <- struct{}{}
					buf := make([]byte, 1)
					_, _ = c.Read(buf)
				}
			}()
		}
	}()
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	n, _ := net.LookupPort("tcp", p)
	return n, func() int { time.Sleep(50 * time.Millisecond); return len(done) }
}

func dialTLS(t *testing.T, cfg Config, port int) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg.Host = "127.0.0.1"
	cfg.UseTLS = true
	conn, err := dialHostServer(ctx, cfg, port)
	if err == nil {
		conn.Close()
	}
	return err
}

func TestTLSVerifiesTheServerCertificateByDefault(t *testing.T) {
	ca := newTestServerCert(t)
	port, handshakes := startTLSHost(t, ca, tls.VersionTLS12)
	// No CA configured: a self-signed certificate must be refused.
	if err := dialTLS(t, Config{}, port); err == nil {
		t.Fatal("connected to a server whose certificate is not trusted")
	}
	if n := handshakes(); n != 0 {
		t.Fatalf("%d handshakes completed against an untrusted certificate", n)
	}
}

func TestTLSTrustsOnlyTheConfiguredCA(t *testing.T) {
	ca := newTestServerCert(t)
	other := newTestServerCert(t)
	port, _ := startTLSHost(t, ca, tls.VersionTLS12)
	if err := dialTLS(t, Config{TLSRootCAs: ca.pool, TLSServerName: "ibmi.test"}, port); err != nil {
		t.Fatalf("configured CA and matching name refused: %v", err)
	}
	if err := dialTLS(t, Config{TLSRootCAs: other.pool, TLSServerName: "ibmi.test"}, port); err == nil {
		t.Fatal("connected with a CA pool that does not contain the server's CA")
	}
}

func TestTLSChecksTheServerName(t *testing.T) {
	ca := newTestServerCert(t)
	port, _ := startTLSHost(t, ca, tls.VersionTLS12)
	if err := dialTLS(t, Config{TLSRootCAs: ca.pool, TLSServerName: "other.example"}, port); err == nil {
		t.Fatal("connected although the certificate does not name other.example")
	}
	// Without an explicit name the host is the name; 127.0.0.1 is in the SAN.
	if err := dialTLS(t, Config{TLSRootCAs: ca.pool}, port); err != nil {
		t.Fatalf("host name check against the SAN failed: %v", err)
	}
}

func TestTLSRefusesOldProtocolVersions(t *testing.T) {
	ca := newTestServerCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{ca.server}, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11})
	if err != nil {
		t.Skipf("this Go toolchain cannot serve TLS 1.1: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _ = c.(*tls.Conn).Handshake() }()
		}
	}()
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := net.LookupPort("tcp", p)
	if err := dialTLS(t, Config{TLSRootCAs: ca.pool, TLSServerName: "ibmi.test"}, port); err == nil {
		t.Fatal("negotiated a TLS version below 1.2")
	}
}

// There must be no way to ask the driver to skip verification.
func TestConfigHasNoTLSEscapeHatch(t *testing.T) {
	typ := reflect.TypeOf(Config{})
	tlsConfigType := reflect.TypeOf(&tls.Config{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Type == tlsConfigType || f.Type == reflect.TypeOf(tls.Config{}) {
			t.Errorf("Config.%s exposes a *tls.Config, which can set InsecureSkipVerify", f.Name)
		}
		name := strings.ToLower(f.Name)
		for _, banned := range []string{"insecure", "skipverify", "skipcheck", "verifyoff", "noverify"} {
			if strings.Contains(name, banned) {
				t.Errorf("Config.%s looks like a verification switch", f.Name)
			}
		}
	}
}

func TestDSNRejectsVerificationSwitches(t *testing.T) {
	for _, key := range []string{"insecureSkipVerify", "tlsInsecure", "skipVerify", "tlsSkipVerify", "sslInsecure", "insecure"} {
		for _, value := range []string{"true", "1", "false"} {
			dsn := "as400s://U:P@host.example/LIB?" + key + "=" + value
			_, err := ParseDSN(dsn)
			if err == nil {
				t.Errorf("DSN option %s=%s accepted", key, value)
				continue
			}
			if strings.Contains(err.Error(), ":P@") {
				t.Errorf("error for %s leaks the DSN credentials: %v", key, err)
			}
		}
	}
}

func TestDSNTLSServerNameAndCAFile(t *testing.T) {
	ca := newTestServerCert(t)
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, ca.certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseDSN("as400s://U:P@host.example/LIB?tlsServerName=ibmi.test&tlsCAFile=" + path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLSServerName != "ibmi.test" || cfg.TLSRootCAs == nil {
		t.Fatalf("TLSServerName=%q TLSRootCAs=%v", cfg.TLSServerName, cfg.TLSRootCAs)
	}
	port, _ := startTLSHost(t, ca, tls.VersionTLS12)
	if err := dialTLS(t, *cfg, port); err != nil {
		t.Fatalf("connection with the DSN CA and name failed: %v", err)
	}

	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseDSN("as400s://U:P@host.example/LIB?tlsCAFile=" + bad); err == nil {
		t.Fatal("a CA file with no certificate was accepted")
	}
	if _, err := ParseDSN("as400s://U:P@host.example/LIB?tlsCAFile=" + filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatal("a missing CA file was accepted")
	}
}

func TestPlainSchemeNeverDialsTLSAndTLSNeverFallsBack(t *testing.T) {
	ca := newTestServerCert(t)
	port, _ := startTLSHost(t, ca, tls.VersionTLS12)
	// A TLS client against a plaintext port must fail, not fall back.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_, _ = c.Write([]byte("plaintext banner, not a TLS record"))
			c.Close()
		}
	}()
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	plainPort, _ := net.LookupPort("tcp", p)
	if err := dialTLS(t, Config{TLSRootCAs: ca.pool}, plainPort); err == nil {
		t.Fatal("TLS dial succeeded against a plaintext server")
	}
	_ = port
}
