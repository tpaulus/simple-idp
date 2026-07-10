package certauth

import (
	"crypto/x509"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tpaulus/simple-idp/internal/testutil"
)

func TestParseInfoCommonName(t *testing.T) {
	header := url.QueryEscape(`Subject="CN=tom-laptop,OU=Home";URI="spiffe://example"`)
	cn, err := ParseInfoCommonName(header)
	if err != nil {
		t.Fatalf("parse info: %v", err)
	}
	if cn != "tom-laptop" {
		t.Fatalf("unexpected CN %q", cn)
	}
}

func TestParseInfoCommonNameRejectsDuplicateSubject(t *testing.T) {
	_, err := ParseInfoCommonName(url.QueryEscape(`Subject="CN=tom-laptop";Subject="CN=mel-laptop"`))
	if err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("expected duplicate key error, got %v", err)
	}
}

func TestParseAndVerifyPEMCertificate(t *testing.T) {
	ca, key, caPEM := testutil.MustGenerateCA(t)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(caPEM))
	certPEM := testutil.MustGenerateClientCert(t, ca, key, "tom-laptop", time.Now().Add(-time.Minute), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	cert, err := ParseAndVerifyPEMCertificate(certPEM, roots, time.Now())
	if err != nil {
		t.Fatalf("verify certificate: %v", err)
	}
	if cert.Subject.CommonName != "tom-laptop" {
		t.Fatalf("unexpected CN %q", cert.Subject.CommonName)
	}
}

func TestParseAndVerifyPEMCertificateAcceptsTraefikHeaderPEM(t *testing.T) {
	ca, key, caPEM := testutil.MustGenerateCA(t)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(caPEM))
	certPEM := testutil.MustGenerateClientCert(t, ca, key, "tom-laptop", time.Now().Add(-time.Minute), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	traefikPEM := strings.NewReplacer(
		"-----BEGIN CERTIFICATE-----", "",
		"-----END CERTIFICATE-----", "",
		"\n", "",
		"\r", "",
	).Replace(certPEM)

	cert, err := ParseAndVerifyPEMCertificate(url.QueryEscape(traefikPEM), roots, time.Now())
	if err != nil {
		t.Fatalf("verify Traefik certificate header: %v", err)
	}
	if cert.Subject.CommonName != "tom-laptop" {
		t.Fatalf("unexpected CN %q", cert.Subject.CommonName)
	}
}

func TestParseAndVerifyPEMCertificateRejectsExpiredCertificate(t *testing.T) {
	ca, key, caPEM := testutil.MustGenerateCA(t)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(caPEM))
	certPEM := testutil.MustGenerateClientCert(t, ca, key, "tom-laptop", time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	if _, err := ParseAndVerifyPEMCertificate(certPEM, roots, time.Now()); err == nil {
		t.Fatal("expected expired certificate to fail")
	}
}

func TestParseAndVerifyPEMCertificateRejectsWrongEKU(t *testing.T) {
	ca, key, caPEM := testutil.MustGenerateCA(t)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(caPEM))
	certPEM := testutil.MustGenerateClientCert(t, ca, key, "tom-laptop", time.Now().Add(-time.Minute), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if _, err := ParseAndVerifyPEMCertificate(certPEM, roots, time.Now()); err == nil {
		t.Fatal("expected wrong EKU to fail")
	}
}

func TestAuthenticatorRejectsCommonNameMismatch(t *testing.T) {
	ca, key, caPEM := testutil.MustGenerateCA(t)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(caPEM))
	certPEM := testutil.MustGenerateClientCert(t, ca, key, "tom-laptop", time.Now().Add(-time.Minute), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	auth := New(Config{
		TrustedProxyNets:      mustCIDRs(t, "127.0.0.0/8"),
		PEMHeader:             "X-Forwarded-Tls-Client-Cert",
		InfoHeader:            "X-Forwarded-Tls-Client-Cert-Info",
		RequirePEM:            true,
		RequireInfoCommonName: true,
		CARoots:               roots,
	})
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/authorize", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-Tls-Client-Cert", url.QueryEscape(certPEM))
	req.Header.Set("X-Forwarded-Tls-Client-Cert-Info", url.QueryEscape(`Subject="CN=mel-laptop"`))
	if _, err := auth.Authenticate(req); err == nil {
		t.Fatal("expected CN mismatch to fail")
	}
}

func TestAuthenticatorRejectsSpoofedHeadersFromUntrustedRemote(t *testing.T) {
	auth := New(Config{PEMHeader: "X-Forwarded-Tls-Client-Cert", InfoHeader: "X-Forwarded-Tls-Client-Cert-Info"})
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/authorize", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("X-Forwarded-Tls-Client-Cert-Info", url.QueryEscape(`Subject="CN=tom-laptop"`))
	if _, err := auth.Authenticate(req); err == nil {
		t.Fatal("expected spoofed header rejection")
	}
}

func mustCIDRs(t *testing.T, values ...string) []*net.IPNet {
	t.Helper()
	cidrs := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, cidr, err := net.ParseCIDR(value)
		if err != nil {
			t.Fatalf("parse cidr %q: %v", value, err)
		}
		cidrs = append(cidrs, cidr)
	}
	return cidrs
}
