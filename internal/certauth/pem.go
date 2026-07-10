package certauth

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

func ParseAndVerifyPEMCertificate(raw string, roots *x509.CertPool, now time.Time) (*x509.Certificate, error) {
	if roots == nil {
		return nil, errors.New("client CA roots not configured")
	}
	decoded := raw
	if strings.Contains(raw, "%") {
		if unescaped, err := url.QueryUnescape(raw); err == nil {
			decoded = unescaped
		}
	}
	block, rest := pem.Decode([]byte(decoded))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid forwarded client certificate")
	}
	if len(strings.TrimSpace(string(rest))) > 0 {
		return nil, errors.New("forwarded client certificate must contain exactly one certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse forwarded client certificate: %w", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, fmt.Errorf("verify forwarded client certificate: %w", err)
	}
	return cert, nil
}
