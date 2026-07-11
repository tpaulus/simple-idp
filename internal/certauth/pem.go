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
		if unescaped, err := url.PathUnescape(raw); err == nil {
			decoded = normalizePEMMarkers(unescaped)
		}
	}
	decoded = normalizeForwardedPEM(decoded)
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

func normalizePEMMarkers(value string) string {
	value = strings.ReplaceAll(value, "-----BEGIN+CERTIFICATE-----", "-----BEGIN CERTIFICATE-----")
	value = strings.ReplaceAll(value, "-----END+CERTIFICATE-----", "-----END CERTIFICATE-----")
	return value
}

func normalizeForwardedPEM(value string) string {
	value = strings.TrimSpace(value)
	if before, _, ok := strings.Cut(value, ","); ok {
		value = strings.TrimSpace(before)
	}
	if strings.Contains(value, "-----BEGIN CERTIFICATE-----") {
		return value
	}
	compact := strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', '\t', ' ':
			return -1
		default:
			return r
		}
	}, value)
	if compact == "" {
		return value
	}
	var b strings.Builder
	b.WriteString("-----BEGIN CERTIFICATE-----\n")
	for len(compact) > 64 {
		b.WriteString(compact[:64])
		b.WriteByte('\n')
		compact = compact[64:]
	}
	b.WriteString(compact)
	b.WriteString("\n-----END CERTIFICATE-----\n")
	return b.String()
}
