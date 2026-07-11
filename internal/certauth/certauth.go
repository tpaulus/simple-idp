package certauth

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxInfoHeaderLen = 8192

type Config struct {
	TrustedProxyNets      []*net.IPNet
	PEMHeader             string
	InfoHeader            string
	RequirePEM            bool
	RequireInfoCommonName bool
	CARoots               *x509.CertPool
	Now                   func() time.Time
}

type Authenticator struct {
	cfg Config
}

func New(cfg Config) *Authenticator {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Authenticator{cfg: cfg}
}

func (a *Authenticator) Authenticate(r *http.Request) (string, error) {
	if !trustedRemote(r.RemoteAddr, a.cfg.TrustedProxyNets) {
		if r.Header.Get(a.cfg.PEMHeader) != "" || r.Header.Get(a.cfg.InfoHeader) != "" {
			return "", errors.New("forwarded client certificate headers not accepted from untrusted remote")
		}
		return "", errors.New("missing trusted proxy identity")
	}
	var infoCN string
	if raw := r.Header.Get(a.cfg.InfoHeader); raw != "" {
		cn, err := ParseInfoCommonName(raw)
		if err != nil {
			return "", fmt.Errorf("parse forwarded cert info: %w", err)
		}
		infoCN = cn
	} else if a.cfg.RequireInfoCommonName {
		return "", errors.New("missing forwarded cert info header")
	}
	var pemCN string
	if raw := r.Header.Get(a.cfg.PEMHeader); raw != "" {
		cert, err := ParseAndVerifyPEMCertificate(raw, a.cfg.CARoots, a.cfg.Now())
		if err != nil {
			return "", err
		}
		pemCN = cert.Subject.CommonName
	} else if a.cfg.RequirePEM {
		return "", errors.New("missing forwarded client certificate header")
	}
	if infoCN != "" && pemCN != "" && infoCN != pemCN {
		return "", errors.New("forwarded certificate common names mismatch")
	}
	if pemCN != "" {
		return pemCN, nil
	}
	if infoCN != "" {
		return infoCN, nil
	}
	return "", errors.New("client certificate identity unavailable")
}

func trustedRemote(remoteAddr string, cidrs []*net.IPNet) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, cidr := range cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func ParseInfoCommonName(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("empty cert info")
	}
	if len(raw) > maxInfoHeaderLen {
		return "", errors.New("cert info header too large")
	}
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		return "", fmt.Errorf("unescape cert info: %w", err)
	}
	pairs, err := parsePairs(decoded)
	if err != nil {
		return "", err
	}
	subject, ok := pairs["Subject"]
	if !ok {
		return "", errors.New("missing Subject entry")
	}
	return parseDNCommonName(subject)
}

func parsePairs(s string) (map[string]string, error) {
	out := map[string]string{}
	for i := 0; i < len(s); {
		for i < len(s) && (s[i] == ' ' || s[i] == ';' || s[i] == ',') {
			i++
		}
		if i >= len(s) {
			break
		}
		start := i
		for i < len(s) && s[i] != '=' {
			i++
		}
		if i >= len(s) {
			return nil, errors.New("malformed key/value segment")
		}
		key := strings.TrimSpace(s[start:i])
		i++
		if key == "" {
			return nil, errors.New("empty key in cert info")
		}
		var value strings.Builder
		if i < len(s) && s[i] == '"' {
			i++
			for i < len(s) {
				switch s[i] {
				case '\\':
					i++
					if i >= len(s) {
						return nil, errors.New("invalid escape in quoted value")
					}
					value.WriteByte(s[i])
					i++
				case '"':
					i++
					goto done
				default:
					value.WriteByte(s[i])
					i++
				}
			}
			return nil, errors.New("unterminated quoted value")
		} else { //nolint:revive // goto exits the if before this else for quoted values
			for i < len(s) && s[i] != ';' && s[i] != ',' {
				value.WriteByte(s[i])
				i++
			}
		}
	done:
		if _, exists := out[key]; exists {
			if key == "Subject" {
				continue
			}
			return nil, fmt.Errorf("duplicate key %q", key)
		}
		out[key] = strings.TrimSpace(value.String())
	}
	return out, nil
}

func parseDNCommonName(subject string) (string, error) {
	var cn string
	for _, part := range splitEscaped(subject, ',') {
		if strings.TrimSpace(part) == "" {
			continue
		}
		pieces := splitFirstUnescaped(part, '=')
		if len(pieces) != 2 {
			return "", errors.New("malformed subject distinguished name")
		}
		key := strings.TrimSpace(pieces[0])
		value := strings.TrimSpace(unescapeDN(pieces[1]))
		if strings.EqualFold(key, "CN") {
			if cn != "" {
				return "", errors.New("multiple CN values in subject")
			}
			if value == "" {
				return "", errors.New("empty CN value")
			}
			cn = value
		}
	}
	if cn == "" {
		return "", errors.New("subject missing CN")
	}
	return cn, nil
}

func splitEscaped(s string, sep byte) []string {
	parts := []string{}
	var b strings.Builder
	escaped := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if escaped {
			b.WriteByte(ch)
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == sep {
			parts = append(parts, b.String())
			b.Reset()
			continue
		}
		b.WriteByte(ch)
	}
	parts = append(parts, b.String())
	return parts
}

func splitFirstUnescaped(s string, sep byte) []string {
	escaped := false
	for i := 0; i < len(s); i++ {
		if escaped {
			escaped = false
			continue
		}
		if s[i] == '\\' {
			escaped = true
			continue
		}
		if s[i] == sep {
			return []string{s[:i], s[i+1:]}
		}
	}
	return []string{s}
}

func unescapeDN(s string) string {
	var b strings.Builder
	escaped := false
	for i := 0; i < len(s); i++ {
		if escaped {
			b.WriteByte(s[i])
			escaped = false
			continue
		}
		if s[i] == '\\' {
			escaped = true
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
