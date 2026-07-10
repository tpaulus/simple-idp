package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"gopkg.in/yaml.v3"
)

const redacted = "REDACTED"

type Config struct {
	Issuer              string              `yaml:"issuer"`
	Endpoints           Endpoints           `yaml:"endpoints"`
	HTTP                HTTP                `yaml:"http"`
	ForwardedClientCert ForwardedClientCert `yaml:"forwardedClientCert"`
	OAuth               OAuth               `yaml:"oauth"`
	SigningKeys         []SigningKey        `yaml:"signingKeys"`
	Clients             []Client            `yaml:"clients"`
	Users               []User              `yaml:"users"`
	TrustedProxyNets    []*net.IPNet        `yaml:"-"`
	ClientCARoots       *x509.CertPool      `yaml:"-"`
	ActiveSigningKey    *SigningKey         `yaml:"-"`
	JWKS                jose.JSONWebKeySet  `yaml:"-"`
	UserByCN            map[string]User     `yaml:"-"`
	UserBySubject       map[string]User     `yaml:"-"`
	ClientByID          map[string]Client   `yaml:"-"`
	HasGroupsClaim      bool                `yaml:"-"`
}

type Endpoints struct {
	Authorization string `yaml:"authorization"`
	Token         string `yaml:"token"`
	Userinfo      string `yaml:"userinfo"`
	JWKS          string `yaml:"jwks"`
	Logout        string `yaml:"logout"`
}

type HTTP struct {
	TrustedProxyCIDRs []string      `yaml:"trustedProxyCIDRs"`
	ReadTimeoutRaw    string        `yaml:"readTimeout"`
	WriteTimeoutRaw   string        `yaml:"writeTimeout"`
	IdleTimeoutRaw    string        `yaml:"idleTimeout"`
	MaxHeaderBytes    int           `yaml:"maxHeaderBytes"`
	ReadTimeout       time.Duration `yaml:"-"`
	WriteTimeout      time.Duration `yaml:"-"`
	IdleTimeout       time.Duration `yaml:"-"`
}

type ForwardedClientCert struct {
	PEMHeader             string `yaml:"pemHeader"`
	InfoHeader            string `yaml:"infoHeader"`
	RequirePEM            bool   `yaml:"requirePem"`
	RequireInfoCommonName bool   `yaml:"requireInfoCommonName"`
	CAPEM                 string `yaml:"caPem"`
}

type OAuth struct {
	AuthorizationCodeTTLRaw string        `yaml:"authorizationCodeTTL"`
	AccessTokenTTLRaw       string        `yaml:"accessTokenTTL"`
	IDTokenTTLRaw           string        `yaml:"idTokenTTL"`
	IssuerClockSkewRaw      string        `yaml:"issuerClockSkew"`
	RequirePKCES256         bool          `yaml:"requirePKCES256"`
	AllowClientSecretPost   bool          `yaml:"allowClientSecretPost"`
	MaxOutstandingCodes     int           `yaml:"maxOutstandingCodes"`
	AuthorizationCodeTTL    time.Duration `yaml:"-"`
	AccessTokenTTL          time.Duration `yaml:"-"`
	IDTokenTTL              time.Duration `yaml:"-"`
	IssuerClockSkew         time.Duration `yaml:"-"`
}

type SigningKey struct {
	KeyID         string          `yaml:"keyID"`
	Algorithm     string          `yaml:"algorithm"`
	PrivateKeyPEM string          `yaml:"privateKeyPem"`
	Active        bool            `yaml:"active"`
	PrivateKey    *rsa.PrivateKey `yaml:"-"`
	PublicJWK     jose.JSONWebKey `yaml:"-"`
}

type Client struct {
	ID                     string   `yaml:"id"`
	Name                   string   `yaml:"name"`
	Secret                 string   `yaml:"secret"`
	RedirectURIs           []string `yaml:"redirectURIs"`
	PostLogoutRedirectURIs []string `yaml:"postLogoutRedirectURIs"`
	AllowedScopes          []string `yaml:"allowedScopes"`
}

type User struct {
	ID                     string     `yaml:"id"`
	Subject                string     `yaml:"subject"`
	Email                  string     `yaml:"email"`
	Name                   string     `yaml:"name"`
	PreferredUsername      string     `yaml:"preferredUsername"`
	EmailVerified          bool       `yaml:"emailVerified"`
	CertificateCommonNames []string   `yaml:"certificateCommonNames"`
	Claims                 UserClaims `yaml:"claims"`
}

type UserClaims struct {
	Groups []string `yaml:"groups"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if err := cfg.resolveEnv(); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c Config) RedactedYAML() string {
	clone := c
	clone.ForwardedClientCert.CAPEM = redactRef(clone.ForwardedClientCert.CAPEM)
	for i := range clone.SigningKeys {
		clone.SigningKeys[i].PrivateKeyPEM = redactRef(clone.SigningKeys[i].PrivateKeyPEM)
		clone.SigningKeys[i].PrivateKey = nil
		clone.SigningKeys[i].PublicJWK = jose.JSONWebKey{}
	}
	for i := range clone.Clients {
		clone.Clients[i].Secret = redactRef(clone.Clients[i].Secret)
	}
	for i := range clone.Users {
		clone.Users[i].Email = redactRef(clone.Users[i].Email)
	}
	clone.ClientCARoots = nil
	clone.ActiveSigningKey = nil
	clone.JWKS = jose.JSONWebKeySet{}
	clone.UserByCN = nil
	clone.UserBySubject = nil
	clone.ClientByID = nil
	out, err := yaml.Marshal(clone)
	if err != nil {
		return "redacted: unavailable"
	}
	return string(out)
}

func redactRef(v string) string {
	if v == "" {
		return ""
	}
	return redacted
}

func (c *Config) resolveEnv() error {
	var err error
	c.ForwardedClientCert.CAPEM, err = resolveValue(c.ForwardedClientCert.CAPEM)
	if err != nil {
		return fmt.Errorf("forwardedClientCert.caPem: %w", err)
	}
	for i := range c.SigningKeys {
		c.SigningKeys[i].PrivateKeyPEM, err = resolveValue(c.SigningKeys[i].PrivateKeyPEM)
		if err != nil {
			return fmt.Errorf("signingKeys[%d].privateKeyPem: %w", i, err)
		}
	}
	for i := range c.Clients {
		c.Clients[i].Secret, err = resolveValue(c.Clients[i].Secret)
		if err != nil {
			return fmt.Errorf("clients[%d].secret: %w", i, err)
		}
	}
	for i := range c.Users {
		c.Users[i].Email, err = resolveValue(c.Users[i].Email)
		if err != nil {
			return fmt.Errorf("users[%d].email: %w", i, err)
		}
	}
	return nil
}

func resolveValue(v string) (string, error) {
	if !strings.HasPrefix(v, "ENV:") {
		return v, nil
	}
	name := strings.TrimPrefix(v, "ENV:")
	if name == "" || strings.Contains(name, "$") || strings.Contains(name, "{") {
		return "", errors.New("invalid env reference")
	}
	value, ok := os.LookupEnv(name)
	if !ok {
		return "", fmt.Errorf("missing env var %s", name)
	}
	if value == "" {
		return "", fmt.Errorf("empty env var %s", name)
	}
	return value, nil
}

func (c *Config) validate() error {
	if c.Issuer == "" {
		return errors.New("issuer is required")
	}
	if err := requireURL("issuer", c.Issuer); err != nil {
		return err
	}
	for name, u := range map[string]string{
		"endpoints.authorization": c.Endpoints.Authorization,
		"endpoints.token":         c.Endpoints.Token,
		"endpoints.userinfo":      c.Endpoints.Userinfo,
		"endpoints.jwks":          c.Endpoints.JWKS,
		"endpoints.logout":        c.Endpoints.Logout,
	} {
		if err := requireURL(name, u); err != nil {
			return err
		}
	}
	if c.HTTP.MaxHeaderBytes <= 0 {
		c.HTTP.MaxHeaderBytes = 16384
	}
	var err error
	if c.HTTP.ReadTimeout, err = time.ParseDuration(defaultString(c.HTTP.ReadTimeoutRaw, "5s")); err != nil {
		return fmt.Errorf("http.readTimeout: %w", err)
	}
	if c.HTTP.WriteTimeout, err = time.ParseDuration(defaultString(c.HTTP.WriteTimeoutRaw, "10s")); err != nil {
		return fmt.Errorf("http.writeTimeout: %w", err)
	}
	if c.HTTP.IdleTimeout, err = time.ParseDuration(defaultString(c.HTTP.IdleTimeoutRaw, "60s")); err != nil {
		return fmt.Errorf("http.idleTimeout: %w", err)
	}
	if c.OAuth.AuthorizationCodeTTL, err = time.ParseDuration(defaultString(c.OAuth.AuthorizationCodeTTLRaw, "60s")); err != nil {
		return fmt.Errorf("oauth.authorizationCodeTTL: %w", err)
	}
	if c.OAuth.AccessTokenTTL, err = time.ParseDuration(defaultString(c.OAuth.AccessTokenTTLRaw, "10m")); err != nil {
		return fmt.Errorf("oauth.accessTokenTTL: %w", err)
	}
	if c.OAuth.IDTokenTTL, err = time.ParseDuration(defaultString(c.OAuth.IDTokenTTLRaw, "10m")); err != nil {
		return fmt.Errorf("oauth.idTokenTTL: %w", err)
	}
	if c.OAuth.IssuerClockSkew, err = time.ParseDuration(defaultString(c.OAuth.IssuerClockSkewRaw, "30s")); err != nil {
		return fmt.Errorf("oauth.issuerClockSkew: %w", err)
	}
	if c.OAuth.MaxOutstandingCodes <= 0 {
		c.OAuth.MaxOutstandingCodes = 512
	}
	c.TrustedProxyNets = nil
	for _, raw := range c.HTTP.TrustedProxyCIDRs {
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			return fmt.Errorf("invalid trusted proxy CIDR %q: %w", raw, err)
		}
		c.TrustedProxyNets = append(c.TrustedProxyNets, network)
	}
	if c.ForwardedClientCert.PEMHeader == "" {
		c.ForwardedClientCert.PEMHeader = "X-Forwarded-Tls-Client-Cert"
	}
	if c.ForwardedClientCert.InfoHeader == "" {
		c.ForwardedClientCert.InfoHeader = "X-Forwarded-Tls-Client-Cert-Info"
	}
	if len(c.SigningKeys) == 0 {
		return errors.New("at least one signing key is required")
	}
	if c.ForwardedClientCert.CAPEM == "" {
		return errors.New("forwardedClientCert.caPem is required")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(c.ForwardedClientCert.CAPEM)) {
		return errors.New("forwardedClientCert.caPem must contain a valid certificate")
	}
	c.ClientCARoots = roots
	kidSeen := map[string]struct{}{}
	active := 0
	jwks := jose.JSONWebKeySet{}
	for i := range c.SigningKeys {
		k := &c.SigningKeys[i]
		if k.KeyID == "" {
			return fmt.Errorf("signingKeys[%d].keyID is required", i)
		}
		if _, ok := kidSeen[k.KeyID]; ok {
			return fmt.Errorf("duplicate signing key ID %q", k.KeyID)
		}
		kidSeen[k.KeyID] = struct{}{}
		if k.Algorithm == "" {
			k.Algorithm = string(jose.RS256)
		}
		if k.Algorithm != string(jose.RS256) {
			return fmt.Errorf("unsupported signing algorithm %q", k.Algorithm)
		}
		block, _ := pem.Decode([]byte(k.PrivateKeyPEM))
		if block == nil {
			return fmt.Errorf("signingKeys[%d].privateKeyPem is invalid", i)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			pkcs1, err2 := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err2 != nil {
				return fmt.Errorf("signingKeys[%d].privateKeyPem parse error: %w", i, err)
			}
			parsed = pkcs1
		}
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("signingKeys[%d].privateKeyPem must be RSA", i)
		}
		k.PrivateKey = rsaKey
		k.PublicJWK = jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: k.KeyID, Use: "sig", Algorithm: k.Algorithm}
		jwks.Keys = append(jwks.Keys, k.PublicJWK)
		if k.Active {
			active++
			c.ActiveSigningKey = k
		}
	}
	if active != 1 {
		return fmt.Errorf("expected exactly one active signing key, got %d", active)
	}
	c.JWKS = jwks
	userIDs := map[string]struct{}{}
	subjects := map[string]struct{}{}
	emails := map[string]struct{}{}
	cns := map[string]struct{}{}
	c.UserByCN = map[string]User{}
	c.UserBySubject = map[string]User{}
	c.HasGroupsClaim = false
	for i, u := range c.Users {
		if u.ID == "" || u.Subject == "" || u.Name == "" || u.PreferredUsername == "" || u.Email == "" {
			return fmt.Errorf("users[%d] has required empty fields", i)
		}
		if _, ok := userIDs[u.ID]; ok {
			return fmt.Errorf("duplicate user id %q", u.ID)
		}
		userIDs[u.ID] = struct{}{}
		if _, ok := subjects[u.Subject]; ok {
			return fmt.Errorf("duplicate subject %q", u.Subject)
		}
		subjects[u.Subject] = struct{}{}
		if _, ok := emails[strings.ToLower(u.Email)]; ok {
			return fmt.Errorf("duplicate email %q", u.Email)
		}
		emails[strings.ToLower(u.Email)] = struct{}{}
		if len(u.Claims.Groups) > 0 {
			c.HasGroupsClaim = true
		}
		for _, cn := range u.CertificateCommonNames {
			if cn == "" || strings.Contains(cn, "*") {
				return fmt.Errorf("invalid certificate common name %q", cn)
			}
			if _, ok := cns[cn]; ok {
				return fmt.Errorf("duplicate certificate common name %q", cn)
			}
			cns[cn] = struct{}{}
			c.UserByCN[cn] = u
		}
		c.UserBySubject[u.Subject] = u
	}
	clientIDs := map[string]struct{}{}
	c.ClientByID = map[string]Client{}
	for i := range c.Clients {
		cl := c.Clients[i]
		if cl.ID == "" || cl.Secret == "" {
			return fmt.Errorf("clients[%d] is missing id or secret", i)
		}
		if _, ok := clientIDs[cl.ID]; ok {
			return fmt.Errorf("duplicate client id %q", cl.ID)
		}
		clientIDs[cl.ID] = struct{}{}
		for _, u := range cl.RedirectURIs {
			if err := requireURL("redirectURI", u); err != nil {
				return err
			}
		}
		for _, u := range cl.PostLogoutRedirectURIs {
			if err := requireURL("postLogoutRedirectURI", u); err != nil {
				return err
			}
		}
		if len(cl.AllowedScopes) == 0 {
			cl.AllowedScopes = []string{"openid", "profile", "email"}
			c.Clients[i].AllowedScopes = cl.AllowedScopes
		}
		if !slices.Contains(cl.AllowedScopes, "openid") {
			return fmt.Errorf("client %q must allow openid scope", cl.ID)
		}
		c.ClientByID[cl.ID] = cl
	}
	return nil
}

func defaultString(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func requireURL(name, raw string) error {
	if raw == "" {
		return fmt.Errorf("%s is required", name)
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("%s must be an absolute URL", name)
	}
	if u.Fragment != "" {
		return fmt.Errorf("%s must not contain fragments", name)
	}
	return nil
}
