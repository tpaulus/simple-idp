package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tpaulus/simple-idp/internal/config"
	"github.com/tpaulus/simple-idp/internal/testutil"
)

func TestLoadResolvesEnvAndRedactsSecrets(t *testing.T) {
	caCert, _, caPEM := testutil.MustGenerateCA(t)
	_ = caCert
	t.Setenv("CLIENT_CA_CRT", caPEM)
	t.Setenv("OIDC_SIGNING_KEY", testutil.MustGenerateRSAPrivateKeyPEM(t))
	t.Setenv("GRAFANA_OIDC_CLIENT_SECRET", "super-secret")
	t.Setenv("TOM_EMAIL", "tom@example.test")
	t.Setenv("MEL_EMAIL", "mel@example.test")

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(sampleConfig()), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Clients[0].Secret != "super-secret" {
		t.Fatalf("expected resolved secret")
	}
	if cfg.Users[0].Email != "tom@example.test" {
		t.Fatalf("expected resolved email")
	}
	redacted := cfg.RedactedYAML()
	for _, forbidden := range []string{"super-secret", "tom@example.test", "BEGIN CERTIFICATE", "BEGIN PRIVATE KEY"} {
		if strings.Contains(redacted, forbidden) {
			t.Fatalf("redacted config leaked %q", forbidden)
		}
	}
}

func TestLoadRejectsDuplicateCertificateCommonName(t *testing.T) {
	t.Setenv("CLIENT_CA_CRT", mustCA(t))
	t.Setenv("OIDC_SIGNING_KEY", testutil.MustGenerateRSAPrivateKeyPEM(t))
	t.Setenv("GRAFANA_OIDC_CLIENT_SECRET", "super-secret")
	t.Setenv("TOM_EMAIL", "tom@example.test")
	t.Setenv("MEL_EMAIL", "mel@example.test")
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg := strings.Replace(sampleConfig(), "mel-iphone", "tom-laptop", 1)
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := config.Load(path); err == nil || !strings.Contains(err.Error(), "duplicate certificate common name") {
		t.Fatalf("expected duplicate CN error, got %v", err)
	}
}

func TestLoadDefaultsClientAllowedScopesInClientsAndLookup(t *testing.T) {
	if err := os.Setenv("CLIENT_CA_CRT", mustCA(t)); err != nil {
		t.Fatalf("set env: %v", err)
	}
	if err := os.Setenv("OIDC_SIGNING_KEY", testutil.MustGenerateRSAPrivateKeyPEM(t)); err != nil {
		t.Fatalf("set env: %v", err)
	}
	if err := os.Setenv("GRAFANA_OIDC_CLIENT_SECRET", "super-secret"); err != nil {
		t.Fatalf("set env: %v", err)
	}
	if err := os.Setenv("TOM_EMAIL", "tom@example.test"); err != nil {
		t.Fatalf("set env: %v", err)
	}
	if err := os.Setenv("MEL_EMAIL", "mel@example.test"); err != nil {
		t.Fatalf("set env: %v", err)
	}
	t.Cleanup(func() {
		for _, name := range []string{"CLIENT_CA_CRT", "OIDC_SIGNING_KEY", "GRAFANA_OIDC_CLIENT_SECRET", "TOM_EMAIL", "MEL_EMAIL"} {
			if err := os.Unsetenv(name); err != nil {
				t.Fatalf("unset env: %v", err)
			}
		}
	})

	path := filepath.Join(t.TempDir(), "config.yaml")
	cfgText := strings.Replace(sampleConfig(), `    allowedScopes: ["openid", "profile", "email"]`+"\n", "", 1)
	if err := os.WriteFile(path, []byte(cfgText), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	want := strings.Join([]string{"openid", "profile", "email"}, ",")
	if strings.Join(cfg.Clients[0].AllowedScopes, ",") != want {
		t.Fatalf("unexpected client scopes: %#v", cfg.Clients[0].AllowedScopes)
	}
	if strings.Join(cfg.ClientByID["grafana"].AllowedScopes, ",") != want {
		t.Fatalf("unexpected client lookup scopes: %#v", cfg.ClientByID["grafana"].AllowedScopes)
	}
}

func mustCA(t *testing.T) string {
	_, _, caPEM := testutil.MustGenerateCA(t)
	return caPEM
}

func sampleConfig() string {
	return `issuer: "https://auth.example.test"
endpoints:
  authorization: "https://auth.example.test/authorize"
  token: "https://auth.example.test/token"
  userinfo: "https://auth.example.test/userinfo"
  jwks: "https://auth.example.test/jwks.json"
  logout: "https://auth.example.test/logout"
http:
  trustedProxyCIDRs: ["127.0.0.0/8"]
  readTimeout: "5s"
  writeTimeout: "10s"
  idleTimeout: "60s"
  maxHeaderBytes: 16384
forwardedClientCert:
  pemHeader: "X-Forwarded-Tls-Client-Cert"
  infoHeader: "X-Forwarded-Tls-Client-Cert-Info"
  requirePem: true
  requireInfoCommonName: true
  caPem: "ENV:CLIENT_CA_CRT"
oauth:
  authorizationCodeTTL: "60s"
  accessTokenTTL: "10m"
  idTokenTTL: "10m"
  issuerClockSkew: "30s"
  requirePKCES256: false
  allowClientSecretPost: true
  maxOutstandingCodes: 512
signingKeys:
  - keyID: "main-rs256"
    algorithm: "RS256"
    privateKeyPem: "ENV:OIDC_SIGNING_KEY"
    active: true
clients:
  - id: grafana
    name: Grafana
    secret: "ENV:GRAFANA_OIDC_CLIENT_SECRET"
    redirectURIs: ["https://grafana.example.test/login/generic_oauth"]
    postLogoutRedirectURIs: ["https://grafana.example.test/"]
    allowedScopes: ["openid", "profile", "email"]
users:
  - id: tom
    subject: "user:tom"
    email: "ENV:TOM_EMAIL"
    name: "Tom Paulus"
    preferredUsername: "tom"
    emailVerified: true
    certificateCommonNames: ["tom-laptop", "tom-iphone"]
    claims:
      groups: ["family"]
  - id: mel
    subject: "user:mel"
    email: "ENV:MEL_EMAIL"
    name: "Mel Paulus"
    preferredUsername: "mel"
    emailVerified: true
    certificateCommonNames: ["mel-laptop", "mel-iphone"]
    claims:
      groups: ["family"]
`
}
