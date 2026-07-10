package tokens_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tpaulus/simple-idp/internal/config"
	"github.com/tpaulus/simple-idp/internal/testutil"
	"github.com/tpaulus/simple-idp/internal/tokens"
)

func TestVerifyAccessToken(t *testing.T) {
	cfg := loadTokenConfig(t)
	manager := tokens.New(cfg, nil)
	token, err := manager.SignAccessToken("grafana", cfg.Users[0], []string{"openid", "profile", "email"}, time.Now(), cfg.OAuth.AccessTokenTTL)
	if err != nil {
		t.Fatalf("sign access token: %v", err)
	}
	claims, err := manager.VerifyAccessToken(token)
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	if claims.Subject != "user:tom" {
		t.Fatalf("unexpected subject %q", claims.Subject)
	}
}

func loadTokenConfig(t *testing.T) *config.Config {
	t.Helper()
	_, _, caPEM := testutil.MustGenerateCA(t)
	t.Setenv("CLIENT_CA_CRT", caPEM)
	t.Setenv("OIDC_SIGNING_KEY", testutil.MustGenerateRSAPrivateKeyPEM(t))
	t.Setenv("GRAFANA_OIDC_CLIENT_SECRET", "grafana-secret")
	t.Setenv("TOM_EMAIL", "tom@example.test")
	t.Setenv("MEL_EMAIL", "mel@example.test")
	cfgText := `issuer: "https://auth.example.test"
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
  - id: mel
    subject: "user:mel"
    email: "ENV:MEL_EMAIL"
    name: "Mel Paulus"
    preferredUsername: "mel"
    emailVerified: true
    certificateCommonNames: ["mel-laptop", "mel-iphone"]
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(cfgText), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	return cfg
}
