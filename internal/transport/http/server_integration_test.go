package httptransport_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/time/rate"

	"github.com/tpaulus/simple-idp/internal/certauth"
	"github.com/tpaulus/simple-idp/internal/config"
	"github.com/tpaulus/simple-idp/internal/endpoint"
	"github.com/tpaulus/simple-idp/internal/oauth"
	"github.com/tpaulus/simple-idp/internal/service"
	"github.com/tpaulus/simple-idp/internal/store"
	"github.com/tpaulus/simple-idp/internal/testutil"
	"github.com/tpaulus/simple-idp/internal/tokens"
	httptransport "github.com/tpaulus/simple-idp/internal/transport/http"
)

func TestAuthorizeTokenUserInfoFlow(t *testing.T) {
	app := newTestApp(t)
	challenge, verifier := pkcePair("verifier-1")
	redirect := authorize(t, app, "tom-laptop", app.tomLaptopPEM, url.Values{
		"client_id":             {"grafana"},
		"redirect_uri":          {"https://grafana.example.test/login/generic_oauth"},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {"opaque-state"},
		"nonce":                 {"nonce-123"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	})
	if redirect.Query().Get("state") != "opaque-state" {
		t.Fatalf("expected returned state")
	}
	code := redirect.Query().Get("code")
	if code == "" {
		t.Fatal("expected authorization code")
	}
	if app.codes.Outstanding() != 1 {
		t.Fatalf("expected hashed code storage")
	}
	resp := exchangeCode(t, app, "grafana", "grafana-secret", code, verifier)
	if resp.TokenType != "Bearer" || resp.AccessToken == "" || resp.IDToken == "" {
		t.Fatalf("unexpected token response: %#v", resp)
	}
	idClaims := parseIDToken(t, app.cfg, resp.IDToken)
	if idClaims["sub"] != "user:tom" || idClaims["nonce"] != "nonce-123" {
		t.Fatalf("unexpected ID token claims: %#v", idClaims)
	}
	userInfo := userInfo(t, app, resp.AccessToken)
	if userInfo["sub"] != "user:tom" || userInfo["email"] != "tom@example.test" {
		t.Fatalf("unexpected userinfo: %#v", userInfo)
	}
	groups, ok := userInfo["groups"].([]any)
	if !ok || len(groups) != 1 || groups[0] != "family" {
		t.Fatalf("expected groups claim, got %#v", userInfo["groups"])
	}
}

func TestTomSubjectStableAcrossDevices(t *testing.T) {
	app := newTestApp(t)
	first := exchangeCode(t, app, "grafana", "grafana-secret", authorize(t, app, "tom-laptop", app.tomLaptopPEM, baseAuthorizeQuery()).Query().Get("code"), "")
	second := exchangeCode(t, app, "grafana", "grafana-secret", authorize(t, app, "tom-iphone", app.tomIPhonePEM, baseAuthorizeQuery()).Query().Get("code"), "")
	firstInfo := userInfo(t, app, first.AccessToken)
	secondInfo := userInfo(t, app, second.AccessToken)
	if firstInfo["sub"] != secondInfo["sub"] || firstInfo["sub"] != "user:tom" {
		t.Fatalf("expected stable subject, got %v and %v", firstInfo["sub"], secondInfo["sub"])
	}
}

func TestRejectsInvalidRequests(t *testing.T) {
	app := newTestApp(t)
	t.Run("wrong redirect URI", func(t *testing.T) {
		rec := serve(t, app.handler, requestWithIdentity(t, http.MethodGet, "/authorize?client_id=grafana&redirect_uri=https://grafana.example.test/login/generic_oauthx&response_type=code&scope=openid", "tom-laptop", app.tomLaptopPEM, true, nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})
	t.Run("unsupported response type", func(t *testing.T) {
		rec := serve(t, app.handler, requestWithIdentity(t, http.MethodGet, "/authorize?client_id=grafana&redirect_uri=https://grafana.example.test/login/generic_oauth&response_type=token&scope=openid", "tom-laptop", app.tomLaptopPEM, true, nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})
	t.Run("missing cert headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/authorize?client_id=grafana&redirect_uri=https://grafana.example.test/login/generic_oauth&response_type=code&scope=openid", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		rec := serve(t, app.handler, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})
	t.Run("spoofed headers from untrusted remote", func(t *testing.T) {
		rec := serve(t, app.handler, requestWithIdentity(t, http.MethodGet, "/authorize?client_id=grafana&redirect_uri=https://grafana.example.test/login/generic_oauth&response_type=code&scope=openid", "tom-laptop", app.tomLaptopPEM, false, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})
	t.Run("code reuse", func(t *testing.T) {
		code := authorize(t, app, "mel-laptop", app.melLaptopPEM, baseAuthorizeQuery()).Query().Get("code")
		_ = exchangeCode(t, app, "grafana", "grafana-secret", code, "")
		rec := tokenRequest(t, app, "grafana", "grafana-secret", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://grafana.example.test/login/generic_oauth"}}, true)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})
	t.Run("wrong client", func(t *testing.T) {
		code := authorize(t, app, "mel-laptop", app.melLaptopPEM, baseAuthorizeQuery()).Query().Get("code")
		rec := tokenRequest(t, app, "argocd", "argocd-secret", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://grafana.example.test/login/generic_oauth"}}, true)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})
	t.Run("unsupported grant type", func(t *testing.T) {
		rec := tokenRequest(t, app, "grafana", "grafana-secret", url.Values{"grant_type": {"refresh_token"}}, true)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})
	t.Run("userinfo invalid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
		req.Header.Set("Authorization", "******")
		rec := serve(t, app.handler, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})
	t.Run("client_secret_post", func(t *testing.T) {
		code := authorize(t, app, "mel-laptop", app.melLaptopPEM, baseAuthorizeQuery()).Query().Get("code")
		rec := tokenRequest(t, app, "grafana", "grafana-secret", url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {"https://grafana.example.test/login/generic_oauth"},
			"client_id":     {"grafana"},
			"client_secret": {"grafana-secret"},
		}, false)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("logout exact redirect", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/logout?post_logout_redirect_uri="+url.QueryEscape("https://grafana.example.test/")+"&state=bye", nil)
		rec := serve(t, app.handler, req)
		if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "state=bye") {
			t.Fatalf("expected safe logout redirect, got %d %q", rec.Code, rec.Header().Get("Location"))
		}
	})
	t.Run("logout static page for unsafe redirect", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/logout?post_logout_redirect_uri="+url.QueryEscape("https://grafana.example.test.evil/"), nil)
		rec := serve(t, app.handler, req)
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Security-Policy") == "" {
			t.Fatalf("expected static page with CSP, got %d headers=%v", rec.Code, rec.Header())
		}
	})
}

type testApp struct {
	cfg          *config.Config
	handler      http.Handler
	codes        *store.CodeStore
	tomLaptopPEM string
	tomIPhonePEM string
	melLaptopPEM string
}

func newTestApp(t *testing.T) testApp {
	t.Helper()
	ca, caKey, caPEM := testutil.MustGenerateCA(t)
	tomLaptop := testutil.MustGenerateClientCert(t, ca, caKey, "tom-laptop", time.Now().Add(-time.Minute), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	tomIPhone := testutil.MustGenerateClientCert(t, ca, caKey, "tom-iphone", time.Now().Add(-time.Minute), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	melLaptop := testutil.MustGenerateClientCert(t, ca, caKey, "mel-laptop", time.Now().Add(-time.Minute), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	t.Setenv("CLIENT_CA_CRT", caPEM)
	t.Setenv("OIDC_SIGNING_KEY", testutil.MustGenerateRSAPrivateKeyPEM(t))
	t.Setenv("GRAFANA_OIDC_CLIENT_SECRET", "grafana-secret")
	t.Setenv("ARGOCD_OIDC_CLIENT_SECRET", "argocd-secret")
	t.Setenv("TOM_EMAIL", "tom@example.test")
	t.Setenv("MEL_EMAIL", "mel@example.test")
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(testConfigYAML()), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	auth := certauth.New(certauth.Config{TrustedProxyNets: cfg.TrustedProxyNets, PEMHeader: cfg.ForwardedClientCert.PEMHeader, InfoHeader: cfg.ForwardedClientCert.InfoHeader, RequirePEM: cfg.ForwardedClientCert.RequirePEM, RequireInfoCommonName: cfg.ForwardedClientCert.RequireInfoCommonName, CARoots: cfg.ClientCARoots})
	codes := store.NewCodeStore(cfg.OAuth.MaxOutstandingCodes, nil)
	svc := service.New(cfg, auth, codes, tokens.New(cfg, nil), nil)
	eps := endpoint.New(svc, endpoint.NewIPRateLimiter(rate.Every(time.Millisecond), 100, nil), endpoint.NewIPRateLimiter(rate.Every(time.Millisecond), 100, nil))
	handler := httptransport.NewHandler(cfg, eps, slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil)))
	return testApp{cfg: cfg, handler: handler, codes: codes, tomLaptopPEM: tomLaptop, tomIPhonePEM: tomIPhone, melLaptopPEM: melLaptop}
}

func authorize(t *testing.T, app testApp, commonName, certPEM string, query url.Values) *url.URL {
	t.Helper()
	req := requestWithIdentity(t, http.MethodGet, "/authorize?"+query.Encode(), commonName, certPEM, true, nil)
	rec := serve(t, app.handler, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d: %s", rec.Code, rec.Body.String())
	}
	redirect, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	return redirect
}

func exchangeCode(t *testing.T, app testApp, clientID, secret, code, verifier string) service.TokenResponse { //nolint:unparam
	t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://grafana.example.test/login/generic_oauth"}}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	rec := tokenRequest(t, app, clientID, secret, form, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected token success, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp service.TokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return resp
}

func tokenRequest(t *testing.T, app testApp, clientID, secret string, form url.Values, useBasic bool) *httptest.ResponseRecorder {
	t.Helper()
	if !useBasic && (clientID != "" || secret != "") {
		form.Set("client_id", clientID)
		form.Set("client_secret", secret)
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if useBasic {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(clientID+":"+secret)))
	}
	return serve(t, app.handler, req)
}

func userInfo(t *testing.T, app testApp, accessToken string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rec := serve(t, app.handler, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected userinfo success, got %d: %s", rec.Code, rec.Body.String())
	}
	var claims map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &claims); err != nil {
		t.Fatalf("decode userinfo: %v", err)
	}
	return claims
}

func parseIDToken(t *testing.T, cfg *config.Config, raw string) map[string]any {
	t.Helper()
	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parse id token: %v", err)
	}
	var claims map[string]any
	if err := parsed.Claims(cfg.JWKS.Keys[0].Key, &claims); err != nil {
		t.Fatalf("verify id token: %v", err)
	}
	return claims
}

func serve(t *testing.T, handler http.Handler, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req.WithContext(context.Background()))
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("missing secure headers: %#v", rec.Header())
	}
	return rec
}

func requestWithIdentity(t *testing.T, method, target, commonName, certPEM string, trusted bool, body *strings.Reader) *http.Request { //nolint:unparam
	t.Helper()
	var reader *strings.Reader
	if body == nil {
		reader = strings.NewReader("")
	} else {
		reader = body
	}
	req := httptest.NewRequest(method, target, reader)
	if trusted {
		req.RemoteAddr = "127.0.0.1:1234"
	} else {
		req.RemoteAddr = "203.0.113.10:1234"
	}
	req.Header.Set("X-Forwarded-Tls-Client-Cert", url.QueryEscape(certPEM))
	req.Header.Set("X-Forwarded-Tls-Client-Cert-Info", url.QueryEscape(fmt.Sprintf(`Subject="CN=%s"`, commonName)))
	return req
}

func testConfigYAML() string {
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
  - id: argocd
    name: Argo CD
    secret: "ENV:ARGOCD_OIDC_CLIENT_SECRET"
    redirectURIs: ["https://argocd.example.test/auth/callback"]
    postLogoutRedirectURIs: ["https://argocd.example.test/"]
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

func baseAuthorizeQuery() url.Values {
	return url.Values{
		"client_id":     {"grafana"},
		"redirect_uri":  {"https://grafana.example.test/login/generic_oauth"},
		"response_type": {"code"},
		"scope":         {"openid profile email"},
	}
}

func pkcePair(verifier string) (string, string) {
	sum := oauth.HashCode(verifier)
	return base64.RawURLEncoding.EncodeToString(sum[:]), verifier
}
