package service

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/tpaulus/simple-idp/internal/certauth"
	"github.com/tpaulus/simple-idp/internal/config"
	"github.com/tpaulus/simple-idp/internal/oauth"
	"github.com/tpaulus/simple-idp/internal/store"
	"github.com/tpaulus/simple-idp/internal/tokens"
)

type Service struct {
	cfg    *config.Config
	auth   *certauth.Authenticator
	codes  *store.CodeStore
	tokens *tokens.Manager
	now    func() time.Time
}

type HTTPError struct {
	Status  int
	Code    string
	Message string
}

func (e *HTTPError) Error() string { return e.Message }

func badRequest(code, msg string) error { return &HTTPError{Status: http.StatusBadRequest, Code: code, Message: msg} }
func unauthorized(msg string) error     { return &HTTPError{Status: http.StatusUnauthorized, Code: "unauthorized", Message: msg} }
func tooManyRequests(msg string) error  { return &HTTPError{Status: http.StatusTooManyRequests, Code: "rate_limited", Message: msg} }

func New(cfg *config.Config, auth *certauth.Authenticator, codes *store.CodeStore, tm *tokens.Manager, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{cfg: cfg, auth: auth, codes: codes, tokens: tm, now: now}
}

type AuthorizeRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	HTTPRequest         *http.Request
}

type AuthorizeResponse struct {
	RedirectURL string `json:"redirect_url"`
}

type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	CodeVerifier string
	AuthHeader   string
	FormClientID string
	FormSecret   string
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
}

func (s *Service) Discovery(_ context.Context) map[string]any {
	authMethods := []string{"client_secret_basic"}
	if s.cfg.OAuth.AllowClientSecretPost {
		authMethods = append(authMethods, "client_secret_post")
	}
	claims := []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "name", "email", "email_verified", "preferred_username"}
	if s.cfg.HasGroupsClaim {
		claims = append(claims, "groups")
	}
	return map[string]any{
		"issuer":                                s.cfg.Issuer,
		"authorization_endpoint":                s.cfg.Endpoints.Authorization,
		"token_endpoint":                        s.cfg.Endpoints.Token,
		"userinfo_endpoint":                     s.cfg.Endpoints.Userinfo,
		"jwks_uri":                              s.cfg.Endpoints.JWKS,
		"end_session_endpoint":                  s.cfg.Endpoints.Logout,
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": authMethods,
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"claims_supported":                      claims,
	}
}

func (s *Service) JWKS(_ context.Context) jose.JSONWebKeySet { return s.cfg.JWKS }

func (s *Service) Authorize(_ context.Context, req AuthorizeRequest) (*AuthorizeResponse, error) {
	client, ok := s.cfg.ClientByID[req.ClientID]
	if !ok {
		return nil, badRequest("invalid_client", "invalid client")
	}
	if !ExactRedirectMatch(client.RedirectURIs, req.RedirectURI) {
		return nil, badRequest("invalid_redirect_uri", "invalid redirect URI")
	}
	if req.ResponseType != "code" {
		return nil, badRequest("unsupported_response_type", "unsupported response type")
	}
	scopes := oauth.ParseScopes(req.Scope)
	if !oauth.HasScope(scopes, "openid") {
		return nil, badRequest("invalid_scope", "openid scope is required")
	}
	for _, scope := range scopes {
		if !ExactRedirectMatch(client.AllowedScopes, scope) {
			return nil, badRequest("invalid_scope", "requested scope is not allowed")
		}
	}
	if req.CodeChallengeMethod != "" && req.CodeChallengeMethod != "S256" {
		return nil, badRequest("invalid_request", "unsupported code challenge method")
	}
	if s.cfg.OAuth.RequirePKCES256 && (req.CodeChallenge == "" || req.CodeChallengeMethod != "S256") {
		return nil, badRequest("invalid_request", "PKCE S256 is required")
	}
	if req.CodeChallenge != "" && req.CodeChallengeMethod != "S256" {
		return nil, badRequest("invalid_request", "PKCE challenge requires S256")
	}
	cn, err := s.auth.Authenticate(req.HTTPRequest)
	if err != nil {
		return nil, unauthorized("client certificate identity required")
	}
	user, ok := s.cfg.UserByCN[cn]
	if !ok {
		return nil, unauthorized("client certificate identity required")
	}
	code, hash, err := oauth.GenerateCode()
	if err != nil {
		return nil, fmt.Errorf("generate authorization code: %w", err)
	}
	now := s.now()
	if err := s.codes.Put(store.AuthorizationCode{
		Hash:          hash,
		ClientID:      req.ClientID,
		RedirectURI:   req.RedirectURI,
		Subject:       user.Subject,
		Scopes:        scopes,
		Nonce:         req.Nonce,
		CodeChallenge: req.CodeChallenge,
		AuthTime:      now,
		ExpiresAt:     now.Add(s.cfg.OAuth.AuthorizationCodeTTL),
	}); err != nil {
		return nil, badRequest("temporarily_unavailable", "authorization code storage limit reached")
	}
	redirect, _ := url.Parse(req.RedirectURI)
	q := redirect.Query()
	q.Set("code", code)
	if req.State != "" {
		q.Set("state", req.State)
	}
	redirect.RawQuery = q.Encode()
	return &AuthorizeResponse{RedirectURL: redirect.String()}, nil
}

func (s *Service) Token(_ context.Context, req TokenRequest) (*TokenResponse, error) {
	client, err := s.authenticateClient(req)
	if err != nil {
		return nil, err
	}
	if req.GrantType != "authorization_code" {
		return nil, badRequest("unsupported_grant_type", "unsupported grant type")
	}
	if req.Code == "" || req.RedirectURI == "" {
		return nil, badRequest("invalid_request", "authorization code and redirect URI are required")
	}
	storedCode, err := s.codes.Consume(oauth.HashCode(req.Code))
	if err != nil {
		return nil, unauthorized("invalid authorization code")
	}
	if subtle.ConstantTimeCompare([]byte(storedCode.ClientID), []byte(client.ID)) != 1 || storedCode.RedirectURI != req.RedirectURI {
		return nil, unauthorized("invalid authorization code")
	}
	if storedCode.CodeChallenge != "" {
		if req.CodeVerifier == "" || !oauth.VerifyPKCES256(storedCode.CodeChallenge, req.CodeVerifier) {
			return nil, unauthorized("invalid authorization code")
		}
	}
	user, ok := s.cfg.UserBySubject[storedCode.Subject]
	if !ok {
		return nil, unauthorized("invalid subject")
	}
	idToken, err := s.tokens.SignIDToken(client.ID, user, storedCode.Scopes, storedCode.Nonce, storedCode.AuthTime, s.cfg.OAuth.IDTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("sign ID token: %w", err)
	}
	accessToken, err := s.tokens.SignAccessToken(client.ID, user, storedCode.Scopes, storedCode.AuthTime, s.cfg.OAuth.AccessTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}
	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.cfg.OAuth.AccessTokenTTL.Seconds()),
		IDToken:     idToken,
		Scope:       strings.Join(storedCode.Scopes, " "),
	}, nil
}

func (s *Service) UserInfo(_ context.Context, rawToken string) (map[string]any, error) {
	if rawToken == "" {
		return nil, unauthorized("missing bearer token")
	}
	claims, err := s.tokens.VerifyAccessToken(rawToken)
	if err != nil {
		return nil, unauthorized("invalid bearer token")
	}
	user, ok := s.cfg.UserBySubject[claims.Subject]
	if !ok {
		return nil, unauthorized("invalid bearer token")
	}
	scopes := oauth.ParseScopes(claims.Scope)
	result := map[string]any{"sub": user.Subject}
	if oauth.HasScope(scopes, "email") {
		result["email"] = user.Email
		result["email_verified"] = user.EmailVerified
	}
	if oauth.HasScope(scopes, "profile") {
		result["name"] = user.Name
		result["preferred_username"] = user.PreferredUsername
		if len(user.Claims.Groups) > 0 {
			result["groups"] = user.Claims.Groups
		}
	}
	return result, nil
}

func (s *Service) Logout(_ context.Context, postLogoutRedirectURI, state string) (string, bool) {
	for _, client := range s.cfg.Clients {
		if ExactRedirectMatch(client.PostLogoutRedirectURIs, postLogoutRedirectURI) {
			if state == "" {
				return postLogoutRedirectURI, true
			}
			u, _ := url.Parse(postLogoutRedirectURI)
			q := u.Query()
			q.Set("state", state)
			u.RawQuery = q.Encode()
			return u.String(), true
		}
	}
	return "", false
}

func (s *Service) authenticateClient(req TokenRequest) (config.Client, error) {
	if req.AuthHeader != "" {
		parts := strings.SplitN(req.AuthHeader, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Basic") {
			decoded, err := base64.StdEncoding.DecodeString(parts[1])
			if err == nil {
				creds := strings.SplitN(string(decoded), ":", 2)
				if len(creds) == 2 {
					return s.checkClientSecret(creds[0], creds[1])
				}
			}
		}
	}
	if req.FormClientID != "" || req.FormSecret != "" {
		if !s.cfg.OAuth.AllowClientSecretPost {
			return config.Client{}, unauthorized("invalid client authentication")
		}
		return s.checkClientSecret(req.FormClientID, req.FormSecret)
	}
	return config.Client{}, unauthorized("missing client authentication")
}

func (s *Service) checkClientSecret(id, secret string) (config.Client, error) {
	client, ok := s.cfg.ClientByID[id]
	if !ok {
		return config.Client{}, unauthorized("invalid client authentication")
	}
	if subtle.ConstantTimeCompare([]byte(client.Secret), []byte(secret)) != 1 {
		return config.Client{}, unauthorized("invalid client authentication")
	}
	return client, nil
}

func ToHTTPError(err error) *HTTPError {
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		return httpErr
	}
	return &HTTPError{Status: http.StatusInternalServerError, Code: "server_error", Message: "internal server error"}
}
