package tokens

import (
	"fmt"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/tpaulus/simple-idp/internal/config"
)

type Manager struct {
	issuer string
	skew   time.Duration
	keys   []config.SigningKey
	active config.SigningKey
	now    func() time.Time
}

type AccessClaims struct {
	jwt.Claims
	TokenUse          string   `json:"token_use"`
	Scope             string   `json:"scope"`
	AuthTime          int64    `json:"auth_time"`
	Email             string   `json:"email,omitempty"`
	EmailVerified     bool     `json:"email_verified,omitempty"`
	Name              string   `json:"name,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Groups            []string `json:"groups,omitempty"`
}

func New(cfg *config.Config, now func() time.Time) *Manager {
	if now == nil {
		now = time.Now
	}
	return &Manager{issuer: cfg.Issuer, skew: cfg.OAuth.IssuerClockSkew, keys: cfg.SigningKeys, active: *cfg.ActiveSigningKey, now: now}
}

func (m *Manager) SignIDToken(clientID string, user config.User, _ []string, nonce string, authTime time.Time, ttl time.Duration) (string, error) {
	claims := map[string]any{
		"email":              user.Email,
		"email_verified":     user.EmailVerified,
		"name":               user.Name,
		"preferred_username": user.PreferredUsername,
		"auth_time":          authTime.Unix(),
	}
	if len(user.Claims.Groups) > 0 {
		claims["groups"] = user.Claims.Groups
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	return m.sign(jwt.Claims{
		Issuer:    m.issuer,
		Subject:   user.Subject,
		Audience:  jwt.Audience{clientID},
		IssuedAt:  jwt.NewNumericDate(m.now()),
		Expiry:    jwt.NewNumericDate(m.now().Add(ttl)),
		NotBefore: jwt.NewNumericDate(m.now().Add(-m.skew)),
	}, claims)
}

func (m *Manager) SignAccessToken(clientID string, user config.User, scopes []string, authTime time.Time, ttl time.Duration) (string, error) {
	claims := AccessClaims{
		Claims: jwt.Claims{
			Issuer:    m.issuer,
			Subject:   user.Subject,
			Audience:  jwt.Audience{clientID},
			IssuedAt:  jwt.NewNumericDate(m.now()),
			Expiry:    jwt.NewNumericDate(m.now().Add(ttl)),
			NotBefore: jwt.NewNumericDate(m.now().Add(-m.skew)),
		},
		TokenUse:          "access_token",
		Scope:             joinScopes(scopes),
		AuthTime:          authTime.Unix(),
		Email:             user.Email,
		EmailVerified:     user.EmailVerified,
		Name:              user.Name,
		PreferredUsername: user.PreferredUsername,
		Groups:            user.Claims.Groups,
	}
	return m.sign(claims.Claims, map[string]any{
		"token_use":          claims.TokenUse,
		"scope":              claims.Scope,
		"auth_time":          claims.AuthTime,
		"email":              claims.Email,
		"email_verified":     claims.EmailVerified,
		"name":               claims.Name,
		"preferred_username": claims.PreferredUsername,
		"groups":             claims.Groups,
	})
}

func (m *Manager) sign(registered jwt.Claims, extra map[string]any) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: m.active.PrivateKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", m.active.KeyID))
	if err != nil {
		return "", err
	}
	builder := jwt.Signed(signer).Claims(registered)
	if len(extra) > 0 {
		builder = builder.Claims(extra)
	}
	return builder.Serialize()
}

func (m *Manager) VerifyAccessToken(raw string) (*AccessClaims, error) {
	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	for _, key := range m.keys {
		var claims AccessClaims
		if err := parsed.Claims(key.PublicJWK.Key, &claims); err != nil {
			continue
		}
		if err := claims.Validate(jwt.Expected{Issuer: m.issuer, Time: m.now()}); err != nil {
			return nil, fmt.Errorf("validate token: %w", err)
		}
		if claims.TokenUse != "access_token" {
			return nil, fmt.Errorf("invalid token use")
		}
		if len(claims.Audience) == 0 {
			return nil, fmt.Errorf("missing audience")
		}
		return &claims, nil
	}
	return nil, fmt.Errorf("verify token: no signing key matched")
}

func joinScopes(scopes []string) string {
	return strings.Join(scopes, " ")
}
