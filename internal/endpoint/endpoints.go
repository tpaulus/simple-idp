package endpoint

import (
	"context"
	"net"
	"sync"
	"time"

	kitendpoint "github.com/go-kit/kit/endpoint"
	"golang.org/x/time/rate"

	"github.com/tpaulus/simple-idp/internal/service"
)

type Endpoints struct {
	Authorize kitendpoint.Endpoint
	Token     kitendpoint.Endpoint
	UserInfo  kitendpoint.Endpoint
	Discovery kitendpoint.Endpoint
	JWKS      kitendpoint.Endpoint
	Logout    kitendpoint.Endpoint
}

type LogoutRequest struct {
	PostLogoutRedirectURI string
	State                 string
}

type LogoutResponse struct {
	Redirect string
	OK       bool
}

func New(svc *service.Service, authorizeRate, tokenRate *IPRateLimiter) Endpoints {
	authorize := svc.Authorize
	if authorizeRate != nil {
		authorize = authorizeRate.WrapAuthorize(authorize)
	}
	token := svc.Token
	if tokenRate != nil {
		token = tokenRate.WrapToken(token)
	}
	return Endpoints{
		Authorize: func(ctx context.Context, request any) (any, error) {
			req, ok := request.(service.AuthorizeRequest)
			if !ok {
				return nil, &service.HTTPError{Status: 500, Code: "server_error", Message: "invalid authorize request"}
			}
			return authorize(ctx, req)
		},
		Token: func(ctx context.Context, request any) (any, error) {
			req, ok := request.(service.TokenRequest)
			if !ok {
				return nil, &service.HTTPError{Status: 500, Code: "server_error", Message: "invalid token request"}
			}
			return token(ctx, req)
		},
		UserInfo: func(ctx context.Context, request any) (any, error) {
			req, ok := request.(string)
			if !ok {
				return nil, &service.HTTPError{Status: 500, Code: "server_error", Message: "invalid userinfo request"}
			}
			return svc.UserInfo(ctx, req)
		},
		Discovery: func(ctx context.Context, _ any) (any, error) {
			return svc.Discovery(ctx), nil
		},
		JWKS: func(ctx context.Context, _ any) (any, error) {
			return svc.JWKS(ctx), nil
		},
		Logout: func(ctx context.Context, request any) (any, error) {
			req, ok := request.(LogoutRequest)
			if !ok {
				return nil, &service.HTTPError{Status: 500, Code: "server_error", Message: "invalid logout request"}
			}
			redirect, ok := svc.Logout(ctx, req.PostLogoutRedirectURI, req.State)
			return LogoutResponse{Redirect: redirect, OK: ok}, nil
		},
	}
}

type IPRateLimiter struct {
	mu      sync.Mutex
	limit   rate.Limit
	burst   int
	now     func() time.Time
	entries map[string]*rateEntry
}

type rateEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func NewIPRateLimiter(r rate.Limit, burst int, now func() time.Time) *IPRateLimiter {
	if now == nil {
		now = time.Now
	}
	return &IPRateLimiter{limit: r, burst: burst, now: now, entries: map[string]*rateEntry{}}
}

func (l *IPRateLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for key, entry := range l.entries {
		if now.Sub(entry.lastSeen) > 10*time.Minute {
			delete(l.entries, key)
		}
	}
	entry, ok := l.entries[ip]
	if !ok {
		entry = &rateEntry{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.entries[ip] = entry
	}
	entry.lastSeen = now
	return entry.limiter.Allow()
}

func (l *IPRateLimiter) WrapAuthorize(next func(context.Context, service.AuthorizeRequest) (*service.AuthorizeResponse, error)) func(context.Context, service.AuthorizeRequest) (*service.AuthorizeResponse, error) {
	return func(ctx context.Context, req service.AuthorizeRequest) (*service.AuthorizeResponse, error) {
		if !l.Allow(remoteHost(req.HTTPRequest.RemoteAddr)) {
			return nil, &service.HTTPError{Status: 429, Code: "rate_limited", Message: "rate limit exceeded"}
		}
		return next(ctx, req)
	}
}

func (l *IPRateLimiter) WrapToken(next func(context.Context, service.TokenRequest) (*service.TokenResponse, error)) func(context.Context, service.TokenRequest) (*service.TokenResponse, error) {
	return func(ctx context.Context, req service.TokenRequest) (*service.TokenResponse, error) {
		if ip, ok := ctx.Value(remoteAddrKey{}).(string); ok && !l.Allow(remoteHost(ip)) {
			return nil, &service.HTTPError{Status: 429, Code: "rate_limited", Message: "rate limit exceeded"}
		}
		return next(ctx, req)
	}
}

type remoteAddrKey struct{}

func WithRemoteAddr(ctx context.Context, remoteAddr string) context.Context {
	return context.WithValue(ctx, remoteAddrKey{}, remoteAddr)
}

func remoteHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
