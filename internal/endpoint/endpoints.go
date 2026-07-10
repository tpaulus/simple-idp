package endpoint

import (
	"context"
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/tpaulus/simple-idp/internal/service"
)

type Endpoints struct {
	Authorize func(context.Context, service.AuthorizeRequest) (*service.AuthorizeResponse, error)
	Token     func(context.Context, service.TokenRequest) (*service.TokenResponse, error)
	UserInfo  func(context.Context, string) (map[string]any, error)
	Discovery func(context.Context) map[string]any
	JWKS      func(context.Context) any
	Logout    func(context.Context, string, string) (string, bool)
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
		Authorize: authorize,
		Token:     token,
		UserInfo:  svc.UserInfo,
		Discovery: svc.Discovery,
		JWKS: func(ctx context.Context) any {
			return svc.JWKS(ctx)
		},
		Logout: svc.Logout,
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
