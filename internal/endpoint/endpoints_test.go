package endpoint

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/tpaulus/simple-idp/internal/service"
)

func TestAuthorizeRateLimit(t *testing.T) {
	limiter := NewIPRateLimiter(rate.Every(time.Hour), 1, time.Now)
	wrapped := limiter.WrapAuthorize(func(context.Context, service.AuthorizeRequest) (*service.AuthorizeResponse, error) {
		return &service.AuthorizeResponse{}, nil
	})
	req := httptest.NewRequest("GET", "http://example.test/authorize", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	if _, err := wrapped(context.Background(), service.AuthorizeRequest{HTTPRequest: req}); err != nil {
		t.Fatalf("first request unexpectedly failed: %v", err)
	}
	if _, err := wrapped(context.Background(), service.AuthorizeRequest{HTTPRequest: req}); err == nil {
		t.Fatal("expected second request to be rate limited")
	}
}
