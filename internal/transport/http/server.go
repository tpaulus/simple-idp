package httptransport

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/tpaulus/simple-idp/internal/config"
	"github.com/tpaulus/simple-idp/internal/endpoint"
	"github.com/tpaulus/simple-idp/internal/service"
)

func NewHandler(_ *config.Config, eps endpoint.Endpoints, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, eps.Discovery(r.Context()))
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, eps.JWKS(r.Context()))
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, &service.HTTPError{Status: http.StatusMethodNotAllowed, Code: "method_not_allowed", Message: "method not allowed"})
			return
		}
		resp, err := eps.Authorize(r.Context(), service.AuthorizeRequest{
			ClientID:            r.URL.Query().Get("client_id"),
			RedirectURI:         r.URL.Query().Get("redirect_uri"),
			ResponseType:        r.URL.Query().Get("response_type"),
			Scope:               r.URL.Query().Get("scope"),
			State:               r.URL.Query().Get("state"),
			Nonce:               r.URL.Query().Get("nonce"),
			CodeChallenge:       r.URL.Query().Get("code_challenge"),
			CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
			HTTPRequest:         r,
		})
		if err != nil {
			writeError(w, err)
			return
		}
		http.Redirect(w, r, resp.RedirectURL, http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, &service.HTTPError{Status: http.StatusMethodNotAllowed, Code: "method_not_allowed", Message: "method not allowed"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			writeError(w, &service.HTTPError{Status: http.StatusBadRequest, Code: "invalid_request", Message: "invalid form body"})
			return
		}
		ctx := endpoint.WithRemoteAddr(r.Context(), r.RemoteAddr)
		resp, err := eps.Token(ctx, service.TokenRequest{
			GrantType:    r.PostForm.Get("grant_type"),
			Code:         r.PostForm.Get("code"),
			RedirectURI:  r.PostForm.Get("redirect_uri"),
			CodeVerifier: r.PostForm.Get("code_verifier"),
			AuthHeader:   r.Header.Get("Authorization"),
			FormClientID: r.PostForm.Get("client_id"),
			FormSecret:   r.PostForm.Get("client_secret"),
		})
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})
	userinfoHandler := func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		resp, err := eps.UserInfo(r.Context(), token)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
	mux.HandleFunc("/userinfo", userinfoHandler)
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) { logoutHandler(w, r, eps) })
	mux.HandleFunc("/oidc/v1/end_session", func(w http.ResponseWriter, r *http.Request) { logoutHandler(w, r, eps) })
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { writeText(w, http.StatusOK, "ok\n") })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { writeText(w, http.StatusOK, "ready\n") })
	return loggingMiddleware(logger, secureHeaders(mux))
}

func logoutHandler(w http.ResponseWriter, r *http.Request, eps endpoint.Endpoints) {
	if redirect, ok := eps.Logout(r.Context(), r.URL.Query().Get("post_logout_redirect_uri"), r.URL.Query().Get("state")); ok {
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
	writeText(w, http.StatusOK, "Logged out.\n")
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return parts[1]
	}
	return ""
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func loggingMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Info("request", "method", r.Method, "path", r.URL.Path, "remote_addr", r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeText(w http.ResponseWriter, status int, v string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, v)
}

func writeError(w http.ResponseWriter, err error) {
	httpErr := service.ToHTTPError(err)
	body := map[string]string{"error": httpErr.Code}
	if httpErr.Status == http.StatusInternalServerError {
		body["error_description"] = "internal server error"
	} else {
		body["error_description"] = httpErr.Message
	}
	writeJSON(w, httpErr.Status, body)
}
