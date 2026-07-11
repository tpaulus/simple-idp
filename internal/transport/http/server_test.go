package httptransport

import (
	"net"
	"net/http/httptest"
	"testing"
)

func mustParseCIDR(s string) *net.IPNet {
	_, cidr, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return cidr
}

func TestClientIP(t *testing.T) {
	trusted := []*net.IPNet{mustParseCIDR("127.0.0.0/8"), mustParseCIDR("10.0.0.0/8")}

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{
			name:       "untrusted proxy, no XFF",
			remoteAddr: "203.0.113.5:1234",
			want:       "203.0.113.5:1234",
		},
		{
			name:       "untrusted proxy, XFF ignored",
			remoteAddr: "203.0.113.5:1234",
			xff:        "1.2.3.4",
			want:       "203.0.113.5:1234",
		},
		{
			name:       "trusted proxy, no XFF falls back to RemoteAddr",
			remoteAddr: "127.0.0.1:1234",
			want:       "127.0.0.1:1234",
		},
		{
			name:       "trusted proxy with XFF returns first entry",
			remoteAddr: "127.0.0.1:1234",
			xff:        "1.2.3.4",
			want:       "1.2.3.4",
		},
		{
			name:       "trusted proxy with multi-hop XFF returns leftmost entry",
			remoteAddr: "10.0.0.1:9999",
			xff:        "1.2.3.4, 10.0.0.5",
			want:       "1.2.3.4",
		},
		{
			name:       "trusted proxy with empty XFF falls back to RemoteAddr",
			remoteAddr: "127.0.0.1:1234",
			xff:        "",
			want:       "127.0.0.1:1234",
		},
		{
			name:       "no trusted nets configured",
			remoteAddr: "127.0.0.1:1234",
			xff:        "1.2.3.4",
			want:       "127.0.0.1:1234",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			nets := trusted
			if tc.name == "no trusted nets configured" {
				nets = nil
			}
			got := clientIP(req, nets)
			if got != tc.want {
				t.Errorf("clientIP() = %q, want %q", got, tc.want)
			}
		})
	}
}
