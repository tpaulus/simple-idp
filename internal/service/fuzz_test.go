package service

import "testing"

func FuzzExactRedirectMatch(f *testing.F) {
	allowed := []string{"https://grafana.example.test/login/generic_oauth"}
	f.Add("https://grafana.example.test/login/generic_oauth")
	f.Add("https://grafana.example.test/login/generic_oauth/extra")
	f.Fuzz(func(_ *testing.T, candidate string) {
		_ = ExactRedirectMatch(allowed, candidate)
	})
}
