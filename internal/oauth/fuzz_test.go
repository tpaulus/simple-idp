package oauth

import "testing"

func FuzzParseScopes(f *testing.F) {
	f.Add("openid profile email")
	f.Add("openid   openid email")
	f.Fuzz(func(t *testing.T, input string) {
		_ = ParseScopes(input)
	})
}
