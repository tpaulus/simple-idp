package certauth

import (
	"net/url"
	"testing"
)

func FuzzParseInfoCommonName(f *testing.F) {
	f.Add(url.QueryEscape(`Subject="CN=tom-laptop"`))
	f.Add(url.QueryEscape(`Subject="CN=tom\,laptop,OU=Home"`))
	f.Fuzz(func(_ *testing.T, input string) {
		_, _ = ParseInfoCommonName(input)
	})
}
