package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

func GenerateCode() (string, [32]byte, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", [32]byte{}, err
	}
	code := base64.RawURLEncoding.EncodeToString(buf)
	return code, sha256.Sum256([]byte(code)), nil
}

func HashCode(code string) [32]byte {
	return sha256.Sum256([]byte(code))
}

func ParseScopes(scope string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, part := range strings.Fields(scope) {
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		out = append(out, part)
	}
	return out
}

func HasScope(scopes []string, required string) bool {
	for _, scope := range scopes {
		if scope == required {
			return true
		}
	}
	return false
}

func VerifyPKCES256(challenge, verifier string) bool {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
}
