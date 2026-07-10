package service

func ExactRedirectMatch(allowed []string, candidate string) bool {
	for _, allowedURI := range allowed {
		if allowedURI == candidate {
			return true
		}
	}
	return false
}
