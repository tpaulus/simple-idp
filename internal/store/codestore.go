package store

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

type AuthorizationCode struct {
	Hash          [32]byte
	ClientID      string
	RedirectURI   string
	Subject       string
	Scopes        []string
	Nonce         string
	CodeChallenge string
	AuthTime      time.Time
	ExpiresAt     time.Time
}

type CodeStore struct {
	mu             sync.Mutex
	codes          map[string]AuthorizationCode
	maxOutstanding int
	now            func() time.Time
}

func NewCodeStore(maxOutstanding int, now func() time.Time) *CodeStore {
	if now == nil {
		now = time.Now
	}
	return &CodeStore{codes: map[string]AuthorizationCode{}, maxOutstanding: maxOutstanding, now: now}
}

func (s *CodeStore) Put(code AuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictExpiredLocked()
	if len(s.codes) >= s.maxOutstanding {
		return errors.New("too many outstanding authorization codes")
	}
	s.codes[hex.EncodeToString(code.Hash[:])] = code
	return nil
}

func (s *CodeStore) Consume(hash [32]byte) (AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictExpiredLocked()
	var foundKey string
	var found AuthorizationCode
	for key, candidate := range s.codes {
		if subtle.ConstantTimeCompare(candidate.Hash[:], hash[:]) == 1 {
			foundKey = key
			found = candidate
			break
		}
	}
	if foundKey == "" {
		return AuthorizationCode{}, errors.New("authorization code not found")
	}
	delete(s.codes, foundKey)
	if s.now().After(found.ExpiresAt) {
		return AuthorizationCode{}, errors.New("authorization code expired")
	}
	return found, nil
}

func (s *CodeStore) Outstanding() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictExpiredLocked()
	return len(s.codes)
}

func (s *CodeStore) evictExpiredLocked() {
	now := s.now()
	for key, code := range s.codes {
		if now.After(code.ExpiresAt) {
			delete(s.codes, key)
		}
	}
}
