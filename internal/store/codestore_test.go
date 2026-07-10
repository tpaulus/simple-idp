package store

import (
	"sync"
	"testing"
	"time"
)

func TestCodeStoreConsumeOnce(t *testing.T) {
	now := time.Now()
	store := NewCodeStore(4, func() time.Time { return now })
	var hash [32]byte
	copy(hash[:], []byte("12345678901234567890123456789012"))
	if err := store.Put(AuthorizationCode{Hash: hash, ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatalf("put code: %v", err)
	}
	if _, err := store.Consume(hash); err != nil {
		t.Fatalf("consume code: %v", err)
	}
	if _, err := store.Consume(hash); err == nil {
		t.Fatal("expected second consume to fail")
	}
}

func TestCodeStoreConcurrentConsume(t *testing.T) {
	now := time.Now()
	store := NewCodeStore(4, func() time.Time { return now })
	var hash [32]byte
	copy(hash[:], []byte("abcdefghijklmnopqrstuvwxzy123456"))
	if err := store.Put(AuthorizationCode{Hash: hash, ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatalf("put code: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	results := make(chan error, 2)
	for range 2 {
		go func() {
			defer wg.Done()
			_, err := store.Consume(hash)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly one successful consume, got %d", successes)
	}
}
