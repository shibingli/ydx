package service

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/shibingli/ydx/middleware/ratelimit"
)

type toggleLimitStore struct {
	inner *ratelimit.MemoryStore
	mu    sync.Mutex
	fail  bool
}

func (s *toggleLimitStore) Allow(ctx context.Context, key string, rate float64, burst int) (ratelimit.Decision, error) {
	s.mu.Lock()
	fail := s.fail
	s.mu.Unlock()
	if fail {
		return ratelimit.Decision{}, errors.New("limiter down | 限流器故障")
	}
	return s.inner.Allow(ctx, key, rate, burst)
}

func (s *toggleLimitStore) setFail(fail bool) {
	s.mu.Lock()
	s.fail = fail
	s.mu.Unlock()
}

func TestVerifyRestoresChallengeOnLimiterFailure(t *testing.T) {
	limiter := &toggleLimitStore{inner: ratelimit.NewMemoryStore(0)}
	m := newTestManager(t, func(o *Options) {
		o.Limits.Store = limiter
		o.Limits.FailClosed = true
	})
	challenge, record := createVisual(t, m, TypeText, testMeta())
	answer := answerFor(t, record)
	limiter.setFail(true)
	if _, err := m.Verify(context.Background(), VerifyRequest{ID: challenge.ID, Answer: answer, Meta: testMeta()}); !errors.Is(err, ErrStore) {
		t.Fatalf("expected store failure, got %v", err)
	}
	limiter.setFail(false)
	if _, err := m.Verify(context.Background(), VerifyRequest{ID: challenge.ID, Answer: answer, Meta: testMeta()}); err != nil {
		t.Fatalf("challenge was not restored: %v", err)
	}
}
