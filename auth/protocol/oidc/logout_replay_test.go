package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// errLogoutReplay is a deterministic store failure. | errLogoutReplay 是确定性的存储失败。
var errLogoutReplay = errors.New("logout replay store failure")

// mutableClock is a concurrency-safe adjustable clock. | mutableClock 是并发安全可调整的时钟。
type mutableClock struct {
	mu  sync.Mutex
	now time.Time
}

// Now returns the current time. | Now 返回当前时间。
func (c *mutableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward. | Advance 向前调整时钟。
func (c *mutableClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// errorLogoutReplayStore always fails. | errorLogoutReplayStore 总是失败。
type errorLogoutReplayStore struct{}

// Accept implements LogoutReplayStore with a permanent error. | Accept 以永久错误实现 LogoutReplayStore。
func (errorLogoutReplayStore) Accept(context.Context, string, time.Time) (bool, error) {
	return false, errLogoutReplay
}

// logoutReplayClaims builds a valid logout token claim set. | logoutReplayClaims 构建合法登出令牌声明集。
func logoutReplayClaims(issuer string, iat time.Time, jti string) map[string]any {
	return map[string]any{
		"iss":    issuer,
		"sub":    "user-1",
		"aud":    []string{"web"},
		"iat":    iat.Unix(),
		"jti":    jti,
		"sid":    "sid-1",
		"events": map[string]any{BackchannelLogoutEvent: map[string]any{}},
	}
}

func TestMemoryLogoutReplayStore(t *testing.T) {
	fixed := time.Unix(1_700_000_000, 0).UTC()
	clock := &mutableClock{now: fixed}
	var nilStore *MemoryLogoutReplayStore
	if _, err := nilStore.Accept(context.Background(), "jti", fixed.Add(time.Minute)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("nil store = %v", err)
	}
	store := NewMemoryLogoutReplayStoreWithClock(2, clock.Now)
	if _, err := store.Accept(context.Background(), "", fixed.Add(time.Minute)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("empty jti = %v", err)
	}
	if fresh, err := store.Accept(context.Background(), "a", fixed.Add(10*time.Minute)); err != nil || !fresh {
		t.Fatalf("first accept = %v err=%v", fresh, err)
	}
	if fresh, err := store.Accept(context.Background(), "a", fixed.Add(10*time.Minute)); err != nil || fresh {
		t.Fatalf("replay = %v err=%v", fresh, err)
	}
	if fresh, err := store.Accept(context.Background(), "b", fixed.Add(time.Minute)); err != nil || !fresh {
		t.Fatalf("accept b = %v err=%v", fresh, err)
	}
	// At capacity the earliest deadline is evicted. | 达到容量时淘汰最早到期的标识。
	if fresh, err := store.Accept(context.Background(), "c", fixed.Add(5*time.Minute)); err != nil || !fresh {
		t.Fatalf("accept c = %v err=%v", fresh, err)
	}
	if len(store.entries) != 2 {
		t.Fatalf("entries = %d want 2", len(store.entries))
	}
	if fresh, err := store.Accept(context.Background(), "b", fixed.Add(30*time.Minute)); err != nil || !fresh {
		t.Fatalf("evicted jti = %v err=%v", fresh, err)
	}

	// Expired identifiers are pruned and may be presented again. | 到期标识会被清除并可再次提交。
	clock.Advance(40 * time.Minute)
	if fresh, err := store.Accept(context.Background(), "a", time.Time{}); err != nil || !fresh {
		t.Fatalf("expired jti = %v err=%v", fresh, err)
	}
	if _, err := store.Accept(context.Background(), "a", fixed); err != nil {
		t.Fatalf("replay after zero deadline = %v", err)
	}

	def := NewMemoryLogoutReplayStore(0)
	if def.capacity != defaultLogoutReplayCapacity || def.now == nil {
		t.Fatalf("defaults = %+v", def)
	}
	defClock := NewMemoryLogoutReplayStoreWithClock(-1, nil)
	if defClock.capacity != defaultLogoutReplayCapacity || defClock.now == nil {
		t.Fatalf("defaults with nil clock = %+v", defClock)
	}
}

func TestMemoryLogoutReplayStoreConcurrent(t *testing.T) {
	fixed := time.Unix(1_700_000_000, 0).UTC()
	clock := &mutableClock{now: fixed}
	store := NewMemoryLogoutReplayStoreWithClock(64, clock.Now)
	var freshCount atomic.Int32
	var errCount atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fresh, err := store.Accept(context.Background(), "same-jti", fixed.Add(5*time.Minute))
			if err != nil {
				errCount.Add(1)
				return
			}
			if fresh {
				freshCount.Add(1)
			}
		}()
	}
	wg.Wait()
	if freshCount.Load() != 1 || errCount.Load() != 0 {
		t.Fatalf("fresh = %d errors = %d", freshCount.Load(), errCount.Load())
	}
}

func TestProviderLogoutReplay(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	provider := fixture.provider
	fixed := time.Unix(1_700_000_000, 0).UTC()
	provider.now = func() time.Time { return fixed }
	clock := &mutableClock{now: fixed}
	store := NewMemoryLogoutReplayStoreWithClock(8, clock.Now)
	provider.config.LogoutReplay = store
	ctx := context.Background()

	claims := logoutReplayClaims(fixture.server.URL, fixed, "jti-replay")
	raw := signLogoutClaims(t, provider, claims)
	if _, err := provider.ValidateLogoutToken(ctx, raw, fixture.server.URL, "web"); err != nil {
		t.Fatalf("first validation: %v", err)
	}
	if _, err := provider.ValidateLogoutToken(ctx, raw, fixture.server.URL, "web"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("replay = %v", err)
	}

	// Once the iat acceptance window has elapsed the same jti is fresh again when the token itself
	// is reissued with a current iat. | iat 接受窗口过去后，若令牌以当前 iat 重新签发，同一 jti
	// 再次被视为新标识。
	provider.now = func() time.Time { return fixed.Add(6 * time.Minute) }
	clock.Advance(6 * time.Minute)
	reissued := signLogoutClaims(t, provider, logoutReplayClaims(fixture.server.URL, fixed.Add(6*time.Minute), "jti-replay"))
	if _, err := provider.ValidateLogoutToken(ctx, reissued, fixture.server.URL, "web"); err != nil {
		t.Fatalf("reissued jti: %v", err)
	}

	// A store error never makes a token acceptable. | 存储错误绝不会让令牌被接受。
	provider.config.LogoutReplay = errorLogoutReplayStore{}
	freshClaims := signLogoutClaims(t, provider, logoutReplayClaims(fixture.server.URL, fixed.Add(6*time.Minute), "jti-store-error"))
	if _, err := provider.ValidateLogoutToken(ctx, freshClaims, fixture.server.URL, "web"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("store error = %v", err)
	}

	// The provider-issued token is recorded as well. | 提供方签发的令牌同样会被记录。
	provider.config.LogoutReplay = store
	issued, err := provider.LogoutToken(fixture.client, "user-1", "sid-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.ValidateLogoutToken(ctx, issued, fixture.server.URL, "web"); err != nil {
		t.Fatalf("issued token: %v", err)
	}
	if _, err := provider.ValidateLogoutToken(ctx, issued, fixture.server.URL, "web"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("issued replay = %v", err)
	}
}

func TestProviderLogoutReplayConcurrent(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	provider := fixture.provider
	fixed := time.Unix(1_700_000_000, 0).UTC()
	provider.now = func() time.Time { return fixed }
	clock := &mutableClock{now: fixed}
	provider.config.LogoutReplay = NewMemoryLogoutReplayStoreWithClock(16, clock.Now)
	raw := signLogoutClaims(t, provider, logoutReplayClaims(fixture.server.URL, fixed, "jti-concurrent"))
	ctx := context.Background()
	var accepted atomic.Int32
	var rejected atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := provider.ValidateLogoutToken(ctx, raw, fixture.server.URL, "web"); err == nil {
				accepted.Add(1)
				return
			} else if !errors.Is(err, ErrInvalidToken) {
				rejected.Add(1)
				return
			}
			rejected.Add(1)
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 || rejected.Load() != 31 {
		t.Fatalf("accepted = %d rejected = %d", accepted.Load(), rejected.Load())
	}
}

func TestBackchannelLogoutReplay(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	provider := fixture.provider
	fixed := time.Unix(1_700_000_000, 0).UTC()
	provider.now = func() time.Time { return fixed }
	provider.config.LogoutReplay = NewMemoryLogoutReplayStoreWithClock(8, func() time.Time { return fixed })
	raw := signLogoutClaims(t, provider, logoutReplayClaims(fixture.server.URL, fixed, "jti-endpoint"))

	deliver := func(token string) *httptest.ResponseRecorder {
		form := url.Values{}
		if token != "" {
			form.Set("logout_token", token)
		}
		req := httptest.NewRequest(http.MethodPost, BackchannelLogoutPath, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		recorder := httptest.NewRecorder()
		provider.BackchannelLogout(recorder, req)
		return recorder
	}
	if recorder := deliver(raw); recorder.Code != http.StatusOK {
		t.Fatalf("first delivery = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder := deliver(raw); recorder.Code != http.StatusBadRequest {
		t.Fatalf("replayed delivery = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder := deliver(""); recorder.Code != http.StatusBadRequest {
		t.Fatalf("missing token = %d", recorder.Code)
	}
	get := httptest.NewRequest(http.MethodGet, BackchannelLogoutPath, nil)
	recorder := httptest.NewRecorder()
	provider.BackchannelLogout(recorder, get)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d", recorder.Code)
	}
}
