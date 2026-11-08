package saml

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/errs"
)

// recordingReplayStore is a concurrency-safe AssertionReplayStore that records calls. |
// recordingReplayStore 是记录调用的并发安全 AssertionReplayStore。
type recordingReplayStore struct {
	mu       sync.Mutex
	seen     map[string]time.Time
	calls    int
	expiries []time.Time
	err      error
}

// newRecordingReplayStore returns an empty recording replay store. | newRecordingReplayStore 返回
// 空的记录型重放存储。
func newRecordingReplayStore() *recordingReplayStore {
	return &recordingReplayStore{seen: make(map[string]time.Time)}
}

// SeenAndStore records assertionID until expiresAt and reports whether it was already recorded. |
// SeenAndStore 记录 assertionID 直到 expiresAt，并报告其是否已被记录。
func (s *recordingReplayStore) SeenAndStore(_ context.Context, assertionID string, expiresAt, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.expiries = append(s.expiries, expiresAt)
	if s.err != nil {
		return false, s.err
	}
	if existing, ok := s.seen[assertionID]; ok && now.Before(existing) {
		return true, nil
	}
	s.seen[assertionID] = expiresAt
	return false, nil
}

// snapshot returns the call count and the recorded expiries. | snapshot 返回调用次数与记录的过期时间。
func (s *recordingReplayStore) snapshot() (int, []time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, append([]time.Time(nil), s.expiries...)
}

// oneTimeUseResponse inserts Conditions/OneTimeUse into samlValidResponse and optionally sets
// SessionNotOnOrAfter on its AuthnStatement. | oneTimeUseResponse 在 samlValidResponse 的 Conditions
// 中插入 OneTimeUse，并可选设置其 AuthnStatement 的 SessionNotOnOrAfter。
func oneTimeUseResponse(now time.Time, sessionNotOnOrAfter string) string {
	document := samlValidResponse(now)
	document = strings.Replace(document, `</saml:Conditions>`, `<saml:OneTimeUse/></saml:Conditions>`, 1)
	return withSessionNotOnOrAfter(document, sessionNotOnOrAfter)
}

// withSessionNotOnOrAfter sets SessionNotOnOrAfter on the first AuthnStatement. |
// withSessionNotOnOrAfter 在首个 AuthnStatement 上设置 SessionNotOnOrAfter。
func withSessionNotOnOrAfter(document, value string) string {
	if value == "" {
		return document
	}
	return strings.Replace(document, `SessionIndex="session-1">`,
		`SessionIndex="session-1" SessionNotOnOrAfter="`+value+`">`, 1)
}

// oneTimeUseOptions returns validation options without a Store. | oneTimeUseOptions 返回未配置 Store
// 的校验选项。
func oneTimeUseOptions() ResponseValidationOptions {
	return ResponseValidationOptions{
		SPEntityID:  "https://sp.example/metadata",
		ACSURL:      "https://sp.example/saml/acs",
		IDPEntityID: "https://idp.example/metadata",
		Now:         func() time.Time { return samlTestNow },
	}
}

// TestValidateOneTimeUseReplayStore covers single use, replay, fallback and failure policies. |
// TestValidateOneTimeUseReplayStore 覆盖单次使用、重放、回退与失败策略。
func TestValidateOneTimeUseReplayStore(t *testing.T) {
	document := []byte(oneTimeUseResponse(samlTestNow, ""))

	t.Run("single use is accepted", func(t *testing.T) {
		store := newRecordingReplayStore()
		opts := oneTimeUseOptions()
		opts.AssertionReplayStore = store
		if _, err := ValidateResponse(context.Background(), document, opts); err != nil {
			t.Fatalf("first use: %v", err)
		}
		calls, expiries := store.snapshot()
		if calls != 1 {
			t.Fatalf("calls = %d", calls)
		}
		if want := samlTestNow.Add(5 * time.Minute); !expiries[0].Equal(want) {
			t.Fatalf("expiry = %s, want %s", expiries[0], want)
		}
	})

	t.Run("second use is a replay", func(t *testing.T) {
		store := newRecordingReplayStore()
		opts := oneTimeUseOptions()
		opts.AssertionReplayStore = store
		if _, err := ValidateResponse(context.Background(), document, opts); err != nil {
			t.Fatalf("first use: %v", err)
		}
		if _, err := ValidateResponse(context.Background(), document, opts); !errors.Is(err, ErrReplay) {
			t.Fatalf("second use error = %v, want ErrReplay", err)
		}
	})

	t.Run("Store fallback enforces replay", func(t *testing.T) {
		store := NewMemoryStore()
		opts := oneTimeUseOptions()
		opts.Store = store
		if _, err := ValidateResponse(context.Background(), document, opts); err != nil {
			t.Fatalf("first use: %v", err)
		}
		if _, err := ValidateResponse(context.Background(), document, opts); !errors.Is(err, ErrReplay) {
			t.Fatalf("second use error = %v, want ErrReplay", err)
		}
	})

	t.Run("separate replay store and Store both record", func(t *testing.T) {
		replayStore := newRecordingReplayStore()
		store := NewMemoryStore()
		opts := oneTimeUseOptions()
		opts.Store = store
		opts.AssertionReplayStore = replayStore
		if _, err := ValidateResponse(context.Background(), document, opts); err != nil {
			t.Fatalf("first use: %v", err)
		}
		if calls, _ := replayStore.snapshot(); calls != 1 {
			t.Fatalf("replay store calls = %d", calls)
		}
		fresh, err := store.SaveAssertion(context.Background(), "assert-1", samlTestNow.Add(time.Minute), samlTestNow)
		if err != nil {
			t.Fatalf("SaveAssertion: %v", err)
		}
		if fresh {
			t.Fatalf("Store did not record the one-time-use assertion")
		}
	})

	t.Run("replay store error is returned", func(t *testing.T) {
		sentinel := errs.New("replay store unavailable | 重放存储不可用")
		store := newRecordingReplayStore()
		store.err = sentinel
		opts := oneTimeUseOptions()
		opts.AssertionReplayStore = store
		if _, err := ValidateResponse(context.Background(), document, opts); !errors.Is(err, sentinel) {
			t.Fatalf("error = %v, want replay store error", err)
		}
	})

	t.Run("one-time use without a store fails closed", func(t *testing.T) {
		if _, err := ValidateResponse(context.Background(), document, oneTimeUseOptions()); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("error = %v, want ErrInvalidConfig", err)
		}
	})

	t.Run("Store without AssertionReplayStore fails closed", func(t *testing.T) {
		opts := oneTimeUseOptions()
		opts.Store = storeWithoutArtifacts{}
		if _, err := ValidateResponse(context.Background(), document, opts); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("error = %v, want ErrInvalidConfig", err)
		}
	})

	t.Run("explicit opt-in accepts without a store", func(t *testing.T) {
		opts := oneTimeUseOptions()
		opts.AllowOneTimeUseWithoutReplayStore = true
		if _, err := ValidateResponse(context.Background(), document, opts); err != nil {
			t.Fatalf("explicit opt-in: %v", err)
		}
	})

	t.Run("assertions without OneTimeUse need no store", func(t *testing.T) {
		if _, err := ValidateResponse(context.Background(), []byte(samlValidResponse(samlTestNow)), oneTimeUseOptions()); err != nil {
			t.Fatalf("plain assertion: %v", err)
		}
	})
}

// TestValidateOneTimeUseConcurrent checks that exactly one concurrent validation wins. |
// TestValidateOneTimeUseConcurrent 校验并发校验中恰好一个成功。
func TestValidateOneTimeUseConcurrent(t *testing.T) {
	store := newRecordingReplayStore()
	opts := oneTimeUseOptions()
	opts.AssertionReplayStore = store
	document := []byte(oneTimeUseResponse(samlTestNow, ""))
	const goroutines = 16
	start := make(chan struct{})
	results := make(chan error, goroutines)
	var wg sync.WaitGroup
	for index := 0; index < goroutines; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := ValidateResponse(context.Background(), document, opts)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	successes, replays := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrReplay):
			replays++
		default:
			t.Fatalf("unexpected concurrent error: %v", err)
		}
	}
	if successes != 1 || replays != goroutines-1 {
		t.Fatalf("successes = %d, replays = %d", successes, replays)
	}
}

// TestValidateSessionNotOnOrAfter covers expiry, clock skew and malformed values. |
// TestValidateSessionNotOnOrAfter 覆盖过期、时钟偏移与非法取值。
func TestValidateSessionNotOnOrAfter(t *testing.T) {
	const skew = 2 * time.Minute
	cases := []struct {
		name      string
		value     string
		clockSkew time.Duration
		want      error
	}{
		{name: "future session accepted", value: FormatTime(samlTestNow.Add(5 * time.Minute))},
		{name: "expired session rejected", value: FormatTime(samlTestNow.Add(-3 * time.Minute)), want: ErrResponseExpired},
		{name: "boundary equals skew rejected", value: FormatTime(samlTestNow.Add(-skew)), want: ErrResponseExpired},
		{name: "inside skew accepted", value: FormatTime(samlTestNow.Add(-skew + time.Second))},
		{name: "custom skew accepts", value: FormatTime(samlTestNow.Add(-9 * time.Minute)), clockSkew: 10 * time.Minute},
		{name: "custom skew rejects", value: FormatTime(samlTestNow.Add(-11 * time.Minute)), clockSkew: 10 * time.Minute, want: ErrResponseExpired},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			opts := oneTimeUseOptions()
			opts.ClockSkew = test.clockSkew
			document := []byte(withSessionNotOnOrAfter(samlValidResponse(samlTestNow), test.value))
			_, err := ValidateResponse(context.Background(), document, opts)
			if test.want == nil {
				if err != nil {
					t.Fatalf("ValidateResponse: %v", err)
				}
				return
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
	t.Run("malformed session expiry rejected", func(t *testing.T) {
		document := []byte(withSessionNotOnOrAfter(samlValidResponse(samlTestNow), "not-a-time"))
		if _, err := ValidateResponse(context.Background(), document, oneTimeUseOptions()); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("error = %v, want ErrInvalidRequest", err)
		}
	})
}

// TestValidateSessionNotOnOrAfterAcrossStatements rejects any expired AuthnStatement. |
// TestValidateSessionNotOnOrAfterAcrossStatements 拒绝任一已过期的 AuthnStatement。
func TestValidateSessionNotOnOrAfterAcrossStatements(t *testing.T) {
	expired := `<saml:AuthnStatement AuthnInstant="` + FormatTime(samlTestNow) + `" SessionIndex="session-2" SessionNotOnOrAfter="` +
		FormatTime(samlTestNow.Add(-3*time.Minute)) + `"><saml:AuthnContext><saml:AuthnContextClassRef>` +
		AuthnContextPasswordProtectedTransport + `</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`
	document := strings.Replace(samlValidResponse(samlTestNow), `</saml:Assertion>`, expired+`</saml:Assertion>`, 1)
	if _, err := ValidateResponse(context.Background(), []byte(document), oneTimeUseOptions()); !errors.Is(err, ErrResponseExpired) {
		t.Fatalf("error = %v, want ErrResponseExpired", err)
	}
}

// TestValidateSessionNotOnOrAfterBoundsReplayExpiry checks the expiry passed to the replay store. |
// TestValidateSessionNotOnOrAfterBoundsReplayExpiry 校验传给重放存储的过期时间。
func TestValidateSessionNotOnOrAfterBoundsReplayExpiry(t *testing.T) {
	cases := []struct {
		name    string
		session time.Time
		want    time.Time
	}{
		{name: "session bounds replay expiry", session: samlTestNow.Add(time.Minute), want: samlTestNow.Add(time.Minute)},
		{name: "conditions bound replay expiry", session: samlTestNow.Add(9 * time.Minute), want: samlTestNow.Add(5 * time.Minute)},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			store := newRecordingReplayStore()
			opts := oneTimeUseOptions()
			opts.AssertionReplayStore = store
			document := []byte(oneTimeUseResponse(samlTestNow, FormatTime(test.session)))
			if _, err := ValidateResponse(context.Background(), document, opts); err != nil {
				t.Fatalf("ValidateResponse: %v", err)
			}
			calls, expiries := store.snapshot()
			if calls != 1 || !expiries[0].Equal(test.want) {
				t.Fatalf("calls = %d, expiry = %s, want %s", calls, expiries[0], test.want)
			}
		})
	}
}

// TestValidateSessionExpiredSkipsReplayStore checks expiry is rejected before replay recording. |
// TestValidateSessionExpiredSkipsReplayStore 校验过期在记录重放之前被拒绝。
func TestValidateSessionExpiredSkipsReplayStore(t *testing.T) {
	store := newRecordingReplayStore()
	opts := oneTimeUseOptions()
	opts.AssertionReplayStore = store
	document := []byte(oneTimeUseResponse(samlTestNow, FormatTime(samlTestNow.Add(-3*time.Minute))))
	if _, err := ValidateResponse(context.Background(), document, opts); !errors.Is(err, ErrResponseExpired) {
		t.Fatalf("error = %v, want ErrResponseExpired", err)
	}
	if calls, _ := store.snapshot(); calls != 0 {
		t.Fatalf("replay store calls = %d, want 0", calls)
	}
}
