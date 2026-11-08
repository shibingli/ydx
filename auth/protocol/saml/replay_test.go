package saml

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// compile-time interface checks for the in-memory replay stores. | 内存重放存储的编译期接口断言。
var (
	_ AssertionReplayStore   = (*MemoryAssertionReplayStore)(nil)
	_ AssertionReplayCleaner = (*MemoryAssertionReplayStore)(nil)
	_ AssertionReplayStore   = (*MemoryStore)(nil)
	_ AssertionReplayCleaner = (*MemoryStore)(nil)
)

// oneTimeUseDocument inserts Conditions/OneTimeUse into document. | oneTimeUseDocument 在 document
// 中插入 Conditions/OneTimeUse。
func oneTimeUseDocument(document string) []byte {
	return []byte(strings.Replace(document, `</saml:Conditions>`, `<saml:OneTimeUse/></saml:Conditions>`, 1))
}

// noBoundOneTimeUseResponse removes SubjectConfirmation and both NotOnOrAfter attributes from
// samlValidResponse. | noBoundOneTimeUseResponse 从 samlValidResponse 删除 SubjectConfirmation 与两个
// NotOnOrAfter 属性。
func noBoundOneTimeUseResponse() []byte {
	document := samlValidResponse(samlTestNow)
	start := strings.Index(document, `<saml:SubjectConfirmation `)
	end := strings.Index(document, `</saml:SubjectConfirmation>`)
	if start >= 0 && end > start {
		document = document[:start] + document[end+len(`</saml:SubjectConfirmation>`):]
	}
	bound := FormatTime(samlTestNow.Add(5 * time.Minute))
	document = strings.ReplaceAll(document, ` NotOnOrAfter="`+bound+`"`, "")
	return oneTimeUseDocument(document)
}

// laterBoundOneTimeUseResponse moves both NotOnOrAfter attributes to now+bound. |
// laterBoundOneTimeUseResponse 把两个 NotOnOrAfter 属性移动到 now+bound。
func laterBoundOneTimeUseResponse(bound time.Duration) []byte {
	original := FormatTime(samlTestNow.Add(5 * time.Minute))
	document := strings.ReplaceAll(samlValidResponse(samlTestNow), original, FormatTime(samlTestNow.Add(bound)))
	return oneTimeUseDocument(document)
}

// bearerBoundOneTimeUseResponse moves only SubjectConfirmationData/NotOnOrAfter to now+bound. |
// bearerBoundOneTimeUseResponse 仅把 SubjectConfirmationData/NotOnOrAfter 移动到 now+bound。
func bearerBoundOneTimeUseResponse(bound time.Duration) []byte {
	original := FormatTime(samlTestNow.Add(5 * time.Minute))
	document := strings.Replace(samlValidResponse(samlTestNow),
		`InResponseTo="req-1" NotOnOrAfter="`+original+`"`,
		`InResponseTo="req-1" NotOnOrAfter="`+FormatTime(samlTestNow.Add(bound))+`"`, 1)
	return oneTimeUseDocument(document)
}

// TestReplayWindowNormalized covers defaults and invalid configurations. |
// TestReplayWindowNormalized 覆盖默认值与非法配置。
func TestReplayWindowNormalized(t *testing.T) {
	normalized, err := (ReplayWindow{}).Normalized()
	if err != nil {
		t.Fatalf("zero window: %v", err)
	}
	if normalized.Fallback != DefaultReplayFallback || normalized.MinRetention != 0 || normalized.MaxRetention != 0 {
		t.Fatalf("zero window normalized = %+v", normalized)
	}
	custom := ReplayWindow{Fallback: 3 * time.Minute, MinRetention: time.Minute, MaxRetention: time.Hour}
	if normalized, err = custom.Normalized(); err != nil || normalized != custom {
		t.Fatalf("custom window = %+v, err = %v", normalized, err)
	}
	invalid := []ReplayWindow{
		{Fallback: -time.Second},
		{MinRetention: -time.Second},
		{MaxRetention: -time.Second},
		{MinRetention: 2 * time.Minute, MaxRetention: time.Minute},
	}
	for _, window := range invalid {
		if _, err := window.Normalized(); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("window %+v error = %v, want ErrInvalidConfig", window, err)
		}
	}
}

// TestValidateReplayWindowRetention checks bound-derived, fallback, minimum and maximum retention.
// | TestValidateReplayWindowRetention 校验按上界计算、回退、最小与最大保留。
func TestValidateReplayWindowRetention(t *testing.T) {
	cases := []struct {
		name     string
		document []byte
		window   ReplayWindow
		want     time.Time
	}{
		{
			name:     "no bound falls back to ten minutes",
			document: noBoundOneTimeUseResponse(),
			want:     samlTestNow.Add(DefaultReplayFallback),
		},
		{
			name:     "assertion bound after former fallback is honored",
			document: laterBoundOneTimeUseResponse(20 * time.Minute),
			want:     samlTestNow.Add(20 * time.Minute),
		},
		{
			name:     "bearer bound wins over later conditions",
			document: bearerBoundOneTimeUseResponse(2 * time.Minute),
			want:     samlTestNow.Add(2 * time.Minute),
		},
		{
			name:     "minimum retention raises the expiry",
			document: []byte(oneTimeUseResponse(samlTestNow, "")),
			window:   ReplayWindow{MinRetention: 15 * time.Minute},
			want:     samlTestNow.Add(15 * time.Minute),
		},
		{
			name:     "maximum retention lowers the expiry",
			document: laterBoundOneTimeUseResponse(20 * time.Minute),
			window:   ReplayWindow{MaxRetention: 5 * time.Minute},
			want:     samlTestNow.Add(5 * time.Minute),
		},
		{
			name:     "maximum retention clamps the fallback",
			document: noBoundOneTimeUseResponse(),
			window:   ReplayWindow{MaxRetention: 5 * time.Minute},
			want:     samlTestNow.Add(5 * time.Minute),
		},
		{
			name:     "minimum retention raises the fallback",
			document: noBoundOneTimeUseResponse(),
			window:   ReplayWindow{MinRetention: 15 * time.Minute},
			want:     samlTestNow.Add(15 * time.Minute),
		},
		{
			name:     "custom fallback is used without a bound",
			document: noBoundOneTimeUseResponse(),
			window:   ReplayWindow{Fallback: 3 * time.Minute},
			want:     samlTestNow.Add(3 * time.Minute),
		},
		{
			name:     "minimum below the bound does not change it",
			document: []byte(oneTimeUseResponse(samlTestNow, "")),
			window:   ReplayWindow{MinRetention: time.Minute},
			want:     samlTestNow.Add(5 * time.Minute),
		},
		{
			name:     "maximum above the bound does not change it",
			document: []byte(oneTimeUseResponse(samlTestNow, "")),
			window:   ReplayWindow{MaxRetention: 15 * time.Minute},
			want:     samlTestNow.Add(5 * time.Minute),
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			store := newRecordingReplayStore()
			opts := oneTimeUseOptions()
			opts.AssertionReplayStore = store
			opts.ReplayWindow = test.window
			if _, err := ValidateResponse(context.Background(), test.document, opts); err != nil {
				t.Fatalf("ValidateResponse: %v", err)
			}
			calls, expiries := store.snapshot()
			if calls != 1 || len(expiries) != 1 {
				t.Fatalf("calls = %d, expiries = %v", calls, expiries)
			}
			if !expiries[0].Equal(test.want) {
				t.Fatalf("expiry = %s, want %s", expiries[0], test.want)
			}
		})
	}
}

// TestValidateReplayWindowInvalid checks invalid windows fail before any replay record is written.
// | TestValidateReplayWindowInvalid 校验非法窗口在写入任何重放记录前失败。
func TestValidateReplayWindowInvalid(t *testing.T) {
	store := newRecordingReplayStore()
	opts := oneTimeUseOptions()
	opts.AssertionReplayStore = store
	opts.ReplayWindow = ReplayWindow{MinRetention: 2 * time.Minute, MaxRetention: time.Minute}
	if _, err := ValidateResponse(context.Background(), oneTimeUseDocument(samlValidResponse(samlTestNow)), opts); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("error = %v, want ErrInvalidConfig", err)
	}
	if calls, _ := store.snapshot(); calls != 0 {
		t.Fatalf("replay store calls = %d, want 0", calls)
	}
}

// TestMemoryAssertionReplayStore covers expiry, cleanup, empty identifiers and nil receivers. |
// TestMemoryAssertionReplayStore 覆盖过期、清理、空标识与空接收者。
func TestMemoryAssertionReplayStore(t *testing.T) {
	ctx := context.Background()
	var zero MemoryAssertionReplayStore
	seen, err := zero.SeenAndStore(ctx, "assert-1", samlTestNow.Add(time.Minute), samlTestNow)
	if err != nil || seen {
		t.Fatalf("first SeenAndStore = %v, %v", seen, err)
	}
	seen, err = zero.SeenAndStore(ctx, "assert-1", samlTestNow.Add(time.Minute), samlTestNow.Add(30*time.Second))
	if err != nil || !seen {
		t.Fatalf("second SeenAndStore = %v, %v", seen, err)
	}
	seen, err = zero.SeenAndStore(ctx, "assert-1", samlTestNow.Add(2*time.Minute), samlTestNow.Add(time.Minute))
	if err != nil || seen {
		t.Fatalf("expired SeenAndStore = %v, %v", seen, err)
	}
	if _, err := zero.SeenAndStore(ctx, "", samlTestNow, samlTestNow); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("empty id error = %v", err)
	}

	store := NewMemoryAssertionReplayStore()
	if _, err := store.SeenAndStore(ctx, "assert-a", samlTestNow.Add(time.Minute), samlTestNow); err != nil {
		t.Fatalf("store assert-a: %v", err)
	}
	if _, err := store.SeenAndStore(ctx, "assert-b", samlTestNow.Add(2*time.Minute), samlTestNow); err != nil {
		t.Fatalf("store assert-b: %v", err)
	}
	if removed, err := store.CleanupAssertions(ctx, samlTestNow.Add(time.Minute)); err != nil || removed != 1 {
		t.Fatalf("cleanup = %d, %v, want 1", removed, err)
	}
	if removed, err := store.CleanupAssertions(ctx, samlTestNow.Add(time.Minute)); err != nil || removed != 0 {
		t.Fatalf("second cleanup = %d, %v, want 0", removed, err)
	}
	seen, err = store.SeenAndStore(ctx, "assert-a", samlTestNow.Add(3*time.Minute), samlTestNow.Add(time.Minute))
	if err != nil || seen {
		t.Fatalf("cleaned identifier = %v, %v", seen, err)
	}

	var nilStore *MemoryAssertionReplayStore
	if _, err := nilStore.SeenAndStore(ctx, "assert-1", samlTestNow, samlTestNow); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil store error = %v", err)
	}
	if _, err := nilStore.CleanupAssertions(ctx, samlTestNow); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil cleanup error = %v", err)
	}
}

// TestMemoryAssertionReplayStoreConcurrent checks exactly one concurrent caller sees a fresh
// identifier. | TestMemoryAssertionReplayStoreConcurrent 校验并发的同一新标识恰好一个调用者成功。
func TestMemoryAssertionReplayStoreConcurrent(t *testing.T) {
	store := NewMemoryAssertionReplayStore()
	const goroutines = 32
	start := make(chan struct{})
	results := make(chan bool, goroutines)
	var wg sync.WaitGroup
	for index := 0; index < goroutines; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			seen, err := store.SeenAndStore(context.Background(), "assert-concurrent", samlTestNow.Add(time.Minute), samlTestNow)
			if err != nil {
				t.Errorf("SeenAndStore: %v", err)
				results <- true
				return
			}
			results <- seen
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	fresh, replays := 0, 0
	for seen := range results {
		if seen {
			replays++
		} else {
			fresh++
		}
	}
	if fresh != 1 || replays != goroutines-1 {
		t.Fatalf("fresh = %d, replays = %d", fresh, replays)
	}
}

// TestMemoryStoreCleanupAssertions checks the Store-level cleaner and combined Cleanup. |
// TestMemoryStoreCleanupAssertions 校验 Store 级清理器与组合 Cleanup。
func TestMemoryStoreCleanupAssertions(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	if _, err := store.SaveAssertion(ctx, "assert-a", samlTestNow.Add(time.Minute), samlTestNow); err != nil {
		t.Fatalf("SaveAssertion assert-a: %v", err)
	}
	if _, err := store.SaveAssertion(ctx, "assert-b", samlTestNow.Add(2*time.Minute), samlTestNow); err != nil {
		t.Fatalf("SaveAssertion assert-b: %v", err)
	}
	if removed, err := store.CleanupAssertions(ctx, samlTestNow.Add(time.Minute)); err != nil || removed != 1 {
		t.Fatalf("CleanupAssertions = %d, %v, want 1", removed, err)
	}
	if fresh, err := store.SaveAssertion(ctx, "assert-a", samlTestNow.Add(3*time.Minute), samlTestNow.Add(time.Minute)); err != nil || !fresh {
		t.Fatalf("SaveAssertion after cleanup = %v, %v", fresh, err)
	}
	if err := store.Cleanup(ctx, samlTestNow.Add(10*time.Minute)); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if fresh, err := store.SaveAssertion(ctx, "assert-b", samlTestNow.Add(20*time.Minute), samlTestNow.Add(10*time.Minute)); err != nil || !fresh {
		t.Fatalf("SaveAssertion after Cleanup = %v, %v", fresh, err)
	}
	var nilStore *MemoryStore
	if _, err := nilStore.CleanupAssertions(ctx, samlTestNow); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil CleanupAssertions error = %v", err)
	}
	if err := nilStore.Cleanup(ctx, samlTestNow); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil Cleanup error = %v", err)
	}
}

// TestValidateReplayStoreTypedNilFailsClosed checks that typed-nil stores cannot disable replay
// detection, even with the explicit opt-in flag. | TestValidateReplayStoreTypedNilFailsClosed 校验
// 类型为空存储即使设置显式开关也不能禁用重放检测。
func TestValidateReplayStoreTypedNilFailsClosed(t *testing.T) {
	document := oneTimeUseDocument(samlValidResponse(samlTestNow))
	opts := oneTimeUseOptions()
	opts.AssertionReplayStore = (*MemoryAssertionReplayStore)(nil)
	opts.AllowOneTimeUseWithoutReplayStore = true
	if _, err := ValidateResponse(context.Background(), document, opts); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("typed-nil replay store error = %v, want ErrInvalidConfig", err)
	}
	opts = oneTimeUseOptions()
	opts.Store = (*MemoryStore)(nil)
	if _, err := ValidateResponse(context.Background(), document, opts); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("typed-nil Store error = %v, want ErrInvalidConfig", err)
	}
	// A non-OneTimeUse assertion still fails closed when the configured Store is unusable. |
	// 非 OneTimeUse 断言在配置的 Store 不可用时同样失败关闭。
	if _, err := ValidateResponse(context.Background(), []byte(samlValidResponse(samlTestNow)), opts); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("typed-nil Store plain assertion error = %v, want ErrInvalidConfig", err)
	}
}

// TestServiceProviderReplayWindow checks normalization and pass-through of the replay window. |
// TestServiceProviderReplayWindow 校验重放窗口的归一化与透传。
func TestServiceProviderReplayWindow(t *testing.T) {
	config := ServiceProviderConfig{
		EntityID:    "https://sp.example/metadata",
		ACSURL:      "https://sp.example/saml/acs",
		IDPMetadata: testMetadata(),
	}
	sp, err := NewServiceProvider(config)
	if err != nil {
		t.Fatalf("NewServiceProvider: %v", err)
	}
	if got := sp.Config().ReplayWindow; got.Fallback != DefaultReplayFallback || got.MinRetention != 0 || got.MaxRetention != 0 {
		t.Fatalf("default replay window = %+v", got)
	}
	config.ReplayWindow = ReplayWindow{MinRetention: 2 * time.Minute, MaxRetention: time.Minute}
	if _, err := NewServiceProvider(config); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid replay window error = %v, want ErrInvalidConfig", err)
	}

	store := newRecordingReplayStore()
	config.ReplayWindow = ReplayWindow{MinRetention: 7 * time.Minute}
	config.AssertionReplayStore = store
	config.AllowIDPInitiated = true
	config.Now = func() time.Time { return samlTestNow }
	sp, err = NewServiceProvider(config)
	if err != nil {
		t.Fatalf("NewServiceProvider with window: %v", err)
	}
	if _, err := sp.validateResponse(context.Background(), []byte(oneTimeUseResponse(samlTestNow, ""))); err != nil {
		t.Fatalf("validateResponse: %v", err)
	}
	calls, expiries := store.snapshot()
	if calls != 1 || !expiries[0].Equal(samlTestNow.Add(7*time.Minute)) {
		t.Fatalf("calls = %d, expiry = %v", calls, expiries)
	}
}
