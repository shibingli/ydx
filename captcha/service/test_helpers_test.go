package service

import (
	"context"
	"testing"
	"time"

	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/middleware/ratelimit"
)

const testSecret = "0123456789abcdef0123456789abcdef"

type testAPIError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	RetryAfter int64  `json:"retry_after,omitempty"`
}

type testAPIResponse struct {
	Challenge *Challenge    `json:"challenge,omitempty"`
	Result    *VerifyResult `json:"result,omitempty"`
	Claims    *TokenClaims  `json:"claims,omitempty"`
	Error     *testAPIError `json:"error,omitempty"`
	OK        bool          `json:"ok"`
}

func testOptions(t *testing.T) Options {
	t.Helper()
	return Options{
		Store:        NewMemoryStore(),
		ImageStore:   NewMemoryImageStore(),
		Secret:       []byte(testSecret),
		ChallengeTTL: time.Minute,
		TokenTTL:     time.Minute,
		MaxAttempts:  3,
		TextLength:   4,
		Width:        320,
		Height:       200,
		PoW:          PoWOptions{Mode: PoWOff, Difficulty: 8, MaxDifficulty: 8},
		Limits: Limits{
			Store:      ratelimit.NewMemoryStore(time.Minute),
			Create:     Rate{Rate: 1000, Burst: 1000},
			Verify:     Rate{Rate: 1000, Burst: 1000},
			Send:       Rate{Rate: 1000, Burst: 1000},
			SendTarget: Rate{Rate: 1000, Burst: 1000},
		},
	}
}

func newTestManager(t *testing.T, mutate func(*Options)) *Manager {
	t.Helper()
	o := testOptions(t)
	if mutate != nil {
		mutate(&o)
	}
	m, err := New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func goodSignals(ua string) Signals {
	return Signals{
		UserAgent:           ua,
		Platform:            "Win32",
		Language:            "zh-CN",
		Languages:           []string{"zh-CN", "en"},
		Timezone:            "Asia/Shanghai",
		ScreenWidth:         1920,
		ScreenHeight:        1080,
		ColorDepth:          24,
		DeviceMemory:        8,
		HardwareConcurrency: 8,
		Plugins:             3,
		CookieEnabled:       true,
		Visibility:          "visible",
	}
}

func testMeta() Meta {
	return Meta{IP: "203.0.113.8", UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"}
}

func goodTrack() Track {
	points := make([]TrackPoint, 0, 12)
	for i := 0; i < 12; i++ {
		points = append(points, TrackPoint{T: int64(i * 30), X: 40 + i*5, Y: 80 + i*2, Kind: "move"})
	}
	return Track{StartedAt: 0, EndedAt: 330, Points: points}
}

func createVisual(t *testing.T, m *Manager, typ Type, meta Meta) (*Challenge, *Record) {
	t.Helper()
	ch, err := m.Create(context.Background(), CreateRequest{
		Type:    typ,
		Action:  "login",
		Locale:  "zh-CN",
		Signals: goodSignals(meta.UserAgent),
		Meta:    meta,
	})
	if err != nil {
		t.Fatalf("Create(%s): %v", typ, err)
	}
	payload, ok, err := m.store.Get(context.Background(), m.recordKey(ch.ID))
	if err != nil || !ok {
		t.Fatalf("load record: ok=%v err=%v", ok, err)
	}
	record, err := decodeRecord(payload)
	if err != nil {
		t.Fatalf("decode record: %v", err)
	}
	return ch, record
}

func answerFor(t *testing.T, record *Record) Answer {
	t.Helper()
	switch record.Type {
	case TypeText, TypeScratch:
		var state struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(record.Answer, &state); err != nil {
			t.Fatal(err)
		}
		return Answer{Text: state.Text, Track: goodTrack()}
	case TypeClickText, TypeClickIcon, TypeSemantic:
		var state struct {
			Points []Point `json:"points"`
		}
		if err := json.Unmarshal(record.Answer, &state); err != nil {
			t.Fatal(err)
		}
		return Answer{Points: append([]Point(nil), state.Points...), Track: goodTrack()}
	case TypeSlide:
		var state struct {
			X int `json:"x"`
			Y int `json:"y"`
		}
		if err := json.Unmarshal(record.Answer, &state); err != nil {
			t.Fatal(err)
		}
		x, y := state.X, state.Y
		return Answer{Offset: &x, OffsetY: &y, Track: goodTrack()}
	case TypeRotate:
		var state struct {
			Correction int `json:"correction"`
		}
		if err := json.Unmarshal(record.Answer, &state); err != nil {
			t.Fatal(err)
		}
		angle := state.Correction
		return Answer{Angle: &angle, Track: goodTrack()}
	default:
		t.Fatalf("unsupported test type %q", record.Type)
		return Answer{}
	}
}
