package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/json"
)

func TestCreateVerifyAllVisualTypes(t *testing.T) {
	types := []Type{TypeText, TypeClickText, TypeClickIcon, TypeSlide, TypeScratch, TypeSemantic, TypeRotate}
	for _, typ := range types {
		t.Run(string(typ), func(t *testing.T) {
			m := newTestManager(t, nil)
			ch, record := createVisual(t, m, typ, testMeta())
			if ch.ID == "" || ch.Action != "login" || ch.ExpiresIn <= 0 {
				t.Fatalf("unexpected challenge: %+v", ch)
			}
			if len(ch.Images) == 0 {
				t.Fatal("expected images")
			}
			for _, img := range ch.Images {
				key := strings.TrimPrefix(img.URL, "image/")
				data, mime, ok, err := m.Image(context.Background(), key)
				if err != nil || !ok {
					t.Fatalf("image %q: ok=%v err=%v", img.Name, ok, err)
				}
				if mime != "image/png" || len(data) < 8 || string(data[1:4]) != "PNG" {
					t.Fatalf("image %q is not PNG: mime=%q len=%d", img.Name, mime, len(data))
				}
			}
			public, err := json.Marshal(ch)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(public), string(record.Answer)) {
				t.Fatal("public challenge leaks answer state")
			}
			res, err := m.Verify(context.Background(), VerifyRequest{ID: ch.ID, Answer: answerFor(t, record), Signals: goodSignals(testMeta().UserAgent), Meta: testMeta()})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if res.Token == "" || res.Action != "login" {
				t.Fatalf("unexpected result: %+v", res)
			}
			claims, err := m.VerifyToken(context.Background(), res.Token, "login")
			if err != nil {
				t.Fatalf("VerifyToken: %v", err)
			}
			if claims.ChallengeID != ch.ID || claims.Action != "login" {
				t.Fatalf("unexpected claims: %+v", claims)
			}
			_, err = m.ConsumeToken(context.Background(), res.Token, "login")
			if err != nil {
				t.Fatalf("ConsumeToken: %v", err)
			}
			if _, err := m.ConsumeToken(context.Background(), res.Token, "login"); !errors.Is(err, ErrTokenUsed) {
				t.Fatalf("second consume: %v", err)
			}
			if _, err := m.Verify(context.Background(), VerifyRequest{ID: ch.ID, Answer: answerFor(t, record), Meta: testMeta()}); !errors.Is(err, ErrNotFound) {
				t.Fatalf("replay: %v", err)
			}
		})
	}
}

func TestInvalidAnswerAttemptBudget(t *testing.T) {
	m := newTestManager(t, func(o *Options) { o.MaxAttempts = 3 })
	ch, _ := createVisual(t, m, TypeText, testMeta())
	for i := 0; i < 2; i++ {
		_, err := m.Verify(context.Background(), VerifyRequest{ID: ch.ID, Answer: Answer{Text: "zzzz", Track: goodTrack()}, Meta: testMeta()})
		if !errors.Is(err, ErrInvalidAnswer) {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
	if _, err := m.Verify(context.Background(), VerifyRequest{ID: ch.ID, Answer: Answer{Text: "zzzz", Track: goodTrack()}, Meta: testMeta()}); !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("third attempt: %v", err)
	}
	if _, err := m.Verify(context.Background(), VerifyRequest{ID: ch.ID, Answer: Answer{Text: "zzzz"}, Meta: testMeta()}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after budget: %v", err)
	}
}

func TestExpiredChallenge(t *testing.T) {
	now := time.Unix(1700000000, 0)
	m := newTestManager(t, func(o *Options) {
		o.Now = func() time.Time { return now }
		o.ChallengeTTL = time.Minute
	})
	ch, _ := createVisual(t, m, TypeText, testMeta())
	now = now.Add(2 * time.Minute)
	if _, err := m.Verify(context.Background(), VerifyRequest{ID: ch.ID, Answer: Answer{Text: "x"}, Meta: testMeta()}); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected expired, got %v", err)
	}
}

func TestDynamicPolicyDeniesCreate(t *testing.T) {
	m := newTestManager(t, nil)
	if err := m.SetPolicy(&Policy{Deny: []Rule{{IP: "203.0.113.0/24"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(context.Background(), CreateRequest{Action: "login", Meta: testMeta(), Signals: goodSignals(testMeta().UserAgent)}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected forbidden, got %v", err)
	}
}

func TestCreateRateLimit(t *testing.T) {
	m := newTestManager(t, func(o *Options) {
		o.Limits.Create = Rate{Rate: 0.0001, Burst: 1}
	})
	if _, err := m.Create(context.Background(), CreateRequest{Action: "login", Meta: testMeta(), Signals: goodSignals(testMeta().UserAgent)}); err != nil {
		t.Fatal(err)
	}
	_, err := m.Create(context.Background(), CreateRequest{Action: "login", Meta: testMeta(), Signals: goodSignals(testMeta().UserAgent)})
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected rate limit, got %v", err)
	}
	var limit *LimitError
	if !errors.As(err, &limit) || limit.RetryAfter <= 0 {
		t.Fatalf("expected retry hint, got %#v", err)
	}
}

func TestGeoBindingRejectsShortTermMove(t *testing.T) {
	geo := GeoResolverFunc(func(_ context.Context, ip string) (Geo, error) {
		switch ip {
		case "1.1.1.1":
			return Geo{Country: "US", Latitude: 37.77, Longitude: -122.41, HasCoordinates: true}, nil
		default:
			return Geo{Country: "CN", Latitude: 31.23, Longitude: 121.47, HasCoordinates: true}, nil
		}
	})
	m := newTestManager(t, func(o *Options) {
		o.GeoResolver = geo
		o.GeoBind = true
	})
	meta := testMeta()
	meta.IP = "1.1.1.1"
	ch, record := createVisual(t, m, TypeText, meta)
	meta.IP = "2.2.2.2"
	if _, err := m.Verify(context.Background(), VerifyRequest{ID: ch.ID, Answer: answerFor(t, record), Meta: meta}); !errors.Is(err, ErrGeoMismatch) {
		t.Fatalf("expected geo mismatch, got %v", err)
	}
}

func TestPoWAlways(t *testing.T) {
	m := newTestManager(t, func(o *Options) {
		o.PoW = PoWOptions{Mode: PoWAlways, Difficulty: 8, MaxDifficulty: 8, Threshold: 50}
	})
	ch, record := createVisual(t, m, TypeText, testMeta())
	if ch.PoW == nil {
		t.Fatal("expected proof of work")
	}
	proof := solveTestPoW(t, ch.PoW)
	if _, err := m.Verify(context.Background(), VerifyRequest{ID: ch.ID, Answer: answerFor(t, record), Meta: testMeta(), PoW: proof}); err != nil {
		t.Fatalf("Verify with PoW: %v", err)
	}
}

func TestCloseRejectsCalls(t *testing.T) {
	m := newTestManager(t, nil)
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(context.Background(), CreateRequest{Action: "login", Meta: testMeta()}); !errors.Is(err, ErrClosed) {
		t.Fatalf("expected closed, got %v", err)
	}
}

func solveTestPoW(t *testing.T, challenge *PoWChallenge) *PoWProof {
	t.Helper()
	for nonce := uint64(0); nonce < 1<<24; nonce++ {
		proof := &PoWProof{Nonce: nonce}
		if verifyPoW(challenge, proof) == nil {
			return proof
		}
	}
	t.Fatal("could not solve test proof of work")
	return nil
}
