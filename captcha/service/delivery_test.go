package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shibingli/ydx/errs"
)

func TestSendCodeLifecycle(t *testing.T) {
	var mu sync.Mutex
	var sent Message
	sender := SenderFunc{Ch: ChannelSMS, Fn: func(_ context.Context, msg Message) error {
		mu.Lock()
		sent = msg
		mu.Unlock()
		return nil
	}}
	m := newTestManager(t, func(o *Options) {
		o.Senders = map[Channel]Sender{ChannelSMS: sender}
	})
	ch, err := m.SendCode(context.Background(), SendRequest{Channel: ChannelSMS, Target: "+86 138-0013-8000", Action: "login", Locale: "zh-CN", Meta: testMeta()})
	if err != nil {
		t.Fatalf("SendCode: %v", err)
	}
	if ch.Type != TypeSMS || ch.Channel != ChannelSMS || ch.Target == "" || strings.Contains(ch.Target, "0013") {
		t.Fatalf("unexpected challenge: %+v", ch)
	}
	if ch.Notice != "" {
		t.Fatalf("non-fallback challenge has notice %q", ch.Notice)
	}
	mu.Lock()
	msg := sent
	mu.Unlock()
	if msg.To != "+8613800138000" || len(msg.Code) != 6 {
		t.Fatalf("unexpected message: %+v", msg)
	}
	payload, ok, err := m.store.Get(context.Background(), m.recordKey(ch.ID))
	if err != nil || !ok {
		t.Fatalf("record: ok=%v err=%v", ok, err)
	}
	record, err := decodeRecord(payload)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(record.CodeHash), msg.Code) || len(record.CodeHash) == 0 {
		t.Fatal("code hash is not hashed")
	}
	if _, err := m.Verify(context.Background(), VerifyRequest{ID: ch.ID, Answer: Answer{Code: "000000"}, Meta: testMeta()}); !errors.Is(err, ErrInvalidAnswer) {
		t.Fatalf("wrong code: %v", err)
	}
	res, err := m.Verify(context.Background(), VerifyRequest{ID: ch.ID, Answer: Answer{Code: msg.Code}, Meta: testMeta()})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	claims, err := m.VerifyToken(context.Background(), res.Token, "login")
	if err != nil || claims.Subject == "" {
		t.Fatalf("claims: %+v err=%v", claims, err)
	}
}

func TestSendCodeCooldownAndFailure(t *testing.T) {
	var fail bool
	sender := SenderFunc{Ch: ChannelEmail, Fn: func(_ context.Context, _ Message) error {
		if fail {
			return errs.New("sender down | 发送器故障")
		}
		return nil
	}}
	var auditMu sync.Mutex
	var events []AuditEvent
	m := newTestManager(t, func(o *Options) {
		o.Senders = map[Channel]Sender{ChannelEmail: sender}
		o.Audit = AuditFunc(func(_ context.Context, event AuditEvent) error {
			auditMu.Lock()
			events = append(events, event)
			auditMu.Unlock()
			return nil
		})
	})
	if _, err := m.SendCode(context.Background(), SendRequest{Channel: ChannelEmail, Target: "User@Example.COM", Action: "login", Meta: testMeta()}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SendCode(context.Background(), SendRequest{Channel: ChannelEmail, Target: "user@example.com", Action: "login", Meta: testMeta()}); !errors.Is(err, ErrCooldown) {
		t.Fatalf("expected cooldown, got %v", err)
	}
	fail = true
	// A different target avoids the first cooldown and exercises send rollback. | 换一个目标避开冷却并验证发送回滚。
	_, err := m.SendCode(context.Background(), SendRequest{Channel: ChannelEmail, Target: "other@example.com", Action: "login", Meta: testMeta()})
	if !errors.Is(err, ErrSendFailed) {
		t.Fatalf("expected send failure, got %v", err)
	}
	// A failed delivery must release its reservation so the user can retry. | 投递失败必须释放预占，允许用户重试。
	fail = false
	if _, err := m.SendCode(context.Background(), SendRequest{Channel: ChannelEmail, Target: "other@example.com", Action: "login", Meta: testMeta()}); err != nil {
		t.Fatalf("retry after failed send: %v", err)
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	found := false
	for _, event := range events {
		if event.Outcome == AuditError && event.ChallengeID != "" && event.Target == "ot***@example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing rollback audit: %+v", events)
	}
}

func TestSendCodeValidation(t *testing.T) {
	m := newTestManager(t, nil)
	if _, err := m.SendCode(context.Background(), SendRequest{Channel: ChannelSMS, Target: "123", Action: "login"}); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("short phone: %v", err)
	}
	if _, err := m.SendCode(context.Background(), SendRequest{Channel: ChannelEmail, Target: "not-an-email", Action: "login"}); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("bad email: %v", err)
	}
	if _, err := m.SendCode(context.Background(), SendRequest{Channel: ChannelSMS, Target: "13800138000", Action: "login"}); !errors.Is(err, ErrNoSender) {
		t.Fatalf("missing sender: %v", err)
	}
	if _, err := m.SendCode(context.Background(), SendRequest{Channel: "pigeon", Target: "13800138000", Action: "login"}); !errors.Is(err, ErrUnsupportedChannel) {
		t.Fatalf("bad channel: %v", err)
	}
}

func TestMaskTarget(t *testing.T) {
	if got := MaskTarget(ChannelSMS, "+8613800138000"); got != "+86*******8000" {
		t.Fatalf("phone mask = %q", got)
	}
	if got := MaskTarget(ChannelEmail, "user@example.com"); got != "us***@example.com" {
		t.Fatalf("email mask = %q", got)
	}
}

func TestSendCodeTTL(t *testing.T) {
	now := time.Unix(1700000000, 0)
	sender := SenderFunc{Ch: ChannelSMS, Fn: func(context.Context, Message) error { return nil }}
	m := newTestManager(t, func(o *Options) {
		o.Now = func() time.Time { return now }
		o.Senders = map[Channel]Sender{ChannelSMS: sender}
		o.ChallengeTTL = time.Minute
	})
	ch, err := m.SendCode(context.Background(), SendRequest{Channel: ChannelSMS, Target: "13800138000", Action: "login", Meta: testMeta()})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := m.Verify(context.Background(), VerifyRequest{ID: ch.ID, Answer: Answer{Code: "123456"}, Meta: testMeta()}); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected expired, got %v", err)
	}
}

func TestNormalizePhoneToE164(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"13800138000", "+8613800138000", true},
		{"0138 0013 8000", "+8613800138000", true},
		{"+86 138-0013-8000", "+8613800138000", true},
		{"0086 (138) 0013-8000", "+8613800138000", true},
		{"+1 (415) 555-2671", "+14155552671", true},
		{"123", "", false},
		{"+012345678", "", false},
		{"+86 138-0013-8000 ext 9", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, err := normalizePhone(tc.in, "86")
		if tc.ok && (err != nil || got != tc.want) {
			t.Fatalf("normalizePhone(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
		if !tc.ok && !errors.Is(err, ErrInvalidTarget) {
			t.Fatalf("normalizePhone(%q) error = %v; want ErrInvalidTarget", tc.in, err)
		}
	}
}

func TestSendCodeCanonicalizesPhoneVariants(t *testing.T) {
	var sent atomic.Int32
	sender := SenderFunc{Ch: ChannelSMS, Fn: func(context.Context, Message) error {
		sent.Add(1)
		return nil
	}}
	m := newTestManager(t, func(o *Options) {
		o.Senders = map[Channel]Sender{ChannelSMS: sender}
	})
	if _, err := m.SendCode(context.Background(), SendRequest{Channel: ChannelSMS, Target: "13800138000", Action: "login", Meta: testMeta()}); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"+86 138-0013-8000", "008613800138000", "013800138000"} {
		if _, err := m.SendCode(context.Background(), SendRequest{Channel: ChannelSMS, Target: target, Action: "login", Meta: testMeta()}); !errors.Is(err, ErrCooldown) {
			t.Fatalf("variant %q bypassed cooldown: %v", target, err)
		}
	}
	if sent.Load() != 1 {
		t.Fatalf("sends = %d, want 1", sent.Load())
	}
}

func TestSendCodeCooldownIsAtomic(t *testing.T) {
	var sends atomic.Int32
	sender := SenderFunc{Ch: ChannelSMS, Fn: func(context.Context, Message) error {
		sends.Add(1)
		time.Sleep(5 * time.Millisecond)
		return nil
	}}
	m := newTestManager(t, func(o *Options) {
		o.Senders = map[Channel]Sender{ChannelSMS: sender}
	})
	const workers = 16
	var wg sync.WaitGroup
	var success atomic.Int32
	var cooldown atomic.Int32
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := m.SendCode(context.Background(), SendRequest{Channel: ChannelSMS, Target: "13800138000", Action: "login", Meta: testMeta()})
			switch {
			case err == nil:
				success.Add(1)
			case errors.Is(err, ErrCooldown):
				cooldown.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 1 || cooldown.Load() != workers-1 {
		t.Fatalf("success=%d cooldown=%d, want 1/%d", success.Load(), cooldown.Load(), workers-1)
	}
	if sends.Load() != 1 {
		t.Fatalf("sends = %d, want 1", sends.Load())
	}
}

func TestFallbackRequiresHostEnablement(t *testing.T) {
	m := newTestManager(t, nil)
	_, err := m.SendCode(context.Background(), SendRequest{
		Channel:  ChannelSMS,
		Target:   "13800138000",
		Action:   "login",
		Fallback: true,
		Meta:     testMeta(),
	})
	if !errors.Is(err, ErrFallbackDisabled) {
		t.Fatalf("expected fallback disabled, got %v", err)
	}
}

func TestFallbackSendBypassesCaptureReject(t *testing.T) {
	var mu sync.Mutex
	var sent Message
	sender := SenderFunc{Ch: ChannelSMS, Fn: func(_ context.Context, msg Message) error {
		mu.Lock()
		sent = msg
		mu.Unlock()
		return nil
	}}
	var auditMu sync.Mutex
	var events []AuditEvent
	m := newTestManager(t, func(o *Options) {
		o.CaptureMode = CaptureReject
		o.Senders = map[Channel]Sender{ChannelSMS: sender}
		o.Fallback = FallbackOptions{Enabled: true, Channel: ChannelSMS}
		o.Audit = AuditFunc(func(_ context.Context, event AuditEvent) error {
			auditMu.Lock()
			events = append(events, event)
			auditMu.Unlock()
			return nil
		})
	})
	ch, err := m.SendCode(context.Background(), SendRequest{
		Channel:     ChannelSMS,
		Target:      "13800138000",
		Action:      "login",
		Fallback:    true,
		CaptureKind: "screen_capture",
		Signals:     Signals{ScreenCapture: true, ScreenshotKey: true},
		Meta:        testMeta(),
	})
	if err != nil {
		t.Fatalf("fallback send: %v", err)
	}
	if ch.Type != TypeSMS || ch.Channel != ChannelSMS {
		t.Fatalf("unexpected challenge: %+v", ch)
	}
	if ch.Notice == "" {
		t.Fatal("fallback challenge is missing its localized notice")
	}
	mu.Lock()
	code := sent.Code
	mu.Unlock()
	if code == "" {
		t.Fatal("sender did not receive a code")
	}
	if _, err := m.Verify(context.Background(), VerifyRequest{
		ID:      ch.ID,
		Answer:  Answer{Code: code},
		Signals: Signals{ScreenCapture: true, ScreenshotKey: true},
		Meta:    testMeta(),
	}); err != nil {
		t.Fatalf("verify fallback code: %v", err)
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	found := false
	for _, event := range events {
		if event.Outcome == AuditSent {
			for _, reason := range event.Reasons {
				if reason == "capture_fallback" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatalf("fallback audit reason missing: %+v", events)
	}
}

func TestFallbackChannelMustMatch(t *testing.T) {
	sms := SenderFunc{Ch: ChannelSMS, Fn: func(context.Context, Message) error { return nil }}
	email := SenderFunc{Ch: ChannelEmail, Fn: func(context.Context, Message) error { return nil }}
	m := newTestManager(t, func(o *Options) {
		o.Senders = map[Channel]Sender{ChannelSMS: sms, ChannelEmail: email}
		o.Fallback = FallbackOptions{Enabled: true, Channel: ChannelSMS}
	})
	_, err := m.SendCode(context.Background(), SendRequest{
		Channel:  ChannelEmail,
		Target:   "user@example.com",
		Action:   "login",
		Fallback: true,
		Meta:     testMeta(),
	})
	if !errors.Is(err, ErrFallbackDisabled) {
		t.Fatalf("expected channel mismatch rejection, got %v", err)
	}
}

func TestFallbackRequiresConfiguredSender(t *testing.T) {
	o := testOptions(t)
	o.Fallback = FallbackOptions{Enabled: true, Channel: ChannelSMS}
	if _, err := New(o); !errors.Is(err, ErrNoSender) {
		t.Fatalf("expected missing sender, got %v", err)
	}
}

func TestDigestKeySurvivesTokenKeyRotation(t *testing.T) {
	keyA := []byte("0123456789abcdef0123456789abcdef")
	keyB := []byte("abcdef0123456789abcdef0123456789")
	m1 := newTestManager(t, func(o *Options) {
		o.Secret = nil
		o.Keys = map[string][]byte{"ka": keyA, "kb": keyB}
		o.KeyID = "ka"
	})
	m2 := newTestManager(t, func(o *Options) {
		o.Secret = nil
		o.Keys = map[string][]byte{"ka": keyA, "kb": keyB}
		o.KeyID = "kb"
	})
	if m1.keyedDigest("target:+8613800138000") != m2.keyedDigest("target:+8613800138000") {
		t.Fatal("target digest changed after token key rotation")
	}
	if string(m1.codeDigest("challenge", "123456")) != string(m2.codeDigest("challenge", "123456")) {
		t.Fatal("code digest changed after token key rotation")
	}
}
