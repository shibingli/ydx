package waf

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/log"
)

// alertTestWAF builds an alerting instance and returns the captured alert channel.
// | alertTestWAF 构建报警实例并返回捕获报警的通道。
func alertTestWAF(t *testing.T, rules []string, config AlertConfig) (*WAF, <-chan Alert) {
	t.Helper()
	alerts := make(chan Alert, 32)
	sink := SinkFunc{
		SinkName: "test",
		Fn: func(_ context.Context, alert Alert) error {
			select {
			case alerts <- alert:
			default:
			}
			return nil
		},
	}
	config.Enabled = true
	config.Sinks = []AlertSink{sink}
	instance, err := New(Options{
		Directives: rules,
		Logger:     log.New(log.Options{Writer: io.Discard, Level: log.ErrorLevel}),
		Alerting:   config,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	return instance, alerts
}

// awaitAlert waits for one alert. | awaitAlert 等待一条报警。
func awaitAlert(t *testing.T, alerts <-chan Alert) Alert {
	t.Helper()
	select {
	case alert := <-alerts:
		return alert
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for alert")
		return Alert{}
	}
}

func TestAlertThresholdAggregation(t *testing.T) {
	instance, alerts := alertTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains attack" "id:9300,phase:1,deny,status:403"`,
	}, AlertConfig{
		Threshold:   3,
		Window:      time.Second,
		Cooldown:    time.Minute,
		MinInterval: time.Millisecond,
		MaxPerHour:  100,
		MaxPerDay:   100,
	})
	for index := 0; index < 2; index++ {
		serveTest(t, instance, httptestNewRequest("/attack"))
	}
	select {
	case alert := <-alerts:
		t.Fatalf("alert emitted before threshold: %+v", alert)
	case <-time.After(50 * time.Millisecond):
	}
	serveTest(t, instance, httptestNewRequest("/attack"))
	alert := awaitAlert(t, alerts)
	if alert.Count != 3 || alert.RuleID != 9300 {
		t.Fatalf("alert = %+v", alert)
	}
	serveTest(t, instance, httptestNewRequest("/attack"))
	time.Sleep(20 * time.Millisecond)
	if stats := instance.Stats(); stats.AlertsSuppressed == 0 {
		t.Fatalf("cooldown did not suppress: %+v", stats)
	}
}

func TestAlertCriticalThreshold(t *testing.T) {
	instance, alerts := alertTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains critical" "id:9301,phase:1,deny,status:403,severity:'CRITICAL'"`,
	}, AlertConfig{
		Threshold:         5,
		CriticalThreshold: 1,
		Window:            time.Second,
		Cooldown:          time.Minute,
		MinInterval:       time.Millisecond,
		MaxPerHour:        100,
		MaxPerDay:         100,
	})
	serveTest(t, instance, httptestNewRequest("/critical"))
	alert := awaitAlert(t, alerts)
	if alert.Severity != "CRITICAL" || alert.Count != 1 {
		t.Fatalf("alert = %+v", alert)
	}
}

func TestAlertHourlyRateLimit(t *testing.T) {
	instance, alerts := alertTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains limit" "id:9302,phase:1,deny,status:403"`,
	}, AlertConfig{
		Threshold:   1,
		Window:      time.Second,
		Cooldown:    time.Millisecond,
		MinInterval: time.Millisecond,
		MaxPerHour:  1,
		MaxPerDay:   10,
	})
	serveTest(t, instance, httptestNewRequest("/limit"))
	_ = awaitAlert(t, alerts)
	time.Sleep(5 * time.Millisecond)
	serveTest(t, instance, httptestNewRequest("/limit"))
	time.Sleep(20 * time.Millisecond)
	if stats := instance.Stats(); stats.AlertsSuppressed == 0 {
		t.Fatalf("hourly limit did not suppress: %+v", stats)
	}
}

func TestAlertFilterPanicIsIsolated(t *testing.T) {
	alerter, err := newAlerter(AlertConfig{
		Enabled:     true,
		Filter:      func(Event) bool { panic("filter panic") },
		MinSeverity: "WARNING",
		Sinks:       []AlertSink{SinkFunc{SinkName: "test", Fn: func(context.Context, Alert) error { return nil }}},
	}, log.New(log.Options{Writer: io.Discard, Level: log.ErrorLevel}), &counters{})
	if err != nil {
		t.Fatalf("newAlerter: %v", err)
	}
	defer alerter.close()
	alerter.notify(Event{
		ID:           "tx",
		ClientIP:     "192.0.2.1",
		Interruption: &Interruption{RuleID: 1, Severity: "WARNING"},
	})
}

func TestEmailSinkRender(t *testing.T) {
	sink, err := NewEmailSink(EmailConfig{
		Host: "localhost",
		Port: 25,
		From: "waf@example.com",
		To:   []string{"ops@example.com"},
	})
	if err != nil {
		t.Fatalf("NewEmailSink: %v", err)
	}
	message := string(sink.render(Alert{
		ID:       "tx-1",
		Time:     time.Now(),
		RuleID:   942100,
		Severity: "CRITICAL",
		Action:   "deny",
		Status:   403,
		ClientIP: "192.0.2.1",
		Method:   "GET",
		Path:     "/login",
		Message:  "evil\r\nBcc: attacker@example.com",
		Count:    7,
		Tags:     []string{"attack-sqli"},
	}))
	for _, want := range []string{"Subject: [ydx-waf] [CRITICAL] rule 942100 deny x7", "Rule: 942100", "Count: 7"} {
		if !strings.Contains(message, want) {
			t.Fatalf("message missing %q:\n%s", want, message)
		}
	}
	if strings.Contains(message, "\r\nBcc:") {
		t.Fatalf("header injection not sanitized:\n%s", message)
	}
}

func TestEmailSinkValidation(t *testing.T) {
	if _, err := NewEmailSink(EmailConfig{Host: "localhost", From: "not-an-address", To: []string{"ops@example.com"}}); err == nil {
		t.Fatal("invalid sender accepted")
	}
	if _, err := NewEmailSink(EmailConfig{Host: "localhost", From: "waf@example.com"}); err == nil {
		t.Fatal("missing recipients accepted")
	}
	if _, err := NewEmailSink(EmailConfig{
		Host: "localhost", From: "waf@example.com", To: []string{"ops@example.com"},
		Username: "user", Password: "x", DisableStartTLS: true,
	}); err == nil {
		t.Fatal("plaintext authentication accepted")
	}
	sink, err := NewEmailSink(EmailConfig{
		Host: "localhost", From: "waf@example.com", To: []string{"ops@example.com"},
		Username: "user", Password: "x", Port: 587,
	})
	if err != nil {
		t.Fatalf("default STARTTLS sink: %v", err)
	}
	if !sink.config.StartTLS {
		t.Fatal("STARTTLS was not enabled by default")
	}
}

func TestFileSink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.jsonl")
	sink := NewFileSink(path)
	if err := sink.Send(context.Background(), Alert{ID: "one", RuleID: 1, Count: 2}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), `"id":"one"`) || !strings.HasSuffix(string(data), "\n") {
		t.Fatalf("file content = %q", data)
	}
}

func TestWebhookSinkSignature(t *testing.T) {
	key := []byte("webhook-key")
	var body []byte
	var signature string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signature = r.Header.Get("X-YDX-WAF-Signature")
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	sink, err := NewWebhookSink(WebhookConfig{URL: server.URL, SignatureKey: key})
	if err != nil {
		t.Fatalf("NewWebhookSink: %v", err)
	}
	if err := sink.Send(context.Background(), Alert{ID: "hook", RuleID: 7}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(body)
	if signature != hex.EncodeToString(mac.Sum(nil)) {
		t.Fatalf("signature = %q", signature)
	}
	if !strings.Contains(string(body), `"rule_id":7`) {
		t.Fatalf("body = %q", body)
	}
}
