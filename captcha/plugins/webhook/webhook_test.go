package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/captcha/core"
)

func TestSenderSignsAndDelivers(t *testing.T) {
	secret := []byte("0123456789abcdef")
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody = body
		timestamp := r.Header.Get("X-Captcha-Timestamp")
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write([]byte(timestamp))
		_, _ = mac.Write([]byte("."))
		_, _ = mac.Write(body)
		want := hex.EncodeToString(mac.Sum(nil))
		if r.Header.Get("X-Captcha-Signature") != want {
			t.Errorf("signature mismatch")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	sender, err := New(Options{URL: server.URL, Secret: secret, AllowInsecureHTTP: true, Headers: map[string]string{
		"X-Api-Key":           "test",
		"X-Captcha-Signature": "attacker",
		"X-Captcha-Timestamp": "0",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if sender.Channel() != core.ChannelSMS {
		t.Fatalf("channel = %q", sender.Channel())
	}
	err = sender.Send(context.Background(), core.Message{
		Channel:   core.ChannelSMS,
		To:        "+8613800138000",
		Code:      "123456",
		Action:    "login",
		Locale:    "zh-CN",
		Template:  "captcha_code",
		ExpiresIn: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(gotBody) == 0 || !strings.Contains(string(gotBody), "123456") {
		t.Fatalf("body = %s", gotBody)
	}
}

func TestSenderRejectsGatewayFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	sender, err := New(Options{URL: server.URL, Secret: []byte("0123456789abcdef"), AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.Send(context.Background(), core.Message{To: "+8613800138000", Code: "123456"}); err == nil {
		t.Fatal("expected delivery error")
	}
}

func TestNewRejectsInvalidOptions(t *testing.T) {
	if _, err := New(Options{URL: "relative", Secret: []byte("0123456789abcdef")}); err == nil {
		t.Fatal("expected invalid URL")
	}
	if _, err := New(Options{URL: "https://example.com", Secret: []byte("short")}); err == nil {
		t.Fatal("expected short secret")
	}
}

func TestNewRequiresHTTPSByDefault(t *testing.T) {
	if _, err := New(Options{URL: "http://example.com/hook", Secret: []byte("0123456789abcdef")}); err == nil {
		t.Fatal("expected insecure HTTP rejection")
	}
}
