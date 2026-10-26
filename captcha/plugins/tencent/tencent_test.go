package tencent

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/shibingli/ydx/captcha/core"
)

func TestSenderSignsRequest(t *testing.T) {
	var sender *Sender
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		timestamp, _ := strconv.ParseInt(r.Header.Get("X-TC-Timestamp"), 10, 64)
		date := time.Unix(timestamp, 0).UTC().Format("2006-01-02")
		want := sender.authorization(body, timestamp, date)
		if r.Header.Get("Authorization") != want {
			t.Errorf("authorization mismatch")
		}
		if r.Header.Get("X-TC-Action") != apiAction || r.Header.Get("X-TC-Version") != apiVersion {
			t.Errorf("missing TC headers: %v", r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Response":{"RequestId":"test","SendStatusSet":[{"Code":"Ok","Message":"ok","PhoneNumber":"+8613800138000"}]}}`))
	}))
	defer server.Close()
	var err error
	sender, err = New(Options{
		SecretID:          "test-id",
		SecretKey:         "test-key",
		SdkAppID:          "1400000000",
		SignName:          "测试签名",
		TemplateID:        "100000",
		Endpoint:          server.URL,
		AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sender.Channel() != core.ChannelSMS {
		t.Fatalf("channel = %q", sender.Channel())
	}
	if err := sender.Send(context.Background(), core.Message{To: "+8613800138000", Code: "123456"}); err != nil {
		t.Fatal(err)
	}
}

func TestSenderRejectsProviderError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Response":{"Error":{"Code":"LimitExceeded","Message":"limited"},"RequestId":"test"}}`))
	}))
	defer server.Close()
	sender, err := New(Options{
		SecretID:          "test-id",
		SecretKey:         "test-key",
		SdkAppID:          "1400000000",
		SignName:          "测试签名",
		TemplateID:        "100000",
		Endpoint:          server.URL,
		AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.Send(context.Background(), core.Message{To: "+8613800138000", Code: "123456"}); err == nil {
		t.Fatal("expected provider error")
	}
}

func TestNewRequiresHTTPSByDefault(t *testing.T) {
	if _, err := New(Options{
		SecretID: "test-id", SecretKey: "test-key", SdkAppID: "1400000000",
		SignName: "测试签名", TemplateID: "100000",
		Endpoint: "http://example.com",
	}); err == nil {
		t.Fatal("expected insecure HTTP rejection")
	}
}

func TestSenderRejectsEmptyStatusSet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Response":{"RequestId":"test"}}`))
	}))
	defer server.Close()
	sender, err := New(Options{
		SecretID: "test-id", SecretKey: "test-key", SdkAppID: "1400000000",
		SignName: "测试签名", TemplateID: "100000",
		Endpoint: server.URL, AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.Send(context.Background(), core.Message{To: "+8613800138000", Code: "123456"}); err == nil {
		t.Fatal("expected empty status rejection")
	}
}
