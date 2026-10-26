package aliyun

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/captcha/core"
)

func TestSenderSignsRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		query := r.PostForm
		if query.Get("AccessKeyId") != "test-key" || query.Get("PhoneNumbers") != "13800138000" {
			t.Errorf("unexpected form: %v", query)
		}
		signature := query.Get("Signature")
		params := make(map[string]string, len(query))
		for key, values := range query {
			if key == "Signature" || len(values) == 0 {
				continue
			}
			params[key] = values[0]
		}
		stringToSign := "POST&%2F&" + percentEncode(canonicalQuery(params))
		mac := hmac.New(sha1.New, []byte("test-secret&"))
		_, _ = mac.Write([]byte(stringToSign))
		want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
		if signature != want {
			t.Errorf("signature mismatch")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Code":"OK","RequestId":"test"}`))
	}))
	defer server.Close()
	sender, err := New(Options{
		AccessKeyID:       "test-key",
		AccessKeySecret:   "test-secret",
		SignName:          "测试签名",
		TemplateCode:      "SMS_0001",
		Endpoint:          server.URL,
		AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sender.Channel() != core.ChannelSMS {
		t.Fatalf("channel = %q", sender.Channel())
	}
	if err := sender.Send(context.Background(), core.Message{To: "13800138000", Code: "123456", ExpiresIn: 5 * time.Minute}); err != nil {
		t.Fatal(err)
	}
}

func TestSenderRejectsProviderError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Code":"isv.BUSINESS_LIMIT_CONTROL","Message":"limited"}`))
	}))
	defer server.Close()
	sender, err := New(Options{
		AccessKeyID:       "test-key",
		AccessKeySecret:   "test-secret",
		SignName:          "测试签名",
		TemplateCode:      "SMS_0001",
		Endpoint:          server.URL,
		AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.Send(context.Background(), core.Message{To: "13800138000", Code: "123456"}); err == nil {
		t.Fatal("expected provider error")
	}
}

func TestNewRequiresHTTPSByDefault(t *testing.T) {
	if _, err := New(Options{
		AccessKeyID: "test-key", AccessKeySecret: "test-secret",
		SignName: "测试签名", TemplateCode: "SMS_0001",
		Endpoint: "http://example.com/",
	}); err == nil {
		t.Fatal("expected insecure HTTP rejection")
	}
}
