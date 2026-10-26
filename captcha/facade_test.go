package captcha_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shibingli/ydx/captcha"
)

func TestFacadeKeepsRootAPI(t *testing.T) {
	manager, err := captcha.New(captcha.Options{
		Secret: []byte("0123456789abcdef0123456789abcdef"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	handler := manager.Handler(captcha.HandlerOptions{})
	if handler == nil {
		t.Fatal("nil handler")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/captcha/challenge", strings.NewReader(`{"type":"text","action":"login","locale":"en"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%s", rec.Code, rec.Body.String())
	}
	challenge, err := manager.Create(context.Background(), captcha.CreateRequest{
		Type:   captcha.TypeText,
		Action: "login",
		Locale: "en",
	})
	if err != nil {
		t.Fatal(err)
	}
	if challenge.Type != captcha.TypeText || challenge.ID == "" {
		t.Fatalf("challenge = %+v", challenge)
	}
	if got := captcha.MaskTarget(captcha.ChannelSMS, "+8613800138000"); got == "" {
		t.Fatal("empty mask")
	}
	if len(captcha.SDKScript()) == 0 || len(captcha.SDKStyle()) == 0 {
		t.Fatal("missing embedded assets")
	}
}
