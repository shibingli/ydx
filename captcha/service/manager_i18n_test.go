package service

import (
	"context"
	"testing"

	"github.com/shibingli/ydx/captcha/core"
)

func TestCreateLocalizesPromptAndError(t *testing.T) {
	m := newTestManager(t, nil)
	ch, err := m.Create(context.Background(), CreateRequest{
		Type:    TypeText,
		Action:  "login",
		Locale:  "ja-JP",
		Signals: goodSignals(testMeta().UserAgent),
		Meta:    testMeta(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if ch.Locale != "ja" {
		t.Fatalf("challenge locale = %q", ch.Locale)
	}
	localizer, err := core.NewLocalizer(testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	if ch.Prompt.Text != localizer.Message("ja", "prompt.text") || ch.Prompt.Hint != localizer.Message("ja", "hint.text") {
		t.Fatalf("Japanese prompt = %+v", ch.Prompt)
	}
	if got := m.ErrorMessage("ja", ErrInvalidAnswer); got != localizer.Message("ja", "error.invalid_answer") {
		t.Fatalf("Japanese error = %q", got)
	}
	if got := m.ErrorMessage("de", ErrRateLimited); got != localizer.Message("de", "error.rate_limited") {
		t.Fatalf("German error = %q", got)
	}
}
