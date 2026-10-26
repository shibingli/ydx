package service

import (
	"context"
	"errors"
	"testing"

	"github.com/shibingli/ydx/errs"
)

func TestInitialPolicyFailureIsFailClosed(t *testing.T) {
	o := testOptions(t)
	o.PolicyProvider = PolicyFunc(func(context.Context) (*Policy, error) {
		return nil, errs.New("policy store down | 策略存储故障")
	})
	if _, err := New(o); !errors.Is(err, ErrStore) {
		t.Fatalf("expected fail-closed startup, got %v", err)
	}
}

func TestAdaptiveTypeHonorsTypeDeny(t *testing.T) {
	m := newTestManager(t, func(o *Options) {
		o.Policy = &Policy{Deny: []Rule{{Type: TypeClickText}, {Type: TypeSlide}}}
	})
	signals := goodSignals(testMeta().UserAgent)
	signals.WebDriver = true
	signals.Headless = true
	ch, err := m.Create(context.Background(), CreateRequest{
		Action:  "login",
		Locale:  "en",
		Signals: signals,
		Meta:    testMeta(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if ch.Type != TypeText {
		t.Fatalf("adaptive type = %s, want text", ch.Type)
	}
}
