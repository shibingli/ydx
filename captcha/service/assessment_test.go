package service

import (
	"context"
	"errors"
	"testing"
)

func TestCaptureRejectPolicy(t *testing.T) {
	m := newTestManager(t, func(o *Options) { o.CaptureMode = CaptureReject })
	meta := testMeta()
	_, err := m.Create(context.Background(), CreateRequest{
		Type:    TypeText,
		Action:  "login",
		Meta:    meta,
		Signals: Signals{ScreenshotKey: true},
	})
	if !errors.Is(err, ErrCaptureDetected) {
		t.Fatalf("expected capture rejection, got %v", err)
	}
}

func TestCaptureRiskPolicyRejectsCorrectAnswer(t *testing.T) {
	m := newTestManager(t, func(o *Options) { o.CaptureMode = CaptureRisk })
	ch, record := createVisual(t, m, TypeText, testMeta())
	_, err := m.Verify(context.Background(), VerifyRequest{
		ID:      ch.ID,
		Answer:  answerFor(t, record),
		Meta:    testMeta(),
		Signals: Signals{ScreenCapture: true},
	})
	if !errors.Is(err, ErrRiskRejected) {
		t.Fatalf("expected risk rejection, got %v", err)
	}
}

func TestCaptureOffPolicyIgnoresSignals(t *testing.T) {
	m := newTestManager(t, func(o *Options) { o.CaptureMode = CaptureOff })
	ch, record := createVisual(t, m, TypeText, testMeta())
	if _, err := m.Verify(context.Background(), VerifyRequest{
		ID:      ch.ID,
		Answer:  answerFor(t, record),
		Meta:    testMeta(),
		Signals: Signals{ScreenCapture: true, ScreenshotKey: true, PrintAttempt: true},
	}); err != nil {
		t.Fatalf("capture off should ignore signals: %v", err)
	}
}
