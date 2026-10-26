package service

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/png"
	"testing"

	"github.com/shibingli/ydx/json"
)

type customTestProvider struct{}

func (customTestProvider) Type() Type { return Type("custom_signal") }

func (customTestProvider) Generate(_ context.Context, _ GenerateRequest) (*Generated, error) {
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	img.SetRGBA(1, 1, color.RGBA{R: 255, A: 255})
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, img); err != nil {
		return nil, err
	}
	answer, err := json.Marshal(struct {
		Text string `json:"text"`
	}{Text: "custom"})
	if err != nil {
		return nil, err
	}
	return &Generated{
		Prompt: Prompt{Text: "custom challenge"},
		Images: []ImageData{{Name: "challenge", MIME: "image/png", Data: encoded.Bytes(), Width: 8, Height: 8}},
		Answer: answer,
	}, nil
}

func (customTestProvider) Verify(ctx context.Context, rec *Record, ans Answer) (CheckResult, error) {
	if err := ctx.Err(); err != nil {
		return CheckResult{}, err
	}
	var state struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(rec.Answer, &state); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Passed: ans.Text == state.Text}, nil
}

func TestCustomProviderType(t *testing.T) {
	custom := Type("custom_signal")
	m := newTestManager(t, func(o *Options) {
		o.Types = []Type{TypeText, custom}
		o.Providers = []Provider{customTestProvider{}}
		o.PoW = PoWOptions{Mode: PoWOff}
	})
	ch, _ := createVisual(t, m, custom, testMeta())
	if ch.Type != custom {
		t.Fatalf("type = %q", ch.Type)
	}
	res, err := m.Verify(context.Background(), VerifyRequest{ID: ch.ID, Answer: Answer{Text: "custom"}, Meta: testMeta()})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Token == "" {
		t.Fatal("missing token")
	}
	if _, err := m.Verify(context.Background(), VerifyRequest{ID: ch.ID, Answer: Answer{Text: "custom"}, Meta: testMeta()}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replay: %v", err)
	}
}
