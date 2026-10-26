package challenge

import (
	"context"
	"image/color"
	"strings"
	"time"
)

// scratchState is the server-side scratch-code answer. | scratchState 是刮刮卡的服务端答案。
type scratchState struct {
	// Text is the hidden character sequence. | Text 是隐藏字符序列。
	Text string `json:"text"`
}

// scratchProvider renders a coating-reveal challenge. | scratchProvider 渲染刮开涂层挑战。
type scratchProvider struct{}

// newScratchProvider builds a scratch provider. | newScratchProvider 构建刮刮卡生成器。
func newScratchProvider() *scratchProvider { return &scratchProvider{} }

// Type implements Provider. | Type 实现 Provider。
func (p *scratchProvider) Type() Type { return TypeScratch }

// Generate implements Provider. | Generate 实现 Provider。
func (p *scratchProvider) Generate(ctx context.Context, req GenerateRequest) (*Generated, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r, err := newRNG()
	if err != nil {
		return nil, err
	}
	atlas, err := loadGlyphs()
	if err != nil {
		return nil, err
	}
	pool := make([]rune, 0, len(atlas.latin)+len(atlas.digits))
	pool = append(pool, atlas.latin...)
	pool = append(pool, atlas.digits...)
	runes := pickRunes(r, pool, 4)
	text := string(runes)
	base := newCanvas(req.Width, req.Height, r)
	base.fill(color.RGBA{R: 248, G: 245, B: 236, A: 255}, color.RGBA{R: 227, G: 220, B: 204, A: 255})
	size, start := scratchLayout(req.Width, req.Height)
	for i, ch := range runes {
		mask, ok := atlas.glyphFor(ch)
		if !ok {
			continue
		}
		col := color.RGBA{R: uint8(24 + r.Intn(60)), G: uint8(24 + r.Intn(60)), B: uint8(24 + r.Intn(60)), A: 255}
		base.glyph(mask, start+i*(size+size/7)+size/2, req.Height/2, size, (r.Float64()-0.5)*0.18, col)
	}
	base.noise(2, 20)
	challenge, err := base.encodePNG("challenge")
	if err != nil {
		return nil, err
	}
	cover := newCanvas(req.Width, req.Height, r)
	cover.fill(color.RGBA{R: 158, G: 164, B: 172, A: 255}, color.RGBA{R: 92, G: 98, B: 108, A: 255})
	for i := 0; i < 90; i++ {
		col := randomColor(r, 110, 220)
		cover.line(r.Intn(cover.width()), r.Intn(cover.height()), r.Intn(cover.width()), r.Intn(cover.height()), 1+r.Intn(3), withAlpha(col, uint8(60+r.Intn(120))))
	}
	for i := 0; i < 45; i++ {
		cover.circle(r.Intn(cover.width()), r.Intn(cover.height()), 2+r.Intn(9), withAlpha(randomColor(r, 100, 230), uint8(40+r.Intn(80))))
	}
	cover.noise(20, 200)
	coverImg, err := cover.encodePNG("cover")
	if err != nil {
		return nil, err
	}
	answer, err := encodeAnswer(scratchState{Text: text})
	if err != nil {
		return nil, err
	}
	prompt := localizedPrompt(req, "prompt.scratch", "hint.scratch", "Scratch the coating and type the characters", "Type what you reveal")
	return &Generated{Prompt: prompt, Images: []ImageData{challenge, coverImg}, Answer: answer}, nil
}

// scratchLayout fits four reveal glyphs inside the canvas. | scratchLayout 让四个显露字形适配画布。
func scratchLayout(width, height int) (size, start int) {
	size = (width - 40) / 4
	size = clampInt(size, 16, 72)
	if max := height - 16; size > max {
		size = max
	}
	if size < 10 {
		size = 10
	}
	maxWidth := width - 16
	for size > 10 {
		total := 4*size + 3*(size/7)
		if total <= maxWidth {
			break
		}
		size--
	}
	total := 4*size + 3*(size/7)
	start = (width - total) / 2
	if start < 0 {
		start = 0
	}
	return size, start
}

// Verify implements Provider. | Verify 实现 Provider。
func (p *scratchProvider) Verify(ctx context.Context, rec *Record, ans Answer) (CheckResult, error) {
	if err := ctx.Err(); err != nil {
		return CheckResult{}, err
	}
	var state scratchState
	if err := decodeAnswer(rec.Answer, &state); err != nil {
		return CheckResult{}, err
	}
	behavior, reasons := scoreTrack(ans.Track, 12)
	if len(ans.Track.Points) < 8 || trackDuration(ans.Track) < 250*time.Millisecond {
		reasons = append(reasons, "scratch_too_short")
		return CheckResult{Passed: false, BehaviorScore: behavior, Reasons: reasons}, nil
	}
	passed := strings.EqualFold(strings.TrimSpace(ans.Text), state.Text)
	if !passed {
		reasons = append(reasons, "scratch_text_mismatch")
	}
	return CheckResult{Passed: passed, BehaviorScore: behavior, Reasons: reasons}, nil
}
