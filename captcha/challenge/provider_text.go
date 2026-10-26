package challenge

import (
	"context"
	"image/color"
	"strings"
)

// textState is the server-side answer of a text challenge. | textState 是文本挑战的服务端答案。
type textState struct {
	// Text is the expected character sequence. | Text 是期望字符序列。
	Text string `json:"text"`
}

// textProvider renders distorted text challenges. | textProvider 渲染扭曲文本挑战。
type textProvider struct {
	length int
}

// newTextProvider builds a text provider. | newTextProvider 构建文本生成器。
func newTextProvider(length int) *textProvider { return &textProvider{length: length} }

// Type implements Provider. | Type 实现 Provider。
func (p *textProvider) Type() Type { return TypeText }

// Generate implements Provider. | Generate 实现 Provider。
func (p *textProvider) Generate(ctx context.Context, req GenerateRequest) (*Generated, error) {
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
	length := clampInt(p.length, 3, 8)
	runes := pickRunes(r, textPool(atlas, req.Locale), length)
	text := string(runes)
	c := newCanvas(req.Width, req.Height, r)
	c.background()
	size, spacing, start, _ := textLayout(req.Width, req.Height, length)
	for i, ch := range runes {
		mask, ok := atlas.glyphFor(ch)
		if !ok {
			continue
		}
		angle := (r.Float64() - 0.5) * 0.5
		col := color.RGBA{R: uint8(20 + r.Intn(80)), G: uint8(20 + r.Intn(80)), B: uint8(20 + r.Intn(80)), A: 255}
		cx := start + i*(size+spacing) + size/2
		cy := req.Height/2 + r.Intn(15) - 7
		c.glyph(mask, cx, cy, size, angle, col)
	}
	c.noise(5, 120)
	img, err := c.encodePNG("challenge")
	if err != nil {
		return nil, err
	}
	answer, err := encodeAnswer(textState{Text: text})
	if err != nil {
		return nil, err
	}
	prompt := localizedPrompt(req, "prompt.text", "hint.text", "Type the characters in the image", "Case-insensitive")
	return &Generated{Prompt: prompt, Images: []ImageData{img}, Answer: answer}, nil
}

// textPool selects characters that match the requested locale. | textPool 按请求语言选择字符集。
//
// Chinese prompts mix Han, Latin and digits; English prompts stay in Latin
// and digits so an English keyboard can enter the answer. | 中文提示混合汉字、
// 拉丁字母与数字；英文提示只使用拉丁字母与数字，便于英文键盘输入。
func textPool(atlas *glyphAtlas, locale string) []rune {
	if isHanLocale(locale) {
		return atlas.runes
	}
	pool := make([]rune, 0, len(atlas.latin)+len(atlas.digits))
	pool = append(pool, atlas.latin...)
	pool = append(pool, atlas.digits...)
	return pool
}

// textLayout fits the requested number of glyphs inside the canvas. | textLayout 让指定数量的字形适配画布。
func textLayout(width, height, length int) (size, spacing, start, total int) {
	length = clampInt(length, 3, 8)
	maxWidth := width - 16
	size = (width - 40) / maxInt(1, length)
	size = clampInt(size, 10, 76)
	if max := height - 24; size > max {
		size = max
	}
	if size < 10 {
		size = 10
	}
	for size > 10 {
		spacing = size / 7
		total = length*size + (length-1)*spacing
		if total <= maxWidth {
			break
		}
		size--
	}
	spacing = size / 7
	total = length*size + (length-1)*spacing
	if total > maxWidth {
		// width is validated at >=120, so the left edge can still be clamped. | width 已校验 >=120，左边缘仍可收敛。
		start = 0
		return
	}
	start = (width - total) / 2
	return
}

// Verify implements Provider. | Verify 实现 Provider。
func (p *textProvider) Verify(ctx context.Context, rec *Record, ans Answer) (CheckResult, error) {
	if err := ctx.Err(); err != nil {
		return CheckResult{}, err
	}
	var state textState
	if err := decodeAnswer(rec.Answer, &state); err != nil {
		return CheckResult{}, err
	}
	passed := strings.EqualFold(strings.TrimSpace(ans.Text), state.Text)
	behavior, reasons := scoreTrack(ans.Track, len(state.Text))
	if !passed {
		reasons = append(reasons, "text_mismatch")
	}
	return CheckResult{Passed: passed, BehaviorScore: behavior, Reasons: reasons}, nil
}
