package challenge

import (
	"context"
	"image/color"
	"time"

	"github.com/shibingli/ydx/errs"
)

// slideState is the server-side slide target. | slideState 是滑动拼图的服务端目标。
type slideState struct {
	// X is the target piece left edge. | X 是拼图块目标左边缘。
	X int `json:"x"`
	// Y is the target piece top edge. | Y 是拼图块目标上边缘。
	Y int `json:"y"`
	// Size is the piece side length. | Size 是拼图块边长。
	Size int `json:"size"`
	// Tolerance is the accepted per-axis error in pixels. | Tolerance 是每轴允许误差像素。
	Tolerance int `json:"tolerance"`
}

// slideProvider renders a two-axis puzzle drag challenge. | slideProvider 渲染双轴拼图拖动挑战。
type slideProvider struct{}

// newSlideProvider builds a slide provider. | newSlideProvider 构建滑动拼图生成器。
func newSlideProvider() *slideProvider { return &slideProvider{} }

// Type implements Provider. | Type 实现 Provider。
func (p *slideProvider) Type() Type { return TypeSlide }

// Generate implements Provider. | Generate 实现 Provider。
func (p *slideProvider) Generate(ctx context.Context, req GenerateRequest) (*Generated, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r, err := newRNG()
	if err != nil {
		return nil, err
	}
	size := minInt(56, minInt(req.Height/3, req.Width/5))
	if size < 32 {
		size = 32
	}
	if size > req.Width/3 || size > req.Height/2 {
		return nil, errs.Detail(ErrProvider, "slide dimensions are too small | 滑动图片尺寸过小")
	}
	c := newCanvas(req.Width, req.Height, r)
	c.background()
	drawSlideScene(c, r)
	gapX := size + 12 + r.Intn(maxInt(1, req.Width-2*size-24))
	gapY := 10 + r.Intn(maxInt(1, req.Height-size-20))
	piece := c.copyRect(gapX, gapY, size, size)
	// Randomize the gap fill and border so a fixed RGB signature cannot find
	// it; the gap stays visible enough for a person to aim at. | 随机化缺口填充与
	// 边框，避免固定 RGB 特征直接定位，同时保持人眼可辨。
	hole := randomColor(r, 14, 54)
	c.rect(gapX, gapY, size, size, hole)
	for i := 0; i < size/5; i++ {
		col := randomColor(r, 30, 90)
		x0 := gapX + r.Intn(size)
		y0 := gapY + r.Intn(size)
		c.line(x0, y0, gapX+r.Intn(size), gapY+r.Intn(size), 1, withAlpha(col, uint8(40+r.Intn(60))))
	}
	border := randomColor(r, 180, 255)
	c.line(gapX, gapY, gapX+size, gapY, 2, border)
	c.line(gapX, gapY+size, gapX+size, gapY+size, 2, border)
	c.line(gapX, gapY, gapX, gapY+size, 2, border)
	c.line(gapX+size, gapY, gapX+size, gapY+size, 2, border)
	main, err := c.encodePNG("challenge")
	if err != nil {
		return nil, err
	}
	pieceCanvas := newCanvas(size, size, r)
	pieceCanvas.drawImage(piece, 0, 0)
	pieceCanvas.line(0, 0, size, 0, 2, color.RGBA{R: 255, G: 255, B: 255, A: 255})
	pieceCanvas.line(0, size, size, size, 2, color.RGBA{R: 255, G: 255, B: 255, A: 255})
	pieceCanvas.line(0, 0, 0, size, 2, color.RGBA{R: 255, G: 255, B: 255, A: 255})
	pieceCanvas.line(size, 0, size, size, 2, color.RGBA{R: 255, G: 255, B: 255, A: 255})
	pieceImg, err := pieceCanvas.encodePNG("piece")
	if err != nil {
		return nil, err
	}
	answer, err := encodeAnswer(slideState{X: gapX, Y: gapY, Size: size, Tolerance: 8})
	if err != nil {
		return nil, err
	}
	prompt := localizedPrompt(req, "prompt.slide", "hint.slide", "Drag the puzzle piece into the gap", "Release to submit")
	return &Generated{Prompt: prompt, Images: []ImageData{main, pieceImg}, Answer: answer}, nil
}

// Verify implements Provider. | Verify 实现 Provider。
func (p *slideProvider) Verify(ctx context.Context, rec *Record, ans Answer) (CheckResult, error) {
	if err := ctx.Err(); err != nil {
		return CheckResult{}, err
	}
	var state slideState
	if err := decodeAnswer(rec.Answer, &state); err != nil {
		return CheckResult{}, err
	}
	behavior, reasons := scoreTrack(ans.Track, 16)
	if len(ans.Track.Points) < 8 || trackDuration(ans.Track) < 200*time.Millisecond {
		return CheckResult{Passed: false, BehaviorScore: behavior, Reasons: append(reasons, "slide_track_too_short")}, nil
	}
	if ans.Offset == nil || ans.OffsetY == nil {
		return CheckResult{Passed: false, BehaviorScore: behavior, Reasons: append(reasons, "slide_offset_missing")}, nil
	}
	if absInt(*ans.Offset-state.X) > state.Tolerance || absInt(*ans.OffsetY-state.Y) > state.Tolerance {
		return CheckResult{Passed: false, BehaviorScore: behavior, Reasons: append(reasons, "slide_miss")}, nil
	}
	return CheckResult{Passed: true, BehaviorScore: behavior, Reasons: reasons}, nil
}

// drawSlideScene paints non-repeating landmarks into the slide background. | drawSlideScene 向滑动背景绘制不重复地标。
func drawSlideScene(c *canvas, r *rng) {
	for i := 0; i < 4; i++ {
		spec := iconCatalog[r.Intn(len(iconCatalog))]
		size := 24 + r.Intn(24)
		drawIcon(c, spec.Name, 20+r.Intn(maxInt(1, c.width()-40)), 20+r.Intn(maxInt(1, c.height()-40)), size)
	}
	for i := 0; i < 8; i++ {
		col := randomColor(r, 30, 220)
		c.line(r.Intn(c.width()), r.Intn(c.height()), r.Intn(c.width()), r.Intn(c.height()), 1+r.Intn(2), withAlpha(col, 90))
	}
}

// absInt returns the absolute value. | absInt 返回绝对值。
func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
