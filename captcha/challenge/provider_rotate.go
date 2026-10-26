package challenge

import (
	"context"
	"image/color"
	"math"
)

// rotateState is the server-side rotate answer. | rotateState 是旋转挑战的服务端答案。
type rotateState struct {
	// Correction is the clockwise correction angle in degrees. | Correction 是顺时针校正角度（度）。
	Correction int `json:"correction"`
	// Tolerance is the accepted angular error in degrees. | Tolerance 是允许角度误差（度）。
	Tolerance int `json:"tolerance"`
}

// rotateProvider renders orientation challenges. | rotateProvider 渲染方向校正挑战。
type rotateProvider struct{}

// newRotateProvider builds a rotate provider. | newRotateProvider 构建旋转生成器。
func newRotateProvider() *rotateProvider { return &rotateProvider{} }

// Type implements Provider. | Type 实现 Provider。
func (p *rotateProvider) Type() Type { return TypeRotate }

// Generate implements Provider. | Generate 实现 Provider。
func (p *rotateProvider) Generate(ctx context.Context, req GenerateRequest) (*Generated, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r, err := newRNG()
	if err != nil {
		return nil, err
	}
	scene := newCanvas(req.Width, req.Height, r)
	scene.background()
	// A strong up-pointing landmark and an asymmetric skyline make the upright
	// orientation unambiguous. | 明确的向上地标与不对称天际线让正向清晰可辨。
	scene.polygon([]Point{
		{X: req.Width/2 - 34, Y: req.Height / 3},
		{X: req.Width / 2, Y: req.Height / 6},
		{X: req.Width/2 + 34, Y: req.Height / 3},
		{X: req.Width/2 + 12, Y: req.Height / 3},
		{X: req.Width/2 + 12, Y: req.Height / 2},
		{X: req.Width/2 - 12, Y: req.Height / 2},
		{X: req.Width/2 - 12, Y: req.Height / 3},
	}, color.RGBA{R: 218, G: 58, B: 54, A: 255})
	drawIcon(scene, "sun", req.Width-42, 40, 42)
	drawIcon(scene, "tree", 44, req.Height-42, 52)
	drawIcon(scene, "house", req.Width-62, req.Height-48, 60)
	scene.line(20, req.Height-20, req.Width-20, req.Height-20, 4, color.RGBA{R: 60, G: 90, B: 64, A: 255})
	initial := 30 + r.Intn(300)
	rotated := rotateImage(scene.img, float64(initial)*math.Pi/180, color.RGBA{R: 246, G: 246, B: 242, A: 255}, r)
	img, err := rotated.encodePNG("challenge")
	if err != nil {
		return nil, err
	}
	// rotateImage turns the scene counter-clockwise; the browser slider uses
	// positive CSS rotate, so the clockwise correction is the initial angle. |
	// rotateImage 将场景逆时针旋转；浏览器滑块使用正 CSS 旋转，因此顺时针校正角等于初始角。
	correction := initial
	answer, err := encodeAnswer(rotateState{Correction: correction, Tolerance: 10})
	if err != nil {
		return nil, err
	}
	prompt := localizedPrompt(req, "prompt.rotate", "hint.rotate", "Rotate the image upright", "Use the slider to correct the angle")
	return &Generated{Prompt: prompt, Images: []ImageData{img}, Answer: answer}, nil
}

// Verify implements Provider. | Verify 实现 Provider。
func (p *rotateProvider) Verify(ctx context.Context, rec *Record, ans Answer) (CheckResult, error) {
	if err := ctx.Err(); err != nil {
		return CheckResult{}, err
	}
	var state rotateState
	if err := decodeAnswer(rec.Answer, &state); err != nil {
		return CheckResult{}, err
	}
	behavior, reasons := scoreTrack(ans.Track, 8)
	if ans.Angle == nil {
		return CheckResult{Passed: false, BehaviorScore: behavior, Reasons: append(reasons, "rotate_angle_missing")}, nil
	}
	diff := (*ans.Angle - state.Correction) % 360
	if diff < 0 {
		diff = -diff
	}
	if diff > 180 {
		diff = 360 - diff
	}
	if diff > state.Tolerance {
		return CheckResult{Passed: false, BehaviorScore: behavior, Reasons: append(reasons, "rotate_miss")}, nil
	}
	return CheckResult{Passed: true, BehaviorScore: behavior, Reasons: reasons}, nil
}
