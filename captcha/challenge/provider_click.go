package challenge

import (
	"context"
	"image/color"
	"math"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// clickState is the server-side state of click and semantic challenges. | clickState 是点选与语义挑战的服务端状态。
type clickState struct {
	// Points are the target centers in image coordinates. | Points 是图片坐标系中的目标中心。
	Points []Point `json:"points"`
	// Labels are optional human labels used for prompts. | Labels 是提示中用到的可选文字标签。
	Labels []string `json:"labels,omitempty"`
	// Icons are optional icon identifiers. | Icons 是可选图标标识。
	Icons []string `json:"icons,omitempty"`
	// Tolerance is the hit radius in pixels. | Tolerance 是命中半径（像素）。
	Tolerance int `json:"tolerance"`
	// Ordered requires clicks in the listed order. | Ordered 要求按列出顺序点击。
	Ordered bool `json:"ordered"`
}

// clickTextProvider renders ordered character-click challenges. | clickTextProvider 渲染有序文字点选挑战。
type clickTextProvider struct{}

// newClickTextProvider builds a text-click provider. | newClickTextProvider 构建文字点选生成器。
func newClickTextProvider() *clickTextProvider { return &clickTextProvider{} }

// Type implements Provider. | Type 实现 Provider。
func (p *clickTextProvider) Type() Type { return TypeClickText }

// Generate implements Provider. | Generate 实现 Provider。
func (p *clickTextProvider) Generate(ctx context.Context, req GenerateRequest) (*Generated, error) {
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
	pool := atlas.han
	if !isHanLocale(req.Locale) {
		pool = atlas.latin
	}
	targetCount := 3
	all := pickRunes(r, pool, targetCount+3)
	targets := all[:targetCount]
	distractors := all[targetCount:]
	chars := append(append([]rune(nil), targets...), distractors...)
	r.src.Shuffle(len(chars), func(i, j int) { chars[i], chars[j] = chars[j], chars[i] })
	c := newCanvas(req.Width, req.Height, r)
	c.background()
	cols, rows := 3, 2
	if len(chars) > 6 {
		rows = 3
	}
	centers := cellCenters(r, cols, rows, req.Width, req.Height, 12)
	positions := make(map[rune]Point, len(chars))
	for i, ch := range chars {
		center := centers[i%len(centers)]
		positions[ch] = center
		mask, ok := atlas.glyphFor(ch)
		if !ok {
			continue
		}
		size := minInt(58, minInt(req.Width/cols-12, req.Height/rows-12))
		if size < 30 {
			size = 30
		}
		col := color.RGBA{R: uint8(20 + r.Intn(90)), G: uint8(20 + r.Intn(90)), B: uint8(20 + r.Intn(90)), A: 255}
		c.glyph(mask, center.X, center.Y, size, (r.Float64()-0.5)*0.2, col)
	}
	targetPoints := make([]Point, 0, targetCount)
	labels := make([]string, 0, targetCount)
	for _, target := range targets {
		targetPoints = append(targetPoints, positions[target])
		labels = append(labels, string(target))
	}
	c.noise(3, 60)
	img, err := c.encodePNG("challenge")
	if err != nil {
		return nil, err
	}
	tolerance, err := clickTargetTolerance(targetPoints, 24)
	if err != nil {
		return nil, err
	}
	answer, err := encodeAnswer(clickState{Points: targetPoints, Labels: labels, Tolerance: tolerance, Ordered: true})
	if err != nil {
		return nil, err
	}
	separator := ", "
	if isHanLocale(req.Locale) {
		separator = " "
	}
	labelText := strings.Join(labels, separator)
	prompt := localizedPrompt(req, "prompt.click_text", "hint.click_text", "Click in order: "+labelText, "Follow the order", labelText)
	prompt.Count = targetCount
	return &Generated{Prompt: prompt, Images: []ImageData{img}, Answer: answer}, nil
}

// Verify implements Provider. | Verify 实现 Provider。
func (p *clickTextProvider) Verify(ctx context.Context, rec *Record, ans Answer) (CheckResult, error) {
	if err := ctx.Err(); err != nil {
		return CheckResult{}, err
	}
	var state clickState
	if err := decodeAnswer(rec.Answer, &state); err != nil {
		return CheckResult{}, err
	}
	return verifyClickState(state, ans, "click_text_mismatch"), nil
}

// clickIconProvider renders ordered icon-click challenges. | clickIconProvider 渲染有序图标点选挑战。
type clickIconProvider struct{}

// newClickIconProvider builds an icon-click provider. | newClickIconProvider 构建图标点选生成器。
func newClickIconProvider() *clickIconProvider { return &clickIconProvider{} }

// Type implements Provider. | Type 实现 Provider。
func (p *clickIconProvider) Type() Type { return TypeClickIcon }

// Generate implements Provider. | Generate 实现 Provider。
func (p *clickIconProvider) Generate(ctx context.Context, req GenerateRequest) (*Generated, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r, err := newRNG()
	if err != nil {
		return nil, err
	}
	specs := pickIcons(r, iconCatalog, 3)
	rest := make([]iconSpec, 0, len(iconCatalog))
	chosen := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		chosen[spec.Name] = struct{}{}
	}
	for _, spec := range iconCatalog {
		if _, ok := chosen[spec.Name]; !ok {
			rest = append(rest, spec)
		}
	}
	r.src.Shuffle(len(rest), func(i, j int) { rest[i], rest[j] = rest[j], rest[i] })
	icons := append(append([]iconSpec(nil), specs...), rest[:5]...)
	r.src.Shuffle(len(icons), func(i, j int) { icons[i], icons[j] = icons[j], icons[i] })
	c := newCanvas(req.Width, req.Height, r)
	c.background()
	cols, rows := 4, 2
	centers := cellCenters(r, cols, rows, req.Width, req.Height, 8)
	positions := make(map[string]Point, len(icons))
	tile := minInt(req.Width/cols, req.Height/rows) - 8
	if tile > 66 {
		tile = 66
	}
	for i, spec := range icons {
		center := centers[i%len(centers)]
		positions[spec.Name] = center
		drawIconTile(c, spec.Name, center.X, center.Y, tile)
	}
	targetPoints := make([]Point, 0, len(specs))
	labels := make([]string, 0, len(specs))
	names := make([]string, 0, len(specs))
	for _, spec := range specs {
		targetPoints = append(targetPoints, positions[spec.Name])
		names = append(names, spec.Name)
		labels = append(labels, iconLabel(req, spec))
	}
	img, err := c.encodePNG("challenge")
	if err != nil {
		return nil, err
	}
	tolerance, err := clickTargetTolerance(targetPoints, 28)
	if err != nil {
		return nil, err
	}
	answer, err := encodeAnswer(clickState{Points: targetPoints, Labels: labels, Icons: names, Tolerance: tolerance, Ordered: true})
	if err != nil {
		return nil, err
	}
	separator := ", "
	if isHanLocale(req.Locale) {
		separator = "、"
	}
	labelText := strings.Join(labels, separator)
	prompt := localizedPrompt(req, "prompt.click_icon", "hint.click_icon", "Click in order: "+labelText, "Follow the order", labelText)
	prompt.Count = len(labels)
	return &Generated{Prompt: prompt, Images: []ImageData{img}, Answer: answer}, nil
}

// Verify implements Provider. | Verify 实现 Provider。
func (p *clickIconProvider) Verify(ctx context.Context, rec *Record, ans Answer) (CheckResult, error) {
	if err := ctx.Err(); err != nil {
		return CheckResult{}, err
	}
	var state clickState
	if err := decodeAnswer(rec.Answer, &state); err != nil {
		return CheckResult{}, err
	}
	return verifyClickState(state, ans, "click_icon_mismatch"), nil
}

// verifyClickState applies ordered hit testing. | verifyClickState 执行有序命中测试。
func verifyClickState(state clickState, ans Answer, mismatch string) CheckResult {
	behavior, reasons := scoreTrack(ans.Track, len(state.Points)+2)
	if len(ans.Points) != len(state.Points) {
		return CheckResult{Passed: false, BehaviorScore: behavior, Reasons: append(reasons, mismatch)}
	}
	for i, point := range ans.Points {
		if distancePoint(point, state.Points[i]) > float64(state.Tolerance) {
			return CheckResult{Passed: false, BehaviorScore: behavior, Reasons: append(reasons, mismatch)}
		}
	}
	return CheckResult{Passed: true, BehaviorScore: behavior, Reasons: reasons}
}

// clickTargetTolerance keeps hit regions from overlapping on small canvases. | clickTargetTolerance 防止小画布上的命中区域互相重叠。
func clickTargetTolerance(points []Point, limit int) (int, error) {
	if len(points) < 2 {
		return limit, nil
	}
	minDistance := math.MaxFloat64
	for i := 0; i < len(points); i++ {
		for j := i + 1; j < len(points); j++ {
			if d := distancePoint(points[i], points[j]); d < minDistance {
				minDistance = d
			}
		}
	}
	if minDistance <= 12 {
		return 0, errs.Detail(ErrProvider, "click targets overlap | 点选目标重叠")
	}
	tolerance := int(minDistance / 3)
	if tolerance < 6 {
		tolerance = 6
	}
	if tolerance > limit {
		tolerance = limit
	}
	return tolerance, nil
}

// distancePoint returns the Euclidean distance between two points. | distancePoint 返回两点欧氏距离。
func distancePoint(a, b Point) float64 {
	return math.Hypot(float64(a.X-b.X), float64(a.Y-b.Y))
}

// cellCenters returns jittered centers for a regular grid. | cellCenters 返回带抖动的规则网格中心。
func cellCenters(r *rng, cols, rows, width, height, jitter int) []Point {
	if cols <= 0 {
		cols = 1
	}
	if rows <= 0 {
		rows = 1
	}
	out := make([]Point, 0, cols*rows)
	cellW := width / cols
	cellH := height / rows
	for row := 0; row < rows; row++ {
		for col := 0; col < cols; col++ {
			cx := col*cellW + cellW/2 + r.Intn(jitter*2+1) - jitter
			cy := row*cellH + cellH/2 + r.Intn(jitter*2+1) - jitter
			// Keep every center inside its own cell so small canvases cannot
			// collapse rows or columns onto one point. | 将中心限制在各自单元格内，
			// 避免小画布把行或列压缩到同一点。
			marginX := minInt(36, cellW/2)
			marginY := minInt(36, cellH/2)
			cx = clampInt(cx, col*cellW+marginX, (col+1)*cellW-marginX)
			cy = clampInt(cy, row*cellH+marginY, (row+1)*cellH-marginY)
			out = append(out, Point{X: cx, Y: cy})
		}
	}
	return out
}

// pickIcons samples n distinct icons. | pickIcons 无放回抽取 n 个不同图标。
func pickIcons(r *rng, pool []iconSpec, n int) []iconSpec {
	if n > len(pool) {
		n = len(pool)
	}
	perm := r.src.Perm(len(pool))
	out := make([]iconSpec, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, pool[perm[i]])
	}
	return out
}
