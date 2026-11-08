package challenge

import (
	"context"
	"image/color"
	"math"
	"strings"
	"time"
)

// Scratch challenge constants. | 刮刮卡挑战常量。
const (
	// scratchGlyphCount is the fixed number of revealed characters. | scratchGlyphCount 是显露字符的固定数量。
	scratchGlyphCount = 4
	// scratchCoverageThreshold is the minimum revealed fraction of the glyph band. | scratchCoverageThreshold 是字符区域最少显露比例。
	scratchCoverageThreshold = 0.5
	// scratchCoverageCell is the coverage raster cell size in pixels. | scratchCoverageCell 是覆盖栅格的像元大小。
	scratchCoverageCell = 4
	// scratchMaxTrackPoints bounds coverage work from direct API callers. | scratchMaxTrackPoints 限制直接 API 调用者的覆盖计算量。
	scratchMaxTrackPoints = 512
	// scratchMaxDimension bounds stored answer geometry. | scratchMaxDimension 限制已存答案的几何尺寸。
	scratchMaxDimension = 2048
)

// scratchState is the server-side scratch-code answer. | scratchState 是刮刮卡的服务端答案。
type scratchState struct {
	// Text is the hidden character sequence. | Text 是隐藏字符序列。
	Text string `json:"text"`
	// Width is the rendered canvas width. | Width 是渲染画布宽度。
	Width int `json:"width"`
	// Height is the rendered canvas height. | Height 是渲染画布高度。
	Height int `json:"height"`
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
	runes := pickRunes(r, pool, scratchGlyphCount)
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
	answer, err := encodeAnswer(scratchState{Text: text, Width: req.Width, Height: req.Height})
	if err != nil {
		return nil, err
	}
	prompt := localizedPrompt(req, "prompt.scratch", "hint.scratch", "Scratch the coating and type the characters", "Type what you reveal")
	return &Generated{Prompt: prompt, Images: []ImageData{challenge, coverImg}, Answer: answer}, nil
}

// scratchLayout fits four reveal glyphs inside the canvas. | scratchLayout 让四个显露字形适配画布。
func scratchLayout(width, height int) (size, start int) {
	size = (width - 40) / scratchGlyphCount
	size = clampInt(size, 16, 72)
	if max := height - 16; size > max {
		size = max
	}
	if size < 10 {
		size = 10
	}
	maxWidth := width - 16
	for size > 10 {
		if scratchTotalWidth(size) <= maxWidth {
			break
		}
		size--
	}
	total := scratchTotalWidth(size)
	start = (width - total) / 2
	if start < 0 {
		start = 0
	}
	return size, start
}

// scratchTotalWidth returns the glyph band width for one glyph size. | scratchTotalWidth 返回给定字形尺寸的字符区域宽度。
func scratchTotalWidth(size int) int {
	return scratchGlyphCount*size + (scratchGlyphCount-1)*(size/7)
}

// scratchBand returns the glyph reveal area used for coverage checks. | scratchBand 返回用于覆盖检查的字符显露区域。
func (s scratchState) scratchBand() (x, y, width, height int, ok bool) {
	if s.Width < 1 || s.Height < 1 || s.Width > scratchMaxDimension || s.Height > scratchMaxDimension {
		return 0, 0, 0, 0, false
	}
	size, start := scratchLayout(s.Width, s.Height)
	total := scratchTotalWidth(size)
	if start < 0 || total <= 0 || start+total > s.Width {
		return 0, 0, 0, 0, false
	}
	y = s.Height/2 - size/2
	if y < 0 || y+size > s.Height {
		return 0, 0, 0, 0, false
	}
	return start, y, total, size, true
}

// scratchCoverage returns the revealed fraction of the glyph band. | scratchCoverage 返回字符区域的显露比例。
//
// The browser erases a round brush of max(12, width/20) pixels along the
// pointer path. Coverage is a bounded raster approximation of that capsule
// union; it is a deterrence signal, not part of the answer. | 浏览器沿指针路径擦除
// max(12, width/20) 像素的圆形笔刷。覆盖率为该胶囊并集的有界栅格近似，只是威慑信号，
// 不参与答案判定本身。
func (s scratchState) scratchCoverage(track Track) float64 {
	bandX, bandY, bandWidth, bandHeight, ok := s.scratchBand()
	if !ok {
		return 0
	}
	cols := (bandWidth + scratchCoverageCell - 1) / scratchCoverageCell
	rows := (bandHeight + scratchCoverageCell - 1) / scratchCoverageCell
	if cols <= 0 || rows <= 0 {
		return 0
	}
	covered := make([]bool, cols*rows)
	radius := float64(s.Width) / 20
	if radius < 12 {
		radius = 12
	}
	grid := scratchGrid{
		covered: covered,
		cols:    cols,
		rows:    rows,
		x:       bandX,
		y:       bandY,
		radius:  radius,
	}
	points := track.Points
	if len(points) > scratchMaxTrackPoints {
		points = points[:scratchMaxTrackPoints]
	}
	clampX := func(value int) float64 {
		if value < 0 {
			return 0
		}
		if value > s.Width {
			return float64(s.Width)
		}
		return float64(value)
	}
	clampY := func(value int) float64 {
		if value < 0 {
			return 0
		}
		if value > s.Height {
			return float64(s.Height)
		}
		return float64(value)
	}
	previousX, previousY := 0.0, 0.0
	hasPrevious := false
	for _, point := range points {
		x, y := clampX(point.X), clampY(point.Y)
		if point.Kind == "down" {
			// The browser starts a new stroke on pointerdown. | 浏览器在 pointerdown 时开始新笔画。
			hasPrevious = false
		}
		if hasPrevious {
			grid.markSegment(previousX, previousY, x, y)
		} else {
			grid.markSegment(x, y, x, y)
		}
		previousX, previousY = x, y
		hasPrevious = point.Kind != "up"
	}
	var marked int
	for _, hit := range covered {
		if hit {
			marked++
		}
	}
	return float64(marked) / float64(len(covered))
}

// scratchGrid marks raster cells covered by a brush capsule. | scratchGrid 标记笔刷胶囊覆盖的栅格单元。
type scratchGrid struct {
	covered []bool
	cols    int
	rows    int
	x       int
	y       int
	radius  float64
}

// markSegment marks every cell center within radius of one line segment. | markSegment 标记距一条线段不超过半径的全部单元中心。
func (g *scratchGrid) markSegment(x0, y0, x1, y1 float64) {
	minX := math.Min(x0, x1) - g.radius
	maxX := math.Max(x0, x1) + g.radius
	minY := math.Min(y0, y1) - g.radius
	maxY := math.Max(y0, y1) + g.radius
	gridMaxX := float64(g.x + g.cols*scratchCoverageCell)
	gridMaxY := float64(g.y + g.rows*scratchCoverageCell)
	if maxX < float64(g.x) || minX >= gridMaxX || maxY < float64(g.y) || minY >= gridMaxY {
		return
	}
	firstCol := int(math.Floor((minX - float64(g.x)) / scratchCoverageCell))
	lastCol := int(math.Floor((maxX - float64(g.x)) / scratchCoverageCell))
	firstRow := int(math.Floor((minY - float64(g.y)) / scratchCoverageCell))
	lastRow := int(math.Floor((maxY - float64(g.y)) / scratchCoverageCell))
	if firstCol < 0 {
		firstCol = 0
	}
	if firstRow < 0 {
		firstRow = 0
	}
	if lastCol >= g.cols {
		lastCol = g.cols - 1
	}
	if lastRow >= g.rows {
		lastRow = g.rows - 1
	}
	radiusSquared := g.radius * g.radius
	cell := float64(scratchCoverageCell)
	for row := firstRow; row <= lastRow; row++ {
		centerY := float64(g.y) + (float64(row)+0.5)*cell
		rowOffset := row * g.cols
		for col := firstCol; col <= lastCol; col++ {
			if g.covered[rowOffset+col] {
				continue
			}
			centerX := float64(g.x) + (float64(col)+0.5)*cell
			if scratchPointSegmentDistanceSquared(centerX, centerY, x0, y0, x1, y1) <= radiusSquared {
				g.covered[rowOffset+col] = true
			}
		}
	}
}

// scratchPointSegmentDistanceSquared returns the squared distance from a point to a segment. | scratchPointSegmentDistanceSquared 返回点到线段的平方距离。
func scratchPointSegmentDistanceSquared(px, py, x0, y0, x1, y1 float64) float64 {
	dx, dy := x1-x0, y1-y0
	if dx == 0 && dy == 0 {
		ex, ey := px-x0, py-y0
		return ex*ex + ey*ey
	}
	t := ((px-x0)*dx + (py-y0)*dy) / (dx*dx + dy*dy)
	if t < 0 {
		t = 0
	} else if t > 1 {
		t = 1
	}
	ex, ey := x0+t*dx-px, y0+t*dy-py
	return ex*ex + ey*ey
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
	if state.scratchCoverage(ans.Track) < scratchCoverageThreshold {
		reasons = append(reasons, "scratch_coverage_low")
		return CheckResult{Passed: false, BehaviorScore: behavior, Reasons: reasons}, nil
	}
	passed := strings.EqualFold(strings.TrimSpace(ans.Text), state.Text)
	if !passed {
		reasons = append(reasons, "scratch_text_mismatch")
	}
	return CheckResult{Passed: passed, BehaviorScore: behavior, Reasons: reasons}, nil
}
