package challenge

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
	randv2 "math/rand/v2"
	"sync"

	"github.com/shibingli/ydx/errs"
)

// pngBufferPool recycles PNG encoding buffers. | pngBufferPool 复用 PNG 编码缓冲。
var pngBufferPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

// rng is a cryptographically seeded challenge random source. | rng 是密码学播种的挑战随机源。
type rng struct {
	src *randv2.Rand
}

// newRNG seeds a PCG source from crypto/rand. | newRNG 用 crypto/rand 为 PCG 播种。
func newRNG() (*rng, error) {
	var seed [16]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, errs.Wrap(err, ErrProvider)
	}
	return &rng{src: randv2.New(randv2.NewPCG(binary.LittleEndian.Uint64(seed[:8]), binary.LittleEndian.Uint64(seed[8:])))}, nil
}

// Intn returns a non-negative integer below n. | Intn 返回小于 n 的非负整数。
func (r *rng) Intn(n int) int {
	if n <= 1 {
		return 0
	}
	return r.src.IntN(n)
}

// Float64 returns a float in [0,1). | Float64 返回 [0,1) 内的浮点数。
func (r *rng) Float64() float64 { return r.src.Float64() }

// canvas is an opaque RGBA drawing surface. | canvas 是不透明 RGBA 绘图表面。
type canvas struct {
	img *image.RGBA
	rng *rng
}

// newCanvas allocates an opaque canvas. | newCanvas 分配不透明画布。
func newCanvas(width, height int, r *rng) *canvas {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for i := 3; i < len(img.Pix); i += 4 {
		img.Pix[i] = 255
	}
	return &canvas{img: img, rng: r}
}

// width returns the canvas width. | width 返回画布宽度。
func (c *canvas) width() int { return c.img.Bounds().Dx() }

// height returns the canvas height. | height 返回画布高度。
func (c *canvas) height() int { return c.img.Bounds().Dy() }

// fill paints a vertical gradient. | fill 绘制垂直渐变。
func (c *canvas) fill(top, bottom color.RGBA) {
	h := c.height()
	if h <= 0 {
		return
	}
	for y := 0; y < h; y++ {
		t := float64(y) / float64(maxInt(1, h-1))
		col := color.RGBA{
			R: uint8(float64(top.R)*(1-t) + float64(bottom.R)*t),
			G: uint8(float64(top.G)*(1-t) + float64(bottom.G)*t),
			B: uint8(float64(top.B)*(1-t) + float64(bottom.B)*t),
			A: 255,
		}
		for x := 0; x < c.width(); x++ {
			c.set(x, y, col)
		}
	}
}

// set writes one opaque pixel. | set 写入一个不透明像素。
func (c *canvas) set(x, y int, col color.RGBA) {
	if x < 0 || y < 0 || x >= c.width() || y >= c.height() {
		return
	}
	i := c.img.PixOffset(x, y)
	c.img.Pix[i] = col.R
	c.img.Pix[i+1] = col.G
	c.img.Pix[i+2] = col.B
	c.img.Pix[i+3] = 255
}

// blend alpha-composites a source color over one pixel. | blend 把一个源色阿尔法合成到一个像素。
func (c *canvas) blend(x, y int, col color.RGBA, alpha uint8) {
	if alpha == 0 || x < 0 || y < 0 || x >= c.width() || y >= c.height() {
		return
	}
	if alpha == 255 {
		c.set(x, y, col)
		return
	}
	i := c.img.PixOffset(x, y)
	a := uint32(alpha)
	inv := 255 - a
	c.img.Pix[i] = uint8((uint32(col.R)*a + uint32(c.img.Pix[i])*inv) / 255)
	c.img.Pix[i+1] = uint8((uint32(col.G)*a + uint32(c.img.Pix[i+1])*inv) / 255)
	c.img.Pix[i+2] = uint8((uint32(col.B)*a + uint32(c.img.Pix[i+2])*inv) / 255)
	c.img.Pix[i+3] = 255
}

// rect fills a rectangle. | rect 填充矩形。
func (c *canvas) rect(x, y, w, h int, col color.RGBA) {
	for py := y; py < y+h; py++ {
		for px := x; px < x+w; px++ {
			c.set(px, py, col)
		}
	}
}

// circle fills a circle. | circle 填充圆。
func (c *canvas) circle(cx, cy, radius int, col color.RGBA) {
	if radius <= 0 {
		return
	}
	r2 := radius * radius
	for y := cy - radius; y <= cy+radius; y++ {
		for x := cx - radius; x <= cx+radius; x++ {
			dx, dy := x-cx, y-cy
			if dx*dx+dy*dy <= r2 {
				c.set(x, y, col)
			}
		}
	}
}

// line draws a thick line with a round brush. | line 用圆刷绘制粗线。
func (c *canvas) line(x1, y1, x2, y2, width int, col color.RGBA) {
	if width <= 0 {
		width = 1
	}
	radius := float64(width) / 2
	minX := minInt(x1, x2) - width
	maxX := maxInt(x1, x2) + width
	minY := minInt(y1, y2) - width
	maxY := maxInt(y1, y2) + width
	dx := float64(x2 - x1)
	dy := float64(y2 - y1)
	lengthSq := dx*dx + dy*dy
	for y := minY; y <= maxY; y++ {
		for x := minX; x <= maxX; x++ {
			var t float64
			if lengthSq > 0 {
				t = (float64(x-x1)*dx + float64(y-y1)*dy) / lengthSq
				if t < 0 {
					t = 0
				} else if t > 1 {
					t = 1
				}
			}
			px := float64(x1) + t*dx
			py := float64(y1) + t*dy
			d := math.Hypot(float64(x)-px, float64(y)-py)
			if d <= radius {
				c.set(x, y, col)
			}
		}
	}
}

// polygon fills a simple polygon using scanline intersections. | polygon 用扫描线交点填充简单多边形。
func (c *canvas) polygon(points []Point, col color.RGBA) {
	if len(points) < 3 {
		return
	}
	minY, maxY := points[0].Y, points[0].Y
	for _, p := range points[1:] {
		minY = minInt(minY, p.Y)
		maxY = maxInt(maxY, p.Y)
	}
	if minY < 0 {
		minY = 0
	}
	if maxY >= c.height() {
		maxY = c.height() - 1
	}
	intersections := make([]float64, 0, len(points))
	for y := minY; y <= maxY; y++ {
		intersections = intersections[:0]
		cy := float64(y) + 0.5
		for i := range points {
			a := points[i]
			b := points[(i+1)%len(points)]
			ay, by := float64(a.Y), float64(b.Y)
			if (ay <= cy && by > cy) || (by <= cy && ay > cy) {
				x := float64(a.X) + (cy-ay)*(float64(b.X-a.X))/(by-ay)
				intersections = append(intersections, x)
			}
		}
		if len(intersections) < 2 {
			continue
		}
		for i := 0; i+1 < len(intersections); i += 2 {
			start := int(math.Ceil(intersections[i] - 0.5))
			end := int(math.Floor(intersections[i+1] - 0.5))
			for x := start; x <= end; x++ {
				c.set(x, y, col)
			}
		}
	}
}

// background paints a noisy gradient with interference shapes. | background 绘制带干扰图形的噪声渐变。
func (c *canvas) background() {
	palettes := [][2]color.RGBA{
		{{R: 238, G: 245, B: 255, A: 255}, {R: 188, G: 215, B: 238, A: 255}},
		{{R: 255, G: 244, B: 230, A: 255}, {R: 245, G: 205, B: 160, A: 255}},
		{{R: 238, G: 247, B: 238, A: 255}, {R: 184, G: 218, B: 184, A: 255}},
		{{R: 245, G: 235, B: 250, A: 255}, {R: 207, G: 186, B: 224, A: 255}},
	}
	pair := palettes[c.rng.Intn(len(palettes))]
	c.fill(pair[0], pair[1])
	for i := 0; i < 7; i++ {
		col := randomColor(c.rng, 60, 220)
		alpha := uint8(25 + c.rng.Intn(45))
		if c.rng.Intn(2) == 0 {
			c.line(c.rng.Intn(c.width()), c.rng.Intn(c.height()), c.rng.Intn(c.width()), c.rng.Intn(c.height()), 1+c.rng.Intn(3), withAlpha(col, alpha))
		} else {
			r := 8 + c.rng.Intn(28)
			c.circle(c.rng.Intn(c.width()), c.rng.Intn(c.height()), r, withAlpha(col, alpha))
		}
	}
	for i := 0; i < 900; i++ {
		col := randomColor(c.rng, 30, 230)
		c.blend(c.rng.Intn(c.width()), c.rng.Intn(c.height()), col, uint8(20+c.rng.Intn(40)))
	}
}

// glyphMask draws one glyph mask. | glyphMask 绘制一张字形掩码。
func (c *canvas) glyph(mask glyphMask, cx, cy, size int, angle float64, col color.RGBA) {
	if size <= 0 {
		return
	}
	cosA, sinA := math.Cos(angle), math.Sin(angle)
	half := float64(size) / 2
	scale := float64(glyphSize) / float64(size)
	startX := cx - size/2
	startY := cy - size/2
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			dx := float64(px) + 0.5 - half
			dy := float64(py) + 0.5 - half
			sx := (dx*cosA + dy*sinA) * scale
			sy := (-dx*sinA + dy*cosA) * scale
			fx := sx + float64(glyphSize)/2 - 0.5
			fy := sy + float64(glyphSize)/2 - 0.5
			if fx < 0 || fy < 0 || fx >= glyphSize-1 || fy >= glyphSize-1 {
				continue
			}
			x0, y0 := int(fx), int(fy)
			ax := fx - float64(x0)
			ay := fy - float64(y0)
			a00 := float64(mask.alpha[y0*glyphSize+x0])
			a10 := float64(mask.alpha[y0*glyphSize+x0+1])
			a01 := float64(mask.alpha[(y0+1)*glyphSize+x0])
			a11 := float64(mask.alpha[(y0+1)*glyphSize+x0+1])
			coverage := a00*(1-ax)*(1-ay) + a10*ax*(1-ay) + a01*(1-ax)*ay + a11*ax*ay
			if coverage <= 4 {
				continue
			}
			c.blend(startX+px, startY+py, col, uint8(coverage))
		}
	}
}

// text draws a string of glyphs and returns the advance width. | text 绘制一串字形并返回推进宽度。
func (c *canvas) text(s string, x, y, size, spacing int, angle float64, col color.RGBA) int {
	atlas, err := loadGlyphs()
	if err != nil || atlas == nil {
		return 0
	}
	advance := size + spacing
	cursor := x
	for _, r := range s {
		if _, ok := atlas.glyphFor(r); !ok {
			cursor += advance
			continue
		}
		mask, _ := atlas.glyphFor(r)
		c.glyph(mask, cursor+size/2, y, size, angle, col)
		cursor += advance
	}
	return cursor - x
}

// noise adds random interference strokes. | noise 添加随机干扰笔画。
func (c *canvas) noise(lines, dots int) {
	for i := 0; i < lines; i++ {
		col := randomColor(c.rng, 40, 230)
		c.line(c.rng.Intn(c.width()), c.rng.Intn(c.height()), c.rng.Intn(c.width()), c.rng.Intn(c.height()), 1, withAlpha(col, uint8(60+c.rng.Intn(100))))
	}
	for i := 0; i < dots; i++ {
		col := randomColor(c.rng, 20, 240)
		c.blend(c.rng.Intn(c.width()), c.rng.Intn(c.height()), col, uint8(50+c.rng.Intn(120)))
	}
}

// copyRect copies a rectangle from the canvas. | copyRect 从画布复制一个矩形。
func (c *canvas) copyRect(x, y, w, h int) *image.RGBA {
	out := image.NewRGBA(image.Rect(0, 0, w, h))
	for py := 0; py < h; py++ {
		for px := 0; px < w; px++ {
			sx, sy := x+px, y+py
			if sx < 0 || sy < 0 || sx >= c.width() || sy >= c.height() {
				continue
			}
			si := c.img.PixOffset(sx, sy)
			di := out.PixOffset(px, py)
			copy(out.Pix[di:di+4], c.img.Pix[si:si+4])
		}
	}
	return out
}

// drawImage copies an RGBA image onto the canvas at x,y. | drawImage 把 RGBA 图片复制到画布 x,y 处。
func (c *canvas) drawImage(src *image.RGBA, x, y int) {
	if src == nil {
		return
	}
	b := src.Bounds()
	for py := 0; py < b.Dy(); py++ {
		for px := 0; px < b.Dx(); px++ {
			si := src.PixOffset(b.Min.X+px, b.Min.Y+py)
			c.set(x+px, y+py, color.RGBA{R: src.Pix[si], G: src.Pix[si+1], B: src.Pix[si+2], A: 255})
		}
	}
}

// rotateImage rotates src by radians into a new canvas. | rotateImage 把 src 旋转 radians 弧度到新画布。
func rotateImage(src *image.RGBA, radians float64, bg color.RGBA, r *rng) *canvas {
	out := newCanvas(src.Bounds().Dx(), src.Bounds().Dy(), r)
	out.fill(bg, bg)
	cosA, sinA := math.Cos(-radians), math.Sin(-radians)
	cx := float64(src.Bounds().Dx()) / 2
	cy := float64(src.Bounds().Dy()) / 2
	for y := 0; y < src.Bounds().Dy(); y++ {
		for x := 0; x < src.Bounds().Dx(); x++ {
			dx := float64(x) - cx
			dy := float64(y) - cy
			sx := int(dx*cosA+dy*sinA+cx) + src.Bounds().Min.X
			sy := int(-dx*sinA+dy*cosA+cy) + src.Bounds().Min.Y
			if sx < src.Bounds().Min.X || sy < src.Bounds().Min.Y || sx >= src.Bounds().Max.X || sy >= src.Bounds().Max.Y {
				continue
			}
			i := src.PixOffset(sx, sy)
			out.set(x, y, color.RGBA{R: src.Pix[i], G: src.Pix[i+1], B: src.Pix[i+2], A: 255})
		}
	}
	return out
}

// encodePNG encodes the canvas as an ImageData. | encodePNG 把画布编码为 ImageData。
func (c *canvas) encodePNG(name string) (ImageData, error) {
	buf := pngBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	encoder := png.Encoder{CompressionLevel: png.BestSpeed}
	if err := encoder.Encode(buf, c.img); err != nil {
		buf.Reset()
		pngBufferPool.Put(buf)
		return ImageData{}, errs.Wrap(err, ErrProvider)
	}
	data := append([]byte(nil), buf.Bytes()...)
	buf.Reset()
	pngBufferPool.Put(buf)
	return ImageData{
		Name:   name,
		MIME:   "image/png",
		Width:  c.width(),
		Height: c.height(),
		Data:   data,
	}, nil
}

// randomColor returns a random color in [min,max] per channel. | randomColor 返回每个通道在 [min,max] 内的随机颜色。
func randomColor(r *rng, min, max int) color.RGBA {
	if max < min {
		min, max = max, min
	}
	span := max - min + 1
	return color.RGBA{
		R: uint8(min + r.Intn(span)),
		G: uint8(min + r.Intn(span)),
		B: uint8(min + r.Intn(span)),
		A: 255,
	}
}

// withAlpha replaces a color's alpha. | withAlpha 替换颜色的阿尔法值。
func withAlpha(col color.RGBA, alpha uint8) color.RGBA {
	col.A = alpha
	return col
}

// maxInt returns the larger integer. | maxInt 返回较大的整数。
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// minInt returns the smaller integer. | minInt 返回较小的整数。
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// clampInt limits v to [lo,hi]. | clampInt 把 v 限制到 [lo,hi]。
func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
