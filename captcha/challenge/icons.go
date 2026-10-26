package challenge

import (
	"image/color"
	"math"
)

// iconSpec describes one icon used by click and semantic challenges. | iconSpec 描述点选与语义挑战使用的一个图标。
type iconSpec struct {
	// Name is the stable icon identifier. | Name 是稳定图标标识。
	Name string
	// ZH is the Chinese label. | ZH 是中文标签。
	ZH string
	// EN is the English label. | EN 是英文标签。
	EN string
	// Category groups semantically related icons. | Category 把语义相关的图标分组。
	Category string
}

// iconCatalog is the built-in icon vocabulary. | iconCatalog 是内置图标词表。
var iconCatalog = []iconSpec{
	{Name: "apple", ZH: "苹果", EN: "apple", Category: "fruit"},
	{Name: "banana", ZH: "香蕉", EN: "banana", Category: "fruit"},
	{Name: "grape", ZH: "葡萄", EN: "grape", Category: "fruit"},
	{Name: "orange", ZH: "橙子", EN: "orange", Category: "fruit"},
	{Name: "pear", ZH: "梨", EN: "pear", Category: "fruit"},
	{Name: "strawberry", ZH: "草莓", EN: "strawberry", Category: "fruit"},
	{Name: "car", ZH: "汽车", EN: "car", Category: "vehicle"},
	{Name: "plane", ZH: "飞机", EN: "plane", Category: "vehicle"},
	{Name: "umbrella", ZH: "雨伞", EN: "umbrella", Category: "object"},
	{Name: "key", ZH: "钥匙", EN: "key", Category: "object"},
	{Name: "sun", ZH: "太阳", EN: "sun", Category: "nature"},
	{Name: "moon", ZH: "月亮", EN: "moon", Category: "nature"},
	{Name: "cloud", ZH: "云朵", EN: "cloud", Category: "nature"},
	{Name: "flower", ZH: "花朵", EN: "flower", Category: "nature"},
	{Name: "fish", ZH: "鱼", EN: "fish", Category: "animal"},
	{Name: "bird", ZH: "鸟", EN: "bird", Category: "animal"},
	{Name: "tree", ZH: "树", EN: "tree", Category: "nature"},
	{Name: "house", ZH: "房子", EN: "house", Category: "object"},
	{Name: "ball", ZH: "球", EN: "ball", Category: "object"},
	{Name: "gift", ZH: "礼物", EN: "gift", Category: "object"},
}

// iconByName returns one catalog entry. | iconByName 返回一个词表条目。
func iconByName(name string) (iconSpec, bool) {
	for _, spec := range iconCatalog {
		if spec.Name == name {
			return spec, true
		}
	}
	return iconSpec{}, false
}

// iconsByCategory returns copies of all icons in a category. | iconsByCategory 返回某一分类的全部图标副本。
func iconsByCategory(category string) []iconSpec {
	out := make([]iconSpec, 0, 6)
	for _, spec := range iconCatalog {
		if spec.Category == category {
			out = append(out, spec)
		}
	}
	return out
}

// drawIconTile paints a pastel tile and the named icon. | drawIconTile 绘制柔和底色方块与指定图标。
func drawIconTile(c *canvas, name string, cx, cy, size int) bool {
	bg := color.RGBA{R: 250, G: 250, B: 246, A: 255}
	c.rect(cx-size/2, cy-size/2, size, size, bg)
	c.line(cx-size/2, cy-size/2, cx+size/2, cy-size/2, 2, color.RGBA{R: 210, G: 214, B: 220, A: 255})
	c.line(cx-size/2, cy+size/2, cx+size/2, cy+size/2, 2, color.RGBA{R: 210, G: 214, B: 220, A: 255})
	c.line(cx-size/2, cy-size/2, cx-size/2, cy+size/2, 2, color.RGBA{R: 210, G: 214, B: 220, A: 255})
	c.line(cx+size/2, cy-size/2, cx+size/2, cy+size/2, 2, color.RGBA{R: 210, G: 214, B: 220, A: 255})
	return drawIcon(c, name, cx, cy, size)
}

// drawIcon dispatches one icon painter. | drawIcon 分发一个图标绘制器。
func drawIcon(c *canvas, name string, cx, cy, size int) bool {
	switch name {
	case "apple":
		drawApple(c, cx, cy, size)
	case "banana":
		drawBanana(c, cx, cy, size)
	case "grape":
		drawGrape(c, cx, cy, size)
	case "orange":
		drawOrange(c, cx, cy, size)
	case "pear":
		drawPear(c, cx, cy, size)
	case "strawberry":
		drawStrawberry(c, cx, cy, size)
	case "car":
		drawCar(c, cx, cy, size)
	case "plane":
		drawPlane(c, cx, cy, size)
	case "umbrella":
		drawUmbrella(c, cx, cy, size)
	case "key":
		drawKey(c, cx, cy, size)
	case "sun":
		drawSun(c, cx, cy, size)
	case "moon":
		drawMoon(c, cx, cy, size)
	case "cloud":
		drawCloud(c, cx, cy, size)
	case "flower":
		drawFlower(c, cx, cy, size)
	case "fish":
		drawFish(c, cx, cy, size)
	case "bird":
		drawBird(c, cx, cy, size)
	case "tree":
		drawTree(c, cx, cy, size)
	case "house":
		drawHouse(c, cx, cy, size)
	case "ball":
		drawBall(c, cx, cy, size)
	case "gift":
		drawGift(c, cx, cy, size)
	default:
		return false
	}
	return true
}

// iconPen maps 0-100 icon coordinates to one tile. | iconPen 把 0-100 图标坐标映射到一个方块。
type iconPen struct {
	c    *canvas
	cx   int
	cy   int
	side float64
}

// newIconPen builds a coordinate mapper. | newIconPen 构建坐标映射器。
func newIconPen(c *canvas, cx, cy, size int) iconPen {
	return iconPen{c: c, cx: cx, cy: cy, side: float64(size) * 0.78}
}

// x maps a horizontal icon coordinate. | x 映射水平图标坐标。
func (p iconPen) x(v float64) int { return p.cx + int((v-50)*p.side/100) }

// y maps a vertical icon coordinate. | y 映射垂直图标坐标。
func (p iconPen) y(v float64) int { return p.cy + int((v-50)*p.side/100) }

// r maps a radius. | r 映射半径。
func (p iconPen) r(v float64) int { return maxInt(1, int(v*p.side/100)) }

// pt maps a point. | pt 映射一个点。
func (p iconPen) pt(x, y float64) Point { return Point{X: p.x(x), Y: p.y(y)} }

// rect fills a mapped rectangle. | rect 填充映射矩形。
func (p iconPen) rect(x, y, w, h float64, col color.RGBA) {
	p.c.rect(p.x(x), p.y(y), p.r(w), p.r(h), col)
}

// circle fills a mapped circle. | circle 填充映射圆。
func (p iconPen) circle(x, y, radius float64, col color.RGBA) {
	p.c.circle(p.x(x), p.y(y), p.r(radius), col)
}

// line draws a mapped line. | line 绘制映射线段。
func (p iconPen) line(x1, y1, x2, y2, width float64, col color.RGBA) {
	p.c.line(p.x(x1), p.y(y1), p.x(x2), p.y(y2), p.r(width), col)
}

// polygon fills mapped points. | polygon 填充映射多边形。
func (p iconPen) polygon(points []Point, col color.RGBA) { p.c.polygon(points, col) }

// std returns a pen with normalized coordinates. | std 返回标准坐标笔。
func (p iconPen) std(points ...[2]float64) []Point {
	out := make([]Point, 0, len(points))
	for _, point := range points {
		out = append(out, p.pt(point[0], point[1]))
	}
	return out
}

// drawApple paints a red apple. | drawApple 绘制红苹果。
func drawApple(c *canvas, cx, cy, size int) {
	p := newIconPen(c, cx, cy, size)
	p.circle(50, 54, 27, color.RGBA{R: 218, G: 61, B: 56, A: 255})
	p.circle(42, 46, 9, color.RGBA{R: 239, G: 112, B: 104, A: 255})
	p.line(50, 31, 55, 18, 4, color.RGBA{R: 100, G: 68, B: 40, A: 255})
	p.circle(64, 20, 9, color.RGBA{R: 70, G: 160, B: 72, A: 255})
}

// drawBanana paints a yellow banana. | drawBanana 绘制黄香蕉。
func drawBanana(c *canvas, cx, cy, size int) {
	p := newIconPen(c, cx, cy, size)
	p.polygon(p.std(
		[2]float64{22, 38}, [2]float64{34, 28}, [2]float64{58, 58},
		[2]float64{80, 72}, [2]float64{73, 83}, [2]float64{48, 72},
	), color.RGBA{R: 244, G: 200, B: 58, A: 255})
	p.line(24, 38, 34, 29, 3, color.RGBA{R: 160, G: 130, B: 36, A: 255})
}

// drawGrape paints a purple grape cluster. | drawGrape 绘制紫葡萄串。
func drawGrape(c *canvas, cx, cy, size int) {
	p := newIconPen(c, cx, cy, size)
	p.line(50, 22, 52, 32, 4, color.RGBA{R: 92, G: 125, B: 55, A: 255})
	grape := color.RGBA{R: 112, G: 76, B: 160, A: 255}
	highlight := color.RGBA{R: 160, G: 126, B: 200, A: 255}
	for row, y := range []float64{36, 49, 62, 74} {
		offset := float64(row%2) * 7
		for i := 0; i < 3; i++ {
			x := 38 + offset + float64(i)*12
			p.circle(x, y, 7, grape)
			p.circle(x-2, y-2, 2, highlight)
		}
	}
}

// drawOrange paints an orange. | drawOrange 绘制橙子。
func drawOrange(c *canvas, cx, cy, size int) {
	p := newIconPen(c, cx, cy, size)
	p.circle(50, 56, 27, color.RGBA{R: 244, G: 150, B: 42, A: 255})
	p.circle(41, 47, 8, color.RGBA{R: 252, G: 190, B: 92, A: 255})
	p.circle(60, 27, 8, color.RGBA{R: 67, G: 155, B: 74, A: 255})
	p.line(50, 31, 50, 40, 3, color.RGBA{R: 100, G: 68, B: 40, A: 255})
}

// drawPear paints a green pear. | drawPear 绘制青梨。
func drawPear(c *canvas, cx, cy, size int) {
	p := newIconPen(c, cx, cy, size)
	p.circle(50, 63, 23, color.RGBA{R: 154, G: 190, B: 65, A: 255})
	p.circle(50, 38, 15, color.RGBA{R: 154, G: 190, B: 65, A: 255})
	p.line(50, 27, 55, 18, 3, color.RGBA{R: 100, G: 68, B: 40, A: 255})
	p.circle(43, 57, 6, color.RGBA{R: 200, G: 220, B: 120, A: 255})
}

// drawStrawberry paints a red strawberry. | drawStrawberry 绘制红草莓。
func drawStrawberry(c *canvas, cx, cy, size int) {
	p := newIconPen(c, cx, cy, size)
	p.polygon(p.std(
		[2]float64{29, 39}, [2]float64{71, 39}, [2]float64{62, 66},
		[2]float64{50, 84}, [2]float64{38, 66},
	), color.RGBA{R: 220, G: 50, B: 57, A: 255})
	p.circle(40, 33, 8, color.RGBA{R: 73, G: 155, B: 66, A: 255})
	p.circle(60, 33, 8, color.RGBA{R: 73, G: 155, B: 66, A: 255})
	p.circle(50, 31, 8, color.RGBA{R: 73, G: 155, B: 66, A: 255})
	for _, pt := range [][2]float64{{42, 50}, {58, 53}, {48, 64}, {61, 66}} {
		p.circle(pt[0], pt[1], 1.5, color.RGBA{R: 255, G: 230, B: 120, A: 255})
	}
}

// drawCar paints a blue car. | drawCar 绘制蓝色汽车。
func drawCar(c *canvas, cx, cy, size int) {
	p := newIconPen(c, cx, cy, size)
	p.rect(20, 45, 60, 22, color.RGBA{R: 54, G: 112, B: 200, A: 255})
	p.polygon(p.std([2]float64{32, 45}, [2]float64{42, 30}, [2]float64{64, 30}, [2]float64{73, 45}), color.RGBA{R: 88, G: 148, B: 228, A: 255})
	p.rect(43, 33, 16, 10, color.RGBA{R: 212, G: 236, B: 252, A: 255})
	p.circle(35, 68, 9, color.RGBA{R: 42, G: 46, B: 54, A: 255})
	p.circle(70, 68, 9, color.RGBA{R: 42, G: 46, B: 54, A: 255})
}

// drawPlane paints a white plane. | drawPlane 绘制白色飞机。
func drawPlane(c *canvas, cx, cy, size int) {
	p := newIconPen(c, cx, cy, size)
	p.polygon(p.std(
		[2]float64{17, 53}, [2]float64{84, 40}, [2]float64{54, 60},
		[2]float64{47, 80}, [2]float64{39, 62},
	), color.RGBA{R: 236, G: 242, B: 250, A: 255})
	p.line(35, 55, 61, 49, 2, color.RGBA{R: 92, G: 132, B: 188, A: 255})
}

// drawUmbrella paints a red umbrella. | drawUmbrella 绘制红雨伞。
func drawUmbrella(c *canvas, cx, cy, size int) {
	p := newIconPen(c, cx, cy, size)
	p.polygon(p.std(
		[2]float64{20, 52}, [2]float64{34, 32}, [2]float64{50, 25},
		[2]float64{66, 32}, [2]float64{80, 52}, [2]float64{50, 45},
	), color.RGBA{R: 214, G: 68, B: 66, A: 255})
	p.line(50, 47, 50, 76, 3, color.RGBA{R: 92, G: 68, B: 46, A: 255})
	p.line(50, 76, 63, 76, 3, color.RGBA{R: 92, G: 68, B: 46, A: 255})
}

// drawKey paints a golden key. | drawKey 绘制金色钥匙。
func drawKey(c *canvas, cx, cy, size int) {
	p := newIconPen(c, cx, cy, size)
	p.circle(35, 42, 14, color.RGBA{R: 230, G: 186, B: 54, A: 255})
	p.circle(35, 42, 6, color.RGBA{R: 250, G: 250, B: 246, A: 255})
	p.line(45, 51, 76, 76, 5, color.RGBA{R: 230, G: 186, B: 54, A: 255})
	p.line(63, 66, 72, 57, 4, color.RGBA{R: 230, G: 186, B: 54, A: 255})
	p.line(70, 73, 78, 65, 4, color.RGBA{R: 230, G: 186, B: 54, A: 255})
}

// drawSun paints a yellow sun. | drawSun 绘制黄色太阳。
func drawSun(c *canvas, cx, cy, size int) {
	p := newIconPen(c, cx, cy, size)
	for i := 0; i < 8; i++ {
		angle := float64(i) * math.Pi / 4
		p.line(50+math.Cos(angle)*29, 50+math.Sin(angle)*29, 50+math.Cos(angle)*40, 50+math.Sin(angle)*40, 3, color.RGBA{R: 240, G: 174, B: 44, A: 255})
	}
	p.circle(50, 50, 22, color.RGBA{R: 247, G: 196, B: 52, A: 255})
	p.circle(43, 43, 7, color.RGBA{R: 255, G: 224, B: 126, A: 255})
}

// drawMoon paints a yellow crescent. | drawMoon 绘制黄色月牙。
func drawMoon(c *canvas, cx, cy, size int) {
	p := newIconPen(c, cx, cy, size)
	p.circle(53, 50, 26, color.RGBA{R: 242, G: 200, B: 72, A: 255})
	p.circle(66, 42, 24, color.RGBA{R: 250, G: 250, B: 246, A: 255})
}

// drawCloud paints a white cloud. | drawCloud 绘制白云。
func drawCloud(c *canvas, cx, cy, size int) {
	p := newIconPen(c, cx, cy, size)
	white := color.RGBA{R: 238, G: 244, B: 252, A: 255}
	shadow := color.RGBA{R: 188, G: 204, B: 224, A: 255}
	p.circle(36, 55, 14, shadow)
	p.circle(51, 43, 18, white)
	p.circle(67, 55, 14, white)
	p.rect(32, 55, 39, 14, white)
}

// drawFlower paints a pink flower. | drawFlower 绘制粉色花朵。
func drawFlower(c *canvas, cx, cy, size int) {
	p := newIconPen(c, cx, cy, size)
	petal := color.RGBA{R: 232, G: 112, B: 170, A: 255}
	for i := 0; i < 6; i++ {
		angle := float64(i) * math.Pi / 3
		p.circle(50+math.Cos(angle)*16, 46+math.Sin(angle)*16, 10, petal)
	}
	p.circle(50, 46, 9, color.RGBA{R: 250, G: 198, B: 56, A: 255})
	p.line(50, 55, 50, 82, 3, color.RGBA{R: 74, G: 146, B: 72, A: 255})
}

// drawFish paints a blue fish. | drawFish 绘制蓝色鱼。
func drawFish(c *canvas, cx, cy, size int) {
	p := newIconPen(c, cx, cy, size)
	p.circle(48, 52, 22, color.RGBA{R: 70, G: 150, B: 214, A: 255})
	p.polygon(p.std([2]float64{68, 52}, [2]float64{84, 38}, [2]float64{84, 66}), color.RGBA{R: 46, G: 112, B: 176, A: 255})
	p.circle(39, 45, 3, color.RGBA{R: 24, G: 34, B: 48, A: 255})
	p.line(50, 74, 58, 84, 3, color.RGBA{R: 46, G: 112, B: 176, A: 255})
}

// drawBird paints a simple bird. | drawBird 绘制简笔鸟。
func drawBird(c *canvas, cx, cy, size int) {
	p := newIconPen(c, cx, cy, size)
	col := color.RGBA{R: 66, G: 140, B: 176, A: 255}
	p.line(18, 50, 34, 34, 5, col)
	p.line(34, 34, 50, 50, 5, col)
	p.line(50, 50, 66, 32, 5, col)
	p.line(66, 32, 82, 48, 5, col)
	p.circle(50, 52, 8, color.RGBA{R: 92, G: 164, B: 196, A: 255})
}

// drawTree paints a green tree. | drawTree 绘制绿树。
func drawTree(c *canvas, cx, cy, size int) {
	p := newIconPen(c, cx, cy, size)
	p.rect(45, 55, 10, 29, color.RGBA{R: 120, G: 82, B: 48, A: 255})
	p.circle(50, 44, 24, color.RGBA{R: 64, G: 148, B: 76, A: 255})
	p.circle(36, 52, 14, color.RGBA{R: 78, G: 166, B: 88, A: 255})
	p.circle(64, 52, 14, color.RGBA{R: 78, G: 166, B: 88, A: 255})
}

// drawHouse paints a house. | drawHouse 绘制房子。
func drawHouse(c *canvas, cx, cy, size int) {
	p := newIconPen(c, cx, cy, size)
	p.rect(28, 49, 44, 32, color.RGBA{R: 234, G: 214, B: 172, A: 255})
	p.polygon(p.std([2]float64{20, 50}, [2]float64{50, 22}, [2]float64{80, 50}), color.RGBA{R: 196, G: 82, B: 66, A: 255})
	p.rect(44, 61, 12, 20, color.RGBA{R: 110, G: 78, B: 52, A: 255})
	p.rect(33, 55, 7, 7, color.RGBA{R: 120, G: 180, B: 220, A: 255})
	p.rect(62, 55, 7, 7, color.RGBA{R: 120, G: 180, B: 220, A: 255})
}

// drawBall paints a striped ball. | drawBall 绘制条纹球。
func drawBall(c *canvas, cx, cy, size int) {
	p := newIconPen(c, cx, cy, size)
	p.circle(50, 52, 27, color.RGBA{R: 240, G: 110, B: 92, A: 255})
	p.line(28, 52, 72, 52, 8, color.RGBA{R: 250, G: 250, B: 246, A: 255})
	p.line(50, 25, 50, 79, 8, color.RGBA{R: 250, G: 250, B: 246, A: 255})
}

// drawGift paints a gift box. | drawGift 绘制礼物盒。
func drawGift(c *canvas, cx, cy, size int) {
	p := newIconPen(c, cx, cy, size)
	p.rect(23, 42, 54, 42, color.RGBA{R: 208, G: 90, B: 102, A: 255})
	p.rect(23, 42, 54, 12, color.RGBA{R: 232, G: 132, B: 140, A: 255})
	p.rect(46, 42, 8, 42, color.RGBA{R: 250, G: 212, B: 88, A: 255})
	p.polygon(p.std([2]float64{42, 42}, [2]float64{50, 24}, [2]float64{58, 42}), color.RGBA{R: 250, G: 212, B: 88, A: 255})
	p.polygon(p.std([2]float64{58, 42}, [2]float64{66, 24}, [2]float64{70, 42}), color.RGBA{R: 250, G: 212, B: 88, A: 255})
}
