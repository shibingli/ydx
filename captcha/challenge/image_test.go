package challenge

import (
	"image"
	"image/color"
	"math"
	"testing"
)

func TestRotateImageTurnsCounterClockwise(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 101, 101))
	for y := 40; y < 60; y++ {
		for x := 90; x < 101; x++ {
			src.SetRGBA(x, y, color.RGBA{R: 255, A: 255})
		}
	}
	out := rotateImage(src, math.Pi/2, color.RGBA{}, &rng{})
	var sumX, sumY, count int
	for y := 0; y < 101; y++ {
		for x := 0; x < 101; x++ {
			r, _, _, _ := out.img.At(x, y).RGBA()
			if r != 0xffff {
				continue
			}
			sumX += x
			sumY += y
			count++
		}
	}
	if count == 0 {
		t.Fatal("marker disappeared")
	}
	cx := float64(sumX) / float64(count)
	cy := float64(sumY) / float64(count)
	// A right-side marker rotated counter-clockwise lands near the top. | 右侧标记逆时针旋转后落在顶部附近。
	if cy > 25 || cx < 40 || cx > 60 {
		t.Fatalf("marker centroid = (%.1f, %.1f)", cx, cy)
	}
}
