package challenge

import "testing"

func TestTextLayoutFitsCanvas(t *testing.T) {
	cases := []struct{ width, height, length int }{
		{320, 200, 4},
		{320, 200, 8},
		{120, 80, 4},
		{120, 80, 8},
	}
	for _, tc := range cases {
		size, _, start, total := textLayout(tc.width, tc.height, tc.length)
		if size < 10 || start < 0 || start+total > tc.width {
			t.Fatalf("layout(%d,%d,%d) size=%d start=%d total=%d", tc.width, tc.height, tc.length, size, start, total)
		}
	}
}

func TestTextPoolFollowsLocale(t *testing.T) {
	atlas, err := loadGlyphs()
	if err != nil {
		t.Fatal(err)
	}
	allowed := make(map[rune]struct{}, len(atlas.latin)+len(atlas.digits))
	for _, ch := range atlas.latin {
		allowed[ch] = struct{}{}
	}
	for _, ch := range atlas.digits {
		allowed[ch] = struct{}{}
	}
	for _, ch := range textPool(atlas, "en") {
		if _, ok := allowed[ch]; !ok {
			t.Fatalf("English pool contains %q", ch)
		}
	}
	if len(textPool(atlas, "zh-CN")) != len(atlas.runes) {
		t.Fatal("Chinese pool should keep the mixed atlas")
	}
}
