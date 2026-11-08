package challenge

import (
	"context"
	"testing"

	"github.com/shibingli/ydx/json"
)

func TestTextLayoutFitsCanvas(t *testing.T) {
	cases := []struct{ width, height, length int }{
		{320, 200, 4},
		{320, 200, 6},
		{120, 80, 4},
		{120, 80, 6},
	}
	for _, tc := range cases {
		size, _, start, total := textLayout(tc.width, tc.height, tc.length)
		if size < 10 || start < 0 || start+total > tc.width {
			t.Fatalf("layout(%d,%d,%d) size=%d start=%d total=%d", tc.width, tc.height, tc.length, size, start, total)
		}
	}
}

func TestTextProviderClampsLengthToPlanRange(t *testing.T) {
	cases := []struct{ configured, expected int }{{3, 4}, {4, 4}, {6, 6}, {8, 6}}
	for _, tc := range cases {
		provider := newTextProvider(tc.configured)
		generated, err := provider.Generate(context.Background(), GenerateRequest{Width: 320, Height: 200, Locale: "en"})
		if err != nil {
			t.Fatalf("length %d: %v", tc.configured, err)
		}
		var state textState
		if err := json.Unmarshal(generated.Answer, &state); err != nil {
			t.Fatalf("length %d: %v", tc.configured, err)
		}
		if runes := []rune(state.Text); len(runes) != tc.expected {
			t.Fatalf("configured %d produced %d runes, want %d", tc.configured, len(runes), tc.expected)
		}
	}
	for configured, want := range map[int]int{3: 4, 8: 6} {
		_, _, _, total := textLayout(320, 200, configured)
		_, _, _, expectedTotal := textLayout(320, 200, want)
		if total != expectedTotal {
			t.Fatalf("textLayout did not clamp %d to %d: total=%d want=%d", configured, want, total, expectedTotal)
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
