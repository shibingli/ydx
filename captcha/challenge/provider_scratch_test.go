package challenge

import "testing"

func TestScratchLayoutFitsCanvas(t *testing.T) {
	cases := []struct{ width, height int }{{320, 200}, {120, 80}}
	for _, tc := range cases {
		size, start := scratchLayout(tc.width, tc.height)
		total := 4*size + 3*(size/7)
		if size < 10 || start < 0 || start+total > tc.width {
			t.Fatalf("layout(%d,%d) size=%d start=%d total=%d", tc.width, tc.height, size, start, total)
		}
	}
}
