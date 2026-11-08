package challenge

import (
	"context"
	"testing"

	"github.com/shibingli/ydx/json"
)

func TestScratchLayoutFitsCanvas(t *testing.T) {
	cases := []struct{ width, height int }{{320, 200}, {120, 80}}
	for _, tc := range cases {
		size, start := scratchLayout(tc.width, tc.height)
		total := scratchTotalWidth(size)
		if size < 10 || start < 0 || start+total > tc.width {
			t.Fatalf("layout(%d,%d) size=%d start=%d total=%d", tc.width, tc.height, size, start, total)
		}
	}
}

func TestScratchCoverageRejectsUnscratchedAnswer(t *testing.T) {
	provider, record, state := scratchTestChallenge(t)
	result, err := provider.Verify(context.Background(), record, Answer{Text: state.Text, Track: scratchCornerTrack()})
	if err != nil {
		t.Fatal(err)
	}
	if result.Passed {
		t.Fatal("correct text must not pass before the glyph band is covered")
	}
	if !scratchHasReason(result.Reasons, "scratch_coverage_low") {
		t.Fatalf("expected coverage rejection, got %v", result.Reasons)
	}
}

func TestScratchCoverageAcceptsRevealedAnswer(t *testing.T) {
	provider, record, state := scratchTestChallenge(t)
	track := scratchBandTrack(state.Width, state.Height)
	ratio := state.scratchCoverage(track)
	if ratio < scratchCoverageThreshold {
		t.Fatalf("test track coverage %.3f is below threshold %.2f", ratio, scratchCoverageThreshold)
	}
	result, err := provider.Verify(context.Background(), record, Answer{Text: state.Text, Track: track})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Passed {
		t.Fatalf("revealed answer rejected: %v", result.Reasons)
	}
}

func TestScratchCoverageBands(t *testing.T) {
	state := scratchState{Width: 320, Height: 200}
	if ratio := state.scratchCoverage(scratchCornerTrack()); ratio >= scratchCoverageThreshold {
		t.Fatalf("corner track coverage %.3f should stay below threshold", ratio)
	}
	if _, _, width, height, ok := state.scratchBand(); !ok || width <= 0 || height <= 0 {
		t.Fatalf("invalid glyph band: width=%d height=%d ok=%v", width, height, ok)
	}
}

func scratchTestChallenge(t *testing.T) (*scratchProvider, *Record, scratchState) {
	t.Helper()
	provider := newScratchProvider()
	generated, err := provider.Generate(context.Background(), GenerateRequest{Width: 320, Height: 200, Locale: "en"})
	if err != nil {
		t.Fatal(err)
	}
	var state scratchState
	if err := json.Unmarshal(generated.Answer, &state); err != nil {
		t.Fatal(err)
	}
	if state.Text == "" || state.Width != 320 || state.Height != 200 {
		t.Fatalf("unexpected scratch state: %+v", state)
	}
	return provider, &Record{Type: TypeScratch, Answer: generated.Answer}, state
}

// scratchCornerTrack stays far away from the centred glyph band. | scratchCornerTrack 远离居中的字符区域。
func scratchCornerTrack() Track {
	points := make([]TrackPoint, 0, 12)
	for i := 0; i < 12; i++ {
		points = append(points, TrackPoint{T: int64(i * 30), X: i, Y: i / 2, Kind: "scratch"})
	}
	return Track{StartedAt: 0, EndedAt: 330, Points: points}
}

// scratchBandTrack scribbles across every row of the glyph band. | scratchBandTrack 在字符区域的每一行来回刮擦。
func scratchBandTrack(width, height int) Track {
	size, start := scratchLayout(width, height)
	total := scratchTotalWidth(size)
	step := maxInt(4, size/4)
	top := height/2 - size/2
	rows := []int{top + size/6, height / 2, top + size - size/6}
	points := make([]TrackPoint, 0, 64)
	var elapsed int64
	for rowIndex, y := range rows {
		if rowIndex%2 == 0 {
			for x := start; x <= start+total; x += step {
				points = append(points, TrackPoint{T: elapsed, X: x, Y: y, Kind: "scratch"})
				elapsed += 20
			}
			continue
		}
		for x := start + total; x >= start; x -= step {
			points = append(points, TrackPoint{T: elapsed, X: x, Y: y, Kind: "scratch"})
			elapsed += 20
		}
	}
	return Track{StartedAt: 0, EndedAt: elapsed - 20, Points: points}
}

func scratchHasReason(reasons []string, target string) bool {
	for _, reason := range reasons {
		if reason == target {
			return true
		}
	}
	return false
}
