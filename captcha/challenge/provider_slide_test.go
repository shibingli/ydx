package challenge

import (
	"context"
	"testing"
)

func TestSlideRequiresInteractionTrack(t *testing.T) {
	provider := newSlideProvider()
	generated, err := provider.Generate(context.Background(), GenerateRequest{Width: 320, Height: 200, Locale: "en"})
	if err != nil {
		t.Fatal(err)
	}
	var state slideState
	if err := decodeAnswer(generated.Answer, &state); err != nil {
		t.Fatal(err)
	}
	x, y := state.X, state.Y
	record := &Record{Answer: generated.Answer}
	if result, err := provider.Verify(context.Background(), record, Answer{Offset: &x, OffsetY: &y}); err != nil || result.Passed {
		t.Fatalf("empty track passed: %+v %v", result, err)
	}
	short := Answer{Offset: &x, OffsetY: &y, Track: Track{
		StartedAt: 0,
		EndedAt:   100,
		Points: []TrackPoint{
			{T: 0, X: 1, Y: 1},
			{T: 50, X: 2, Y: 2},
			{T: 100, X: 3, Y: 3},
		},
	}}
	if result, err := provider.Verify(context.Background(), record, short); err != nil || result.Passed {
		t.Fatalf("short track passed: %+v %v", result, err)
	}
	good := Answer{Offset: &x, OffsetY: &y, Track: goodTrack()}
	if result, err := provider.Verify(context.Background(), record, good); err != nil || !result.Passed {
		t.Fatalf("good track rejected: %+v %v", result, err)
	}
}

func goodTrack() Track {
	points := make([]TrackPoint, 0, 12)
	for i := 0; i < 12; i++ {
		points = append(points, TrackPoint{T: int64(i * 30), X: 40 + i*5, Y: 80 + i*2, Kind: "move"})
	}
	return Track{StartedAt: 0, EndedAt: 330, Points: points}
}
