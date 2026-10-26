package challenge

import (
	"context"
	"testing"
)

func TestClickLayoutKeepsHitRegionsDistinct(t *testing.T) {
	providers := []Provider{newClickTextProvider(), newClickIconProvider(), newSemanticProvider()}
	for _, provider := range providers {
		generated, err := provider.Generate(context.Background(), GenerateRequest{Width: 120, Height: 80, Locale: "en"})
		if err != nil {
			t.Fatalf("%s generate: %v", provider.Type(), err)
		}
		var state clickState
		if err := decodeAnswer(generated.Answer, &state); err != nil {
			t.Fatalf("%s decode: %v", provider.Type(), err)
		}
		if state.Tolerance < 6 {
			t.Fatalf("%s tolerance = %d", provider.Type(), state.Tolerance)
		}
		for i, point := range state.Points {
			if point.X < 0 || point.X >= 120 || point.Y < 0 || point.Y >= 80 {
				t.Fatalf("%s point outside canvas: %+v", provider.Type(), point)
			}
			for j := i + 1; j < len(state.Points); j++ {
				if d := distancePoint(point, state.Points[j]); d <= float64(2*state.Tolerance) {
					t.Fatalf("%s targets %d,%d overlap: distance %.1f tolerance %d", provider.Type(), i, j, d, state.Tolerance)
				}
			}
		}
	}
}
