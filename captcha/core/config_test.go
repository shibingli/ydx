package core

import (
	"errors"
	"testing"
)

func TestTextLengthRange(t *testing.T) {
	for _, length := range []int{3, 7, 8} {
		o := Options{}.Defaults()
		o.TextLength = length
		if err := o.Validate(); !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("text length %d should be rejected, got %v", length, err)
		}
	}
	for _, length := range []int{4, 5, 6} {
		o := Options{}.Defaults()
		o.TextLength = length
		if err := o.Validate(); err != nil {
			t.Fatalf("text length %d should be accepted: %v", length, err)
		}
	}
}

func TestRejectsEmptyTypesAndInvalidPoWThreshold(t *testing.T) {
	o := Options{}.Defaults()
	o.Types = []Type{}
	if err := o.Validate(); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("empty types: %v", err)
	}
	o = Options{}.Defaults()
	o.PoW = PoWOptions{Mode: PoWAdaptive, Difficulty: 16, MaxDifficulty: 22, Threshold: 500}
	if err := o.Validate(); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("threshold: %v", err)
	}
}
