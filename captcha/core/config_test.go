package core

import (
	"errors"
	"testing"
)

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
