package client

import (
	"testing"
)

func TestVars(t *testing.T) {
	vars := NewVars()
	vars.Set("s", "x")
	vars.Set("i", int64(42))
	vars.Set("b", true)
	vars.Set("f", 1.5)
	vars.Set("obj", map[string]any{"value": 7})

	if vars.String("s") != "x" || vars.String("i") != "42" || vars.String("missing") != "" {
		t.Fatalf("strings %q %q", vars.String("s"), vars.String("i"))
	}
	if value, ok := vars.Int64("i"); !ok || value != 42 {
		t.Fatalf("int64 %d %v", value, ok)
	}
	if value, ok := vars.Bool("b"); !ok || !value {
		t.Fatalf("bool %v %v", value, ok)
	}
	var out struct {
		Value int `json:"value"`
	}
	if err := vars.JSON("obj", &out); err != nil || out.Value != 7 {
		t.Fatalf("json %+v err %v", out, err)
	}

	clone := vars.Clone()
	clone.Set("s", "y")
	if vars.String("s") != "x" || clone.String("s") != "y" {
		t.Fatalf("clone isolation %q %q", vars.String("s"), clone.String("s"))
	}
}
