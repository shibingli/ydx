package client

import (
	"testing"
)

func TestMatcherBacktracking(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"/:a-:b", "/x-y-z", true},
		{"/:a-:b.json", "/x-y-z.json", true},
		{"/:a.:b", "/x.y.z", true},
		{"/:a(.*)-:b", "/x-1-y", true},
		{"/:a([0-9]+)-:b", "/x-y", false},
	}
	for _, tc := range cases {
		p, err := CompilePattern(tc.pattern)
		if err != nil {
			t.Fatalf("%s: %v", tc.pattern, err)
		}
		if _, ok := p.Match(tc.path); ok != tc.want {
			t.Fatalf("%s on %s = %v want %v", tc.pattern, tc.path, ok, tc.want)
		}
	}
}

func TestMatcherGlobBacktracking(t *testing.T) {
	p, err := CompilePattern("/files/*.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Match("/files/a.tar.gz"); !ok {
		t.Fatal("expected match")
	}
	if _, ok := p.Match("/files/a.tar.bz2"); ok {
		t.Fatal("unexpected match")
	}
}
