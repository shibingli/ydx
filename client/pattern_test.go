package client

import (
	"errors"
	"testing"
)

func TestPatternMatch(t *testing.T) {
	cases := []struct {
		pattern    string
		path       string
		wantParams map[string]string
		want       bool
	}{
		{"/api/user/{id}", "/api/user/42", map[string]string{"id": "42"}, true},
		{"/api/user/:id", "/api/user/42", map[string]string{"id": "42"}, true},
		{"/api/user/:id([0-9]+)", "/api/user/42", map[string]string{"id": "42"}, true},
		{"/api/user/:id([0-9]+)", "/api/user/abc", nil, false},
		{"/api/user/{id:[0-9]+}", "/api/user/7", map[string]string{"id": "7"}, true},
		{"/api/user/{id:[0-9]{2}}", "/api/user/42", map[string]string{"id": "42"}, true},
		{"/api/user/{id:[0-9]{2}}", "/api/user/4", nil, false},
		{"/report/:y-:m-:d.json", "/report/2026-11-18.json", map[string]string{"y": "2026", "m": "11", "d": "18"}, true},
		{"/res/{id}/*.jpg", "/res/9/b.jpg", map[string]string{"id": "9"}, true},
		{"/res/{id}/*.jpg", "/res/9/b.png", nil, false},
		{"/res/{id}/*.jpg", "/res/9/a/b.jpg", nil, false},
		{"/static/*path", "/static/a/b.js", map[string]string{"path": "a/b.js"}, true},
		{"/static/*path", "/static/", map[string]string{"path": ""}, true},
		{"/static/*path", "/static", nil, false},
		{"/a", "/a/", nil, false},
		{"/a/", "/a/", nil, true},
		{"/a/:id", "/a/", nil, false},
		{"/a/\\:b", "/a/:b", nil, true},
		{"/a/\\*b", "/a/*b", nil, true},
		{"/", "/", nil, true},
	}
	for _, tc := range cases {
		p, err := CompilePattern(tc.pattern)
		if err != nil {
			t.Fatalf("%s: %v", tc.pattern, err)
		}
		ps, ok := p.Match(tc.path)
		if ok != tc.want {
			t.Fatalf("%s on %s = %v, want %v", tc.pattern, tc.path, ok, tc.want)
		}
		if !ok {
			continue
		}
		for key, want := range tc.wantParams {
			if got := ps.Get(key); got != want {
				t.Fatalf("%s param %s=%q want %q", tc.pattern, key, got, want)
			}
		}
		if ps.Len() != len(tc.wantParams) {
			t.Fatalf("%s params %v want %v", tc.pattern, ps.Values(), tc.wantParams)
		}
	}
}

func TestCompilePatternErrors(t *testing.T) {
	cases := []struct {
		pattern string
		want    error
	}{
		{"", ErrBadPattern},
		{"a", ErrBadPattern},
		{"/a//b", ErrBadPattern},
		{"/a/:id/:id", ErrDuplicateParam},
		{"/a/:id([0-9]+", ErrBadPattern},
		{"/a/:1", ErrParamName},
		{"/a/*path/b", ErrWildcardPosition},
		{"/a/\\q", ErrEscapeSequence},
		{"/a/\\", ErrDanglingEscape},
	}
	for _, tc := range cases {
		if _, err := CompilePattern(tc.pattern); !errors.Is(err, tc.want) {
			t.Fatalf("%s: got %v want %v", tc.pattern, err, tc.want)
		}
	}
}

func TestExpand(t *testing.T) {
	got, err := Expand("/api/user/{id}", map[string]string{"id": "42"})
	if err != nil || got != "/api/user/42" {
		t.Fatalf("got %q err %v", got, err)
	}
	got, err = Expand("/report/:y-:m-:d.json", map[string]string{"y": "2026", "m": "11", "d": "18"})
	if err != nil || got != "/report/2026-11-18.json" {
		t.Fatalf("got %q err %v", got, err)
	}
	got, err = Expand("/static/*path", map[string]string{"path": "a/b.js"})
	if err != nil || got != "/static/a/b.js" {
		t.Fatalf("got %q err %v", got, err)
	}
	if _, err := Expand("/api/user/{id:[0-9]+}", map[string]string{"id": "x"}); !errors.Is(err, ErrParamValue) {
		t.Fatalf("want ErrParamValue, got %v", err)
	}
	if _, err := Expand("/api/user/{id}", nil); !errors.Is(err, ErrMissingParam) {
		t.Fatalf("want ErrMissingParam, got %v", err)
	}
	if _, err := Expand("/res/*.jpg", map[string]string{"x": "1"}); !errors.Is(err, ErrBadPattern) {
		t.Fatalf("want ErrBadPattern for glob, got %v", err)
	}
}

func TestParamsMethods(t *testing.T) {
	var ps Params
	ps.Append("a", "1")
	ps.Append("b", "2")
	if ps.Len() != 2 || ps.Get("a") != "1" || !ps.Has("b") || ps.Get("missing") != "" {
		t.Fatalf("params %+v", ps)
	}
	ps.Truncate(1)
	if ps.Len() != 1 || ps.Get("b") != "" {
		t.Fatalf("truncate %+v", ps)
	}
	ps.Reset()
	if ps.Len() != 0 {
		t.Fatal("reset failed")
	}
}
