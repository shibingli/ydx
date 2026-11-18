package client

import (
	"testing"
)

func FuzzPatternNoPanic(f *testing.F) {
	f.Add("/api/user/{id}", "/api/user/42")
	f.Add("/res/{id}/*.jpg", "/res/9/b.jpg")
	f.Add("/static/*path", "/static/a/b.js")
	f.Add("/report/:y-:m-:d.json", "/report/2026-11-18.json")
	f.Fuzz(func(t *testing.T, pattern, path string) {
		p, err := CompilePattern(pattern)
		if err != nil {
			return
		}
		_, _ = p.Match(path)
	})
}

func FuzzExpandNoPanic(f *testing.F) {
	f.Add("/api/user/{id}", "42")
	f.Fuzz(func(t *testing.T, pattern, value string) {
		_, _ = Expand(pattern, map[string]string{"id": value, "path": value})
	})
}
