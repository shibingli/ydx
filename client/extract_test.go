package client

import (
	"net/http"
	"testing"
)

func TestExtractors(t *testing.T) {
	vars := NewVars()
	body := []byte(`{"data":{"token":"T","items":[{"id":1},{"id":2}]},"ok":true}`)
	ctx := extractContext{
		Status: http.StatusOK,
		Header: http.Header{"X-Id": {"7"}},
		Body:   body,
	}
	cases := []Extractor{
		ExtractJSON("token", "data.token"),
		ExtractJSON("id", "data.items[1].id"),
		ExtractJSON("ok", "ok"),
		ExtractHeader("header", "X-Id"),
		ExtractStatus("status"),
		ExtractRegexp("num", `"id":(\d+)`, 1),
		ExtractBody("body"),
	}
	for _, extractor := range cases {
		if err := extractor.apply(ctx, vars); err != nil {
			t.Fatal(err)
		}
	}
	if vars.String("token") != "T" || vars.String("id") != "2" || vars.String("ok") != "true" {
		t.Fatalf("json vars token=%q id=%q ok=%q", vars.String("token"), vars.String("id"), vars.String("ok"))
	}
	if vars.String("header") != "7" || vars.String("status") != "200" || vars.String("num") != "1" {
		t.Fatalf("header=%q status=%q num=%q", vars.String("header"), vars.String("status"), vars.String("num"))
	}
	if vars.String("body") != string(body) {
		t.Fatalf("body %q", vars.String("body"))
	}
}

func TestExtractJSONMissing(t *testing.T) {
	vars := NewVars()
	ctx := extractContext{Status: 200, Header: make(http.Header), Body: []byte(`{"a":1}`)}
	if err := ExtractJSON("x", "a.b").apply(ctx, vars); err == nil {
		t.Fatal("expected error")
	}
	if err := ExtractFunc("fn", func(*Response, *Vars) error { return nil }).apply(ctx, vars); err != nil {
		t.Fatal(err)
	}
}
