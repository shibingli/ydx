package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type xmlPayload struct {
	Value string `xml:"value"`
}

func TestXMLRequestBody(t *testing.T) {
	var gotType, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
	}))
	defer srv.Close()

	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Post(context.Background(), srv.URL, XML(xmlPayload{Value: "x"})); err != nil {
		t.Fatal(err)
	}
	if gotType != "application/xml" || !strings.Contains(gotBody, "<value>x</value>") {
		t.Fatalf("type=%q body=%q", gotType, gotBody)
	}
}

func TestResponseXML(t *testing.T) {
	resp := &Response{Response: &http.Response{Body: io.NopCloser(strings.NewReader(`<xmlPayload><value>7</value></xmlPayload>`))}}
	var out xmlPayload
	if err := resp.XML(&out); err != nil {
		t.Fatal(err)
	}
	if out.Value != "7" {
		t.Fatalf("value %q", out.Value)
	}
}
