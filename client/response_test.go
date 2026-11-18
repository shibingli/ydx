package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResponseHelpers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":42}`))
	}))
	defer srv.Close()

	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ Value int }
	if err := resp.JSON(&out); err != nil {
		t.Fatal(err)
	}
	if out.Value != 42 {
		t.Fatalf("value %d", out.Value)
	}
	if _, err := resp.Bytes(); !errors.Is(err, ErrBodyConsumed) {
		t.Fatalf("want ErrBodyConsumed, got %v", err)
	}
}

func TestResponseBytesLimit(t *testing.T) {
	resp := &Response{Response: &http.Response{Body: io.NopCloser(strings.NewReader("12345"))}}
	if _, err := resp.BytesLimit(3); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("want ErrResponseTooLarge, got %v", err)
	}

	resp = &Response{Response: &http.Response{Body: io.NopCloser(strings.NewReader("12345"))}}
	b, err := resp.BytesLimit(5)
	if err != nil || string(b) != "12345" {
		t.Fatalf("got %q err %v", b, err)
	}
}

func TestResponseSaveToAndDiscard(t *testing.T) {
	resp := &Response{Response: &http.Response{Body: io.NopCloser(strings.NewReader("streamed"))}}
	var buf bytes.Buffer
	n, err := resp.SaveTo(&buf)
	if err != nil || n != int64(len("streamed")) || buf.String() != "streamed" {
		t.Fatalf("n=%d err=%v body=%q", n, err, buf.String())
	}

	resp = &Response{Response: &http.Response{Body: io.NopCloser(strings.NewReader("ignored"))}}
	if err := resp.Discard(); err != nil {
		t.Fatal(err)
	}
	if resp.Body != nil {
		t.Fatal("body not released")
	}
}
