package client

import (
	"io"
	"strings"
	"testing"
)

func TestPrepareBodyKinds(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		body, getBody, contentType, err := prepareBody(nil)
		if err != nil {
			t.Fatal(err)
		}
		if body != nil || getBody != nil || contentType != "" {
			t.Fatalf("body=%v getBody=%v type=%q", body, getBody != nil, contentType)
		}
	})

	t.Run("bytes", func(t *testing.T) {
		body, getBody, contentType, err := prepareBody([]byte("raw"))
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(body)
		if string(got) != "raw" || getBody == nil || contentType != "" {
			t.Fatalf("got %q getBody=%v type=%q", got, getBody != nil, contentType)
		}
		replay, _ := getBody()
		again, _ := io.ReadAll(replay)
		if string(again) != "raw" {
			t.Fatalf("replay %q", again)
		}
	})

	t.Run("json", func(t *testing.T) {
		body, getBody, contentType, err := prepareBody(map[string]string{"a": "b"})
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(body)
		if string(got) != `{"a":"b"}` || contentType != "application/json" || getBody == nil {
			t.Fatalf("got %q type=%q getBody=%v", got, contentType, getBody != nil)
		}
	})

	t.Run("reader", func(t *testing.T) {
		nonSeekable := struct{ io.Reader }{strings.NewReader("stream")}
		body, getBody, contentType, err := prepareBody(nonSeekable)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(body)
		if string(got) != "stream" || getBody != nil || contentType != "" {
			t.Fatalf("got %q getBody=%v type=%q", got, getBody != nil, contentType)
		}
	})
}
