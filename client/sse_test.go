package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestEventReader(t *testing.T) {
	src := "\xef\xbb\xbfid: 1\r\nevent: tick\r\ndata: a\r\ndata: b\r\nretry: 1500\r\n\r\n: ping\n\ndata: c\n\n"
	r := NewEventReader(strings.NewReader(src))
	e, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if e.ID != "1" || e.Name != "tick" || string(e.Data) != "a\nb" || e.Retry != 1500*time.Millisecond {
		t.Fatalf("event %+v", e)
	}
	e, err = r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if string(e.Data) != "c" {
		t.Fatalf("second event %+v", e)
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestEventReaderCRAndIgnoredFields(t *testing.T) {
	src := "data: x\r\rdata: y\r\nid: bad\x00id\r\nretry: abc\r\nunknown: z\r\n\r\n"
	r := NewEventReader(strings.NewReader(src))
	e, err := r.Next()
	if err != nil || string(e.Data) != "x" {
		t.Fatalf("first %+v err %v", e, err)
	}
	e, err = r.Next()
	if err != nil || string(e.Data) != "y" || e.ID != "" || e.Retry != 0 {
		t.Fatalf("second %+v err %v", e, err)
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestEventReaderTooLarge(t *testing.T) {
	src := "data: " + strings.Repeat("x", 32) + "\n\n"
	r := NewEventReader(strings.NewReader(src), WithEventMaxBytes(16))
	if _, err := r.Next(); !errors.Is(err, ErrSSETooLarge) {
		t.Fatalf("want ErrSSETooLarge, got %v", err)
	}
}

func TestStreamReconnectLastEventID(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		if n == 1 {
			fmt.Fprint(w, "id: 7\ndata: one\n\n")
			return
		}
		if r.Header.Get("Last-Event-ID") != "7" {
			t.Errorf("last id %q", r.Header.Get("Last-Event-ID"))
		}
		fmt.Fprint(w, "id: 8\ndata: two\n\n")
	}))
	defer srv.Close()
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := c.OpenStream(context.Background(), mustRequest(t, http.MethodGet, srv.URL, ""),
		WithStreamReconnect(3, time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	e1, err := s.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	e2, err := s.Next(context.Background())
	if err != nil || e1.ID != "7" || e2.ID != "8" {
		t.Fatalf("events %+v %+v err %v", e1, e2, err)
	}
}

func TestStreamRawMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: a\n\n")
	}))
	defer srv.Close()
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := c.OpenStream(context.Background(), mustRequest(t, http.MethodGet, srv.URL, ""))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	raw := s.Raw()
	data, err := io.ReadAll(raw)
	if err != nil || !strings.Contains(string(data), "data: a") {
		t.Fatalf("raw %q err %v", data, err)
	}
	if _, err := s.Next(context.Background()); !errors.Is(err, ErrStreamMode) {
		t.Fatalf("want ErrStreamMode, got %v", err)
	}
}

func TestStreamIdleTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: a\n\n")
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-r.Context().Done()
	}))
	defer srv.Close()
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := c.OpenStream(context.Background(), mustRequest(t, http.MethodGet, srv.URL, ""),
		WithStreamIdleTimeout(20*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Next(context.Background()); !errors.Is(err, ErrSSEIdle) {
		t.Fatalf("want ErrSSEIdle, got %v", err)
	}
}

func TestStreamRejectsNonSSE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.OpenStream(context.Background(), mustRequest(t, http.MethodGet, srv.URL, "")); !errors.Is(err, ErrSSEProtocol) {
		t.Fatalf("want ErrSSEProtocol, got %v", err)
	}
}

func TestStreamClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
	}))
	defer srv.Close()
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := c.OpenStream(context.Background(), mustRequest(t, http.MethodGet, srv.URL, ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Next(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", err)
	}
}
