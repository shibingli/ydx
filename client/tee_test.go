package client

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTeeSlowSinkDrops(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 256<<10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	var received atomic.Int32
	sink := SinkFunc(func(ctx context.Context, chunk []byte) error {
		time.Sleep(5 * time.Millisecond)
		received.Add(1)
		return nil
	})
	c, err := New(WithRule(Rule{
		Name:    "r",
		Pattern: "/x",
		Mirror: &MirrorPolicy{
			Mode:       MirrorTee,
			TeeSinks:   []Sink{sink},
			TeeQueue:   1,
			TeeDrop:    DropNewest,
			TeeTimeout: time.Millisecond,
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	resp, err := c.Get(context.Background(), srv.URL+"/x")
	if err != nil {
		t.Fatal(err)
	}
	body, err := resp.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != len(payload) {
		t.Fatalf("primary body length %d", len(body))
	}
	if c.engine.mirrorDrops.Load() == 0 {
		t.Fatalf("expected tee drops, received=%d", received.Load())
	}
}

func TestTeeCloseBounded(t *testing.T) {
	var drops atomic.Uint64
	sink := SinkFunc(func(context.Context, []byte) error {
		time.Sleep(50 * time.Millisecond)
		return nil
	})
	worker := newTeeSinkWorker(sink, 64, DropNewest, 10*time.Millisecond, &drops)
	for i := 0; i < 50; i++ {
		worker.enqueue([]byte("x"))
	}
	start := time.Now()
	worker.Close()
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Close blocked for %v", elapsed)
	}
}

func TestTeeSinkReceives(t *testing.T) {
	payload := []byte("tee-payload")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	var mu sync.Mutex
	var collected []byte
	sink := SinkFunc(func(ctx context.Context, chunk []byte) error {
		mu.Lock()
		collected = append(collected, chunk...)
		mu.Unlock()
		return nil
	})
	c, err := New(WithRule(Rule{
		Name:    "r",
		Pattern: "/x",
		Mirror: &MirrorPolicy{
			Mode:     MirrorTee,
			TeeSinks: []Sink{sink},
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	resp, err := c.Get(context.Background(), srv.URL+"/x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resp.Bytes(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !bytes.Equal(collected, payload) {
		t.Fatalf("sink collected %q", collected)
	}
}

func TestGlobalTeeSinkReceives(t *testing.T) {
	payload := []byte("global-tee")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()
	var mu sync.Mutex
	var collected []byte
	sink := SinkFunc(func(ctx context.Context, chunk []byte) error {
		mu.Lock()
		collected = append(collected, chunk...)
		mu.Unlock()
		return nil
	})
	c, err := New(WithMirror(MirrorPolicy{Mode: MirrorTee, TeeSinks: []Sink{sink}}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), srv.URL+"/x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resp.Bytes(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !bytes.Equal(collected, payload) {
		t.Fatalf("sink collected %q", collected)
	}
}

func TestTeeSinkPanicIsIsolated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("payload"))
	}))
	defer srv.Close()
	sink := SinkFunc(func(context.Context, []byte) error { panic("boom") })
	c, err := New(WithMirror(MirrorPolicy{Mode: MirrorTee, TeeSinks: []Sink{sink}}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), srv.URL+"/x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resp.Bytes(); err != nil {
		t.Fatal(err)
	}
	if c.engine.mirrorDrops.Load() == 0 {
		t.Fatal("expected drop after sink panic")
	}
}
