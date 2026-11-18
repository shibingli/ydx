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
