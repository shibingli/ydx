package sse

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shibingli/ydx/client"
)

func TestFanoutBroadcast(t *testing.T) {
	fanout := NewFanout(Options{Queue: 8})
	defer fanout.Close()

	rec1 := httptest.NewRecorder()
	rec2 := httptest.NewRecorder()
	sub1, err := fanout.Add(rec1)
	if err != nil {
		t.Fatal(err)
	}
	sub2, err := fanout.Add(rec2)
	if err != nil {
		t.Fatal(err)
	}
	if err := fanout.Sink().WriteEvent(context.Background(), client.Event{
		ID:   "1",
		Name: "tick",
		Data: []byte("hi"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := sub1.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sub2.Close(); err != nil {
		t.Fatal(err)
	}
	for name, recorder := range map[string]*httptest.ResponseRecorder{"one": rec1, "two": rec2} {
		body := recorder.Body.String()
		if !strings.Contains(body, "event: tick") || !strings.Contains(body, "data: hi") {
			t.Fatalf("%s body %q", name, body)
		}
	}
}

func TestFanoutClose(t *testing.T) {
	fanout := NewFanout(Options{})
	if err := fanout.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fanout.Sink().WriteEvent(context.Background(), client.Event{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", err)
	}
	if _, err := fanout.Add(httptest.NewRecorder()); !errors.Is(err, ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", err)
	}
}
