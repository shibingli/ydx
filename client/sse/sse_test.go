package sse

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestFanoutBroadcastCloseRace(t *testing.T) {
	fanout := NewFanout(Options{Queue: 8})
	sub, err := fanout.Add(httptest.NewRecorder())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_ = fanout.Sink().WriteEvent(context.Background(), client.Event{Data: []byte("x")})
		}
	}()
	for i := 0; i < 100; i++ {
		_ = sub.Close()
	}
	_ = fanout.Close()
	wg.Wait()
}

// blockingWriter is a ResponseWriter without SetWriteDeadline whose Write blocks until released. |
// blockingWriter 是一个不支持 SetWriteDeadline、且 Write 会阻塞到释放的响应写入器。
type blockingWriter struct {
	header  http.Header
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *blockingWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *blockingWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.release
	return len(p), nil
}

func (w *blockingWriter) WriteHeader(int) {}

func (w *blockingWriter) Flush() {}

// TestCloseBoundedWithoutWriteDeadline pins that Close returns even when the ResponseWriter
// cannot be unblocked through SetWriteDeadline, so one stalled subscriber cannot pin the fanout
// forever. | TestCloseBoundedWithoutWriteDeadline 固定：ResponseWriter 无法通过
// SetWriteDeadline 解除阻塞时 Close 仍会返回，一个停滞订阅者不能永久拖住扇出。
func TestCloseBoundedWithoutWriteDeadline(t *testing.T) {
	fanout := NewFanout(Options{Queue: 1, WriteTimeout: 100 * time.Millisecond})
	defer fanout.Close()
	writer := &blockingWriter{started: make(chan struct{}), release: make(chan struct{})}
	sub, err := fanout.Add(writer)
	if err != nil {
		t.Fatal(err)
	}
	if err := fanout.Sink().WriteEvent(context.Background(), client.Event{Data: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-writer.started:
	case <-time.After(2 * time.Second):
		t.Fatal("subscriber never started writing | 订阅者未开始写入")
	}
	start := time.Now()
	if err := sub.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Close blocked for %v | Close 阻塞过久", elapsed)
	}
	close(writer.release)
	sub.wg.Wait()
}
