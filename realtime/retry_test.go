package realtime

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// flakyBackend fails Publish until healthy is set and records successful
// publishes. | flakyBackend 在 healthy 置位前让 Publish 失败，并记录成功发布的消息。
type flakyBackend struct {
	mu      sync.Mutex
	healthy bool
	pubs    []Message
	err     error
}

func (b *flakyBackend) Publish(_ context.Context, msg Message) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.healthy {
		if b.err == nil {
			b.err = errors.New("backend down | 后端不可用")
		}
		return b.err
	}
	b.pubs = append(b.pubs, msg)
	return nil
}

func (b *flakyBackend) Subscribe(context.Context, string) (<-chan Message, func(), error) {
	return make(chan Message), func() {}, nil
}

func (b *flakyBackend) Close() error { return nil }

func (b *flakyBackend) setHealthy(v bool) {
	b.mu.Lock()
	b.healthy = v
	b.mu.Unlock()
}

func (b *flakyBackend) published() []Message {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Message(nil), b.pubs...)
}

// captureQueue records messages handed to the durable retry queue. | captureQueue
// 记录交给持久重试队列的消息。
type captureQueue struct {
	mu   sync.Mutex
	msgs []Message
	err  error
}

func (q *captureQueue) Enqueue(_ context.Context, msg Message) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.err != nil {
		return q.err
	}
	q.msgs = append(q.msgs, msg)
	return nil
}

func (q *captureQueue) queued() []Message {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]Message(nil), q.msgs...)
}

// TestPublishQueuesFailedBroadcast proves a failed backend publish still
// delivers locally, becomes durable through the retry queue, and reports
// success only when the queue accepted the message. | TestPublishQueuesFailedBroadcast
// 证明后端发布失败时本地投递仍然发生，消息经重试队列持久化，且只在队列接收后报告成功。
func TestPublishQueuesFailedBroadcast(t *testing.T) {
	backend := &flakyBackend{}
	queue := &captureQueue{}
	hub := NewHub(Options{NodeID: "node-a", Retry: queue})
	defer func() { _ = hub.Close() }()
	hub.Use(backend)

	ch := make(chan string, 4)
	sub, err := hub.Subscribe(context.Background(), "chat:1", func(m Message) error {
		ch <- string(m.Body)
		return nil
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Close()

	if err := hub.Publish(context.Background(), "chat:1", []byte("hello")); err != nil {
		t.Fatalf("Publish with retry queue: %v", err)
	}
	if got := recv(t, ch); got != "hello" {
		t.Fatalf("local delivery = %q, want hello", got)
	}
	queued := queue.queued()
	if len(queued) != 1 {
		t.Fatalf("queued %d messages, want 1", len(queued))
	}
	if queued[0].Topic != "chat:1" || string(queued[0].Body) != "hello" || queued[0].Node != "node-a" || queued[0].ID == "" {
		t.Fatalf("queued message = %+v", queued[0])
	}
	st := hub.Stats()
	if st.Retried != 1 || st.Published != 1 {
		t.Fatalf("stats = %+v, want Retried=1 Published=1", st)
	}

	backend.setHealthy(true)
	if err := hub.PublishRemote(context.Background(), queued[0]); err != nil {
		t.Fatalf("PublishRemote: %v", err)
	}
	pubs := backend.published()
	if len(pubs) != 1 || string(pubs[0].Body) != "hello" {
		t.Fatalf("backend publishes = %+v", pubs)
	}
	expectNothing(t, ch) // PublishRemote must not fan out locally again.
}

// TestPublishReportsQueueFailure proves both the backend error and the queue
// error survive when even the durable fallback fails. | TestPublishReportsQueueFailure
// 证明持久兜底也失败时，后端错误与队列错误都被保留。
func TestPublishReportsQueueFailure(t *testing.T) {
	backend := &flakyBackend{}
	queue := &captureQueue{err: errors.New("queue full | 队列已满")}
	hub := NewHub(Options{NodeID: "node-a", Retry: queue})
	defer func() { _ = hub.Close() }()
	hub.Use(backend)

	err := hub.Publish(context.Background(), "chat:1", []byte("x"))
	if err == nil {
		t.Fatal("expected an error when backend and queue both fail")
	}
	if !errors.Is(err, backend.err) {
		t.Fatalf("error %v does not carry the backend failure", err)
	}
	if !errors.Is(err, queue.err) {
		t.Fatalf("error %v does not carry the queue failure", err)
	}
	if got := hub.Stats().Retried; got != 0 {
		t.Fatalf("Retried = %d, want 0", got)
	}
}

// TestPublishRemoteValidates proves the retry entry point applies the same
// topic and size limits as Publish. | TestPublishRemoteValidates 证明重试入口与
// Publish 施加相同的主题与大小限制。
func TestPublishRemoteValidates(t *testing.T) {
	hub := NewHub(Options{NodeID: "node-a", MaxMessageBytes: 4})
	defer func() { _ = hub.Close() }()
	backend := &flakyBackend{healthy: true}
	hub.Use(backend)

	if err := hub.PublishRemote(context.Background(), Message{Topic: "bad topic", Body: []byte("x")}); !errors.Is(err, ErrInvalidTopic) {
		t.Fatalf("invalid topic error = %v, want ErrInvalidTopic", err)
	}
	if err := hub.PublishRemote(context.Background(), Message{Topic: "t", Body: []byte("toolong")}); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("oversized body error = %v, want ErrMessageTooLarge", err)
	}
	if err := hub.PublishRemote(context.Background(), Message{Topic: "t", Body: []byte("ok")}); err != nil {
		t.Fatalf("PublishRemote: %v", err)
	}
	pubs := backend.published()
	if len(pubs) != 1 || pubs[0].Node != "node-a" || !strings.HasPrefix(pubs[0].ID, "node-a:") {
		t.Fatalf("retried message identity = %+v, want node-a with generated id", pubs)
	}
	if got := hub.Stats().Published; got != 0 {
		t.Fatalf("PublishRemote changed Published: %d", got)
	}
	if err := hub.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := hub.PublishRemote(context.Background(), Message{Topic: "t", Body: []byte("ok")}); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed error = %v, want ErrClosed", err)
	}
}
