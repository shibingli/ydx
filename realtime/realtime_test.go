package realtime

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// recv waits for one message on ch. | recv 等待 ch 上的一条消息。
func recv(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a message | 等待消息超时")
		return ""
	}
}

// expectNothing asserts that no message arrives within a short window. | expectNothing
// 断言短时间内没有消息到达。
func expectNothing(t *testing.T, ch <-chan string) {
	t.Helper()
	select {
	case v := <-ch:
		t.Fatalf("unexpected message %q", v)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestLocalFanOut proves single-node mode fans one publish out to every
// subscriber in order, and only to the matching topic. | TestLocalFanOut 证明单机
// 模式把一次发布按顺序扇出给每个订阅者，且只送达匹配的主题。
func TestLocalFanOut(t *testing.T) {
	hub := NewHub(Options{NodeID: "node-a"})
	defer func() { _ = hub.Close() }()

	ch1 := make(chan string, 8)
	ch2 := make(chan string, 8)
	other := make(chan string, 8)
	sub1, err := hub.Subscribe(context.Background(), "chat:1", func(m Message) error { ch1 <- string(m.Body); return nil })
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub1.Close()
	sub2, err := hub.Subscribe(context.Background(), "chat:1", func(m Message) error { ch2 <- string(m.Body); return nil })
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub2.Close()
	sub3, err := hub.Subscribe(context.Background(), "chat:2", func(m Message) error { other <- string(m.Body); return nil })
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub3.Close()

	for _, msg := range []string{"a", "b", "c"} {
		if err := hub.Publish(context.Background(), "chat:1", []byte(msg)); err != nil {
			t.Fatalf("Publish: %v", err)
		}
	}
	for _, want := range []string{"a", "b", "c"} {
		if got := recv(t, ch1); got != want {
			t.Fatalf("sub1 got %q, want %q", got, want)
		}
		if got := recv(t, ch2); got != want {
			t.Fatalf("sub2 got %q, want %q", got, want)
		}
	}
	expectNothing(t, other)
	if got := hub.Stats().Published; got != 3 {
		t.Fatalf("Published = %d, want 3", got)
	}
}

// TestSlowConsumerDrop proves a blocked sink never stalls the publisher and the
// excess messages are counted. | TestSlowConsumerDrop 证明阻塞的 sink 不会拖住发布方，
// 且多余消息被计数。
func TestSlowConsumerDrop(t *testing.T) {
	hub := NewHub(Options{NodeID: "node-a", QueueSize: 1})
	defer func() { _ = hub.Close() }()

	block := make(chan struct{})
	sub, err := hub.Subscribe(context.Background(), "slow", func(Message) error {
		<-block
		return nil
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer func() { close(block); sub.Close() }()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			_ = hub.Publish(context.Background(), "slow", []byte("x"))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a slow consumer | Publish 被慢消费者阻塞")
	}
	if got := hub.Stats().Dropped; got == 0 {
		t.Fatal("Dropped = 0, want > 0")
	}
}

// TestSlowConsumerClose proves the close policy tears the subscription down
// instead of dropping silently. | TestSlowConsumerClose 证明 close 策略会拆除订阅，而不是
// 静默丢弃。
func TestSlowConsumerClose(t *testing.T) {
	hub := NewHub(Options{NodeID: "node-a", QueueSize: 1, SlowPolicy: SlowClose})
	defer func() { _ = hub.Close() }()

	block := make(chan struct{})
	defer close(block)
	sub, err := hub.Subscribe(context.Background(), "slow", func(Message) error {
		<-block
		return nil
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	// The first publish enters the sink; the second fills the queue; the third
	// triggers the close policy. | 第一条进入 sink；第二条填满队列；第三条触发关闭策略。
	for i := 0; i < 3; i++ {
		_ = hub.Publish(context.Background(), "slow", []byte("x"))
	}
	deadline := time.Now().Add(2 * time.Second)
	for hub.Stats().ClosedSlow == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := hub.Stats().ClosedSlow; got == 0 {
		t.Fatal("ClosedSlow = 0, want > 0")
	}
	select {
	case <-sub.done:
	case <-time.After(time.Second):
		t.Fatal("subscription was not closed | 订阅未被关闭")
	}
}

// TestSubscribeAuthorize proves the security hook can deny a topic. |
// TestSubscribeAuthorize 证明安全钩子可以拒绝主题。
func TestSubscribeAuthorize(t *testing.T) {
	hub := NewHub(Options{
		NodeID: "node-a",
		Authorize: func(_ context.Context, topic string) error {
			if topic == "secret" {
				return errors.New("denied")
			}
			return nil
		},
	})
	defer func() { _ = hub.Close() }()
	if _, err := hub.Subscribe(context.Background(), "secret", func(Message) error { return nil }); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Subscribe(secret) error = %v, want ErrUnauthorized", err)
	}
	sub, err := hub.Subscribe(context.Background(), "public", func(Message) error { return nil })
	if err != nil {
		t.Fatalf("Subscribe(public): %v", err)
	}
	sub.Close()
}

// TestPublishValidation proves topic and size validation. | TestPublishValidation
// 证明主题与大小校验。
func TestPublishValidation(t *testing.T) {
	hub := NewHub(Options{NodeID: "node-a", MaxMessageBytes: 4})
	defer func() { _ = hub.Close() }()
	if err := hub.Publish(context.Background(), "bad topic!", []byte("x")); !errors.Is(err, ErrInvalidTopic) {
		t.Fatalf("invalid topic error = %v, want ErrInvalidTopic", err)
	}
	if err := hub.Publish(context.Background(), "ok", []byte("12345")); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("oversized message error = %v, want ErrMessageTooLarge", err)
	}
}

// TestCloseStopsSubscriptions proves Hub.Close ends every subscription and
// rejects later work. | TestCloseStopsSubscriptions 证明 Hub.Close 结束全部订阅并拒绝
// 后续操作。
func TestCloseStopsSubscriptions(t *testing.T) {
	hub := NewHub(Options{NodeID: "node-a"})
	ch := make(chan struct{})
	sub, err := hub.Subscribe(context.Background(), "t", func(Message) error { return nil })
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	go func() {
		<-sub.done
		close(ch)
	}()
	if err := hub.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("subscription survived Close | 订阅在关闭后仍存活")
	}
	if err := hub.Publish(context.Background(), "t", nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("Publish after Close = %v, want ErrClosed", err)
	}
	if _, err := hub.Subscribe(context.Background(), "t", func(Message) error { return nil }); !errors.Is(err, ErrClosed) {
		t.Fatalf("Subscribe after Close = %v, want ErrClosed", err)
	}
}

// TestMessageCodec pins the Redis payload format. | TestMessageCodec 固定 Redis 载荷格式。
func TestMessageCodec(t *testing.T) {
	msg := Message{Topic: "t", Node: "node-a", ID: "node-a:7", Body: []byte("hello")}
	raw := encodeMessage(msg)
	got, err := decodeMessage("t", raw, 1<<10)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Node != msg.Node || got.ID != msg.ID || string(got.Body) != "hello" {
		t.Fatalf("decoded = %+v", got)
	}
	if _, err := decodeMessage("t", []byte{2, 0, 0}, 16); !errors.Is(err, ErrCorruptMessage) {
		t.Fatalf("bad version error = %v, want ErrCorruptMessage", err)
	}
	if _, err := decodeMessage("t", raw[:4], 16); !errors.Is(err, ErrCorruptMessage) {
		t.Fatalf("truncated error = %v, want ErrCorruptMessage", err)
	}
	big := Message{Node: "n", ID: "i", Body: make([]byte, 20)}
	if _, err := decodeMessage("t", encodeMessage(big), 4); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("oversized error = %v, want ErrMessageTooLarge", err)
	}
}

// TestParseSlowPolicy pins the configuration mapping. | TestParseSlowPolicy 固定配置映射。
func TestParseSlowPolicy(t *testing.T) {
	for in, want := range map[string]SlowPolicy{"": SlowDrop, "drop": SlowDrop, " CLOSE ": SlowClose} {
		got, err := ParseSlowPolicy(in)
		if err != nil || got != want {
			t.Fatalf("ParseSlowPolicy(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseSlowPolicy("explode"); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("ParseSlowPolicy(explode) error = %v, want ErrInvalidOptions", err)
	}
}

// TestSubscriptionCloseIsIdempotent pins double-close safety. | TestSubscriptionCloseIsIdempotent
// 固定重复关闭的安全性。
func TestSubscriptionCloseIsIdempotent(t *testing.T) {
	hub := NewHub(Options{NodeID: "node-a"})
	defer func() { _ = hub.Close() }()
	sub, err := hub.Subscribe(context.Background(), "t", func(Message) error { return nil })
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); sub.Close() }()
	}
	wg.Wait()
}
