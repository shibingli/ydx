package realtime

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// newRedisPair builds two hubs sharing one Redis instance, as two nodes of a
// deployment would. | newRedisPair 构造两个共享同一个 Redis 实例的 hub，模拟部署中的
// 两个节点。
func newRedisPair(t *testing.T) (*miniredis.Miniredis, *redis.Client, *Hub, *Hub) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	hubA := NewHub(Options{NodeID: "node-a"})
	hubA.Use(NewRedisBackend(client, RedisOptions{}))
	hubB := NewHub(Options{NodeID: "node-b"})
	hubB.Use(NewRedisBackend(client, RedisOptions{}))
	t.Cleanup(func() { _ = hubA.Close(); _ = hubB.Close() })
	return mr, client, hubA, hubB
}

// waitSubscribers waits until the channel has at least want subscribers. |
// waitSubscribers 等待频道至少有 want 个订阅者。
func waitSubscribers(t *testing.T, mr *miniredis.Miniredis, channel string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if mr.PubSubNumSub(channel)[channel] >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("channel %s has %d subscribers, want %d | 频道 %s 只有 %d 个订阅者，期望 %d",
		channel, mr.PubSubNumSub(channel)[channel], want, channel, mr.PubSubNumSub(channel)[channel], want)
}

// TestRedisMultiNodeFanOut proves a publish on one node reaches subscribers on
// the other exactly once, and local subscribers exactly once (the Redis echo is
// filtered). | TestRedisMultiNodeFanOut 证明一个节点上的发布恰好一次到达另一节点的
// 订阅者，本地订阅者也恰好一次（Redis 回声被过滤）。
func TestRedisMultiNodeFanOut(t *testing.T) {
	mr, _, hubA, hubB := newRedisPair(t)
	chA := make(chan string, 8)
	chB := make(chan string, 8)
	subA, err := hubA.Subscribe(context.Background(), "room", func(m Message) error { chA <- string(m.Body); return nil })
	if err != nil {
		t.Fatalf("hubA.Subscribe: %v", err)
	}
	defer subA.Close()
	subB, err := hubB.Subscribe(context.Background(), "room", func(m Message) error { chB <- string(m.Body); return nil })
	if err != nil {
		t.Fatalf("hubB.Subscribe: %v", err)
	}
	defer subB.Close()
	waitSubscribers(t, mr, DefaultChannelPrefix+"room", 2)

	if err := hubA.Publish(context.Background(), "room", []byte("hello")); err != nil {
		t.Fatalf("hubA.Publish: %v", err)
	}
	if got := recv(t, chA); got != "hello" {
		t.Fatalf("node A got %q", got)
	}
	if got := recv(t, chB); got != "hello" {
		t.Fatalf("node B got %q", got)
	}
	expectNothing(t, chA)

	if err := hubB.Publish(context.Background(), "room", []byte("world")); err != nil {
		t.Fatalf("hubB.Publish: %v", err)
	}
	if got := recv(t, chB); got != "world" {
		t.Fatalf("node B got %q", got)
	}
	if got := recv(t, chA); got != "world" {
		t.Fatalf("node A got %q", got)
	}
}

// TestRedisUnsubscribeStopsRemote proves the last local subscriber removes the
// node's Redis subscription. | TestRedisUnsubscribeStopsRemote 证明最后一个本地订阅者
// 离开时会移除该节点的 Redis 订阅。
func TestRedisUnsubscribeStopsRemote(t *testing.T) {
	mr, _, hubA, hubB := newRedisPair(t)
	chA := make(chan string, 8)
	subA, err := hubA.Subscribe(context.Background(), "room", func(m Message) error { chA <- string(m.Body); return nil })
	if err != nil {
		t.Fatalf("hubA.Subscribe: %v", err)
	}
	defer subA.Close()
	chB := make(chan string, 8)
	subB, err := hubB.Subscribe(context.Background(), "room", func(m Message) error { chB <- string(m.Body); return nil })
	if err != nil {
		t.Fatalf("hubB.Subscribe: %v", err)
	}
	waitSubscribers(t, mr, DefaultChannelPrefix+"room", 2)
	subB.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && mr.PubSubNumSub(DefaultChannelPrefix + "room")[DefaultChannelPrefix+"room"] != 1 {
		time.Sleep(5 * time.Millisecond)
	}
	if got := mr.PubSubNumSub(DefaultChannelPrefix + "room")[DefaultChannelPrefix+"room"]; got != 1 {
		t.Fatalf("subscribers after unsubscribe = %d, want 1", got)
	}
	if err := hubA.Publish(context.Background(), "room", []byte("after")); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got := recv(t, chA); got != "after" {
		t.Fatalf("node A got %q", got)
	}
	expectNothing(t, chB)
}

// TestRedisBackendValidation proves publish guards and closed behaviour. |
// TestRedisBackendValidation 证明发布的校验与关闭行为。
func TestRedisBackendValidation(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = client.Close() }()
	b := NewRedisBackend(client, RedisOptions{MaxMessageBytes: 4})
	if err := b.Publish(context.Background(), Message{Topic: "ok", Body: []byte("12345")}); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("oversized publish = %v, want ErrMessageTooLarge", err)
	}
	if err := b.Publish(context.Background(), Message{Topic: "bad topic!", Body: nil}); !errors.Is(err, ErrInvalidTopic) {
		t.Fatalf("bad topic publish = %v, want ErrInvalidTopic", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := b.Publish(context.Background(), Message{Topic: "ok"}); !errors.Is(err, ErrClosed) {
		t.Fatalf("publish after close = %v, want ErrClosed", err)
	}
	if _, _, err := b.Subscribe(context.Background(), "ok"); !errors.Is(err, ErrClosed) {
		t.Fatalf("subscribe after close = %v, want ErrClosed", err)
	}
}

// TestRedisCorruptPayloadIgnored proves a corrupted channel payload is dropped
// without killing the subscription. | TestRedisCorruptPayloadIgnored 证明损坏的频道
// 载荷被丢弃且不会杀死订阅。
func TestRedisCorruptPayloadIgnored(t *testing.T) {
	mr, client, hubA, _ := newRedisPair(t)
	ch := make(chan string, 4)
	sub, err := hubA.Subscribe(context.Background(), "room", func(m Message) error { ch <- string(m.Body); return nil })
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Close()
	waitSubscribers(t, mr, DefaultChannelPrefix+"room", 1)

	if err := client.Publish(context.Background(), DefaultChannelPrefix+"room", []byte{0xff, 0x00}).Err(); err != nil {
		t.Fatalf("publish corrupt: %v", err)
	}
	expectNothing(t, ch)
	if err := hubA.Publish(context.Background(), "room", []byte("alive")); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got := recv(t, ch); got != "alive" {
		t.Fatalf("got %q after corrupt payload", got)
	}
}
