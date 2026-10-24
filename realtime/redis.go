package realtime

import (
	"context"
	"encoding/binary"
	"sync"
	"sync/atomic"

	"github.com/redis/go-redis/v9"

	"github.com/shibingli/ydx/errs"
)

// ErrBackend reports a Redis failure. | ErrBackend 表示 Redis 失败。
var ErrBackend = errs.New("realtime: redis backend failed | realtime：Redis 后端失败")

// ErrCorruptMessage reports a backend payload that does not decode. | ErrCorruptMessage
// 表示后端载荷无法解码。
var ErrCorruptMessage = errs.New("realtime: corrupt backend message | realtime：后端消息损坏")

// RedisOptions configures the Redis backend. | RedisOptions 配置 Redis 后端。
type RedisOptions struct {
	// ChannelPrefix namespaces channels; empty takes DefaultChannelPrefix. |
	// ChannelPrefix 为频道加命名空间；空值取 DefaultChannelPrefix。
	ChannelPrefix string
	// QueueSize bounds the per-topic delivery buffer before Redis reads are
	// throttled; <=0 takes DefaultQueueSize. | QueueSize 限制每个主题的投递缓冲；
	// <=0 取 DefaultQueueSize。
	QueueSize int
	// MaxMessageBytes bounds one remote payload; <=0 takes
	// DefaultMaxMessageBytes. | MaxMessageBytes 限制单条远端载荷；<=0 取
	// DefaultMaxMessageBytes。
	MaxMessageBytes int
}

// RedisBackend carries messages between nodes over Redis Pub/Sub. | RedisBackend 通过
// Redis Pub/Sub 在节点之间传递消息。
//
// Pub/Sub is at-most-once: a node that is disconnected when a message is
// published will not receive it after reconnecting. Callers that need replay
// keep a cursor in their own durable store. | Pub/Sub 是至多一次：消息发布时断开的节点
// 在重连后不会收到它。需要重放的调用方应自行在持久存储中保存游标。
type RedisBackend struct {
	client redis.UniversalClient
	opts   RedisOptions

	mu     sync.Mutex
	subs   map[*redis.PubSub]struct{}
	closed atomic.Bool
}

// NewRedisBackend builds a backend over an existing client. The client stays
// owned by the caller; Close only releases the subscriptions this backend
// opened. | NewRedisBackend 在既有客户端之上构建后端。客户端仍由调用方拥有；
// Close 只释放本后端打开的订阅。
func NewRedisBackend(client redis.UniversalClient, o RedisOptions) *RedisBackend {
	if o.ChannelPrefix == "" {
		o.ChannelPrefix = DefaultChannelPrefix
	}
	if o.QueueSize <= 0 {
		o.QueueSize = DefaultQueueSize
	}
	if o.MaxMessageBytes <= 0 {
		o.MaxMessageBytes = DefaultMaxMessageBytes
	}
	return &RedisBackend{client: client, opts: o, subs: make(map[*redis.PubSub]struct{}, 8)}
}

// channel renders the Redis channel of a topic. | channel 渲染主题对应的 Redis 频道。
func (b *RedisBackend) channel(topic string) string { return b.opts.ChannelPrefix + topic }

// encodeMessage serializes one message:
//
//	version(1) | nodeLen(2) | node | idLen(2) | id | body
//
// The topic is carried by the channel name. | encodeMessage 序列化一条消息：
// 版本(1) | 节点长度(2) | 节点 | id 长度(2) | id | 正文；主题由频道名承载。
func encodeMessage(msg Message) []byte {
	buf := make([]byte, 0, 1+2+len(msg.Node)+2+len(msg.ID)+len(msg.Body))
	buf = append(buf, 1)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(msg.Node)))
	buf = append(buf, msg.Node...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(msg.ID)))
	buf = append(buf, msg.ID...)
	return append(buf, msg.Body...)
}

// decodeMessage parses one payload, rejecting oversized or truncated input
// before allocating. | decodeMessage 解析一条载荷，在分配之前拒绝超长或截断的输入。
func decodeMessage(topic string, p []byte, max int) (Message, error) {
	if len(p) < 1 || p[0] != 1 {
		return Message{}, ErrCorruptMessage
	}
	rest := p[1:]
	readStr := func() (string, []byte, error) {
		if len(rest) < 2 {
			return "", nil, ErrCorruptMessage
		}
		n := int(binary.BigEndian.Uint16(rest))
		rest = rest[2:]
		if len(rest) < n {
			return "", nil, ErrCorruptMessage
		}
		s := string(rest[:n])
		return s, rest[n:], nil
	}
	node, rest, err := readStr()
	if err != nil {
		return Message{}, err
	}
	id, rest, err := readStr()
	if err != nil {
		return Message{}, err
	}
	if len(rest) > max {
		return Message{}, errs.Detail(ErrMessageTooLarge, "length %d exceeds %d | 长度 %d 超过 %d",
			len(rest), max, len(rest), max)
	}
	body := make([]byte, len(rest))
	copy(body, rest)
	return Message{Topic: topic, ID: id, Node: node, Body: body}, nil
}

// Publish implements Backend. | Publish 实现 Backend。
func (b *RedisBackend) Publish(ctx context.Context, msg Message) error {
	if b.closed.Load() {
		return ErrClosed
	}
	if !validTopic(msg.Topic) {
		return errs.Detail(ErrInvalidTopic, "topic %q | 主题 %q", msg.Topic, msg.Topic)
	}
	if len(msg.Body) > b.opts.MaxMessageBytes {
		return errs.Detail(ErrMessageTooLarge, "length %d exceeds %d | 长度 %d 超过 %d",
			len(msg.Body), b.opts.MaxMessageBytes, len(msg.Body), b.opts.MaxMessageBytes)
	}
	if err := b.client.Publish(ctx, b.channel(msg.Topic), encodeMessage(msg)).Err(); err != nil {
		return errs.Wrap(err, ErrBackend)
	}
	return nil
}

// Subscribe implements Backend. | Subscribe 实现 Backend。
func (b *RedisBackend) Subscribe(ctx context.Context, topic string) (<-chan Message, func(), error) {
	if b.closed.Load() {
		return nil, nil, ErrClosed
	}
	ps := b.client.Subscribe(ctx, b.channel(topic))
	b.mu.Lock()
	if b.closed.Load() {
		b.mu.Unlock()
		_ = ps.Close()
		return nil, nil, ErrClosed
	}
	b.subs[ps] = struct{}{}
	b.mu.Unlock()

	out := make(chan Message, b.opts.QueueSize)
	src := ps.Channel(redis.WithChannelSize(b.opts.QueueSize))
	go func() {
		defer close(out)
		for m := range src {
			msg, err := decodeMessage(topic, []byte(m.Payload), b.opts.MaxMessageBytes)
			if err != nil {
				continue
			}
			select {
			case out <- msg:
			default:
				// A slow local consumer must not stall Redis delivery. | 慢的本地消费者
				// 不得拖住 Redis 投递。
			}
		}
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.subs, ps)
			b.mu.Unlock()
			_ = ps.Close()
		})
	}
	return out, stop, nil
}

// Close implements Backend. | Close 实现 Backend。
func (b *RedisBackend) Close() error {
	if b.closed.Swap(true) {
		return nil
	}
	b.mu.Lock()
	subs := make([]*redis.PubSub, 0, len(b.subs))
	for ps := range b.subs {
		subs = append(subs, ps)
	}
	clear(b.subs)
	b.mu.Unlock()
	var first error
	for _, ps := range subs {
		if err := ps.Close(); err != nil && first == nil {
			first = errs.Wrap(err, ErrBackend)
		}
	}
	return first
}
