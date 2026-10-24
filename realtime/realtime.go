package realtime

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Errors returned by this package. | 本包返回的哨兵错误。
var (
	// ErrInvalidTopic reports a topic outside the accepted alphabet. | ErrInvalidTopic
	// 表示主题超出允许的字符集。
	ErrInvalidTopic = errs.New("realtime: invalid topic | realtime：非法主题")

	// ErrMessageTooLarge reports a publish (or a remote message) above the
	// configured limit. | ErrMessageTooLarge 表示发布（或远端消息）超过配置上限。
	ErrMessageTooLarge = errs.New("realtime: message exceeds the configured limit | realtime：消息超过配置上限")

	// ErrClosed reports work on a closed hub or subscription. | ErrClosed 表示在已关闭的
	// hub 或订阅上操作。
	ErrClosed = errs.New("realtime: hub or subscription is closed | realtime：hub 或订阅已关闭")

	// ErrUnauthorized reports an Authorize callback that denied the topic. |
	// ErrUnauthorized 表示 Authorize 回调拒绝了该主题。
	ErrUnauthorized = errs.New("realtime: topic is not authorized | realtime：主题未获授权")
)

// SlowPolicy selects what happens when a subscription's queue is full. |
// SlowPolicy 选择订阅队列满时的行为。
type SlowPolicy uint8

const (
	// SlowDrop drops the message and counts it; the subscription stays alive.
	// This is the default: one slow peer must not stall the publisher or the
	// other subscribers. | SlowDrop 丢弃该消息并计数，订阅保持存活。这是默认值：
	// 一个慢对端不得拖住发布方或其它订阅者。
	SlowDrop SlowPolicy = iota
	// SlowClose closes the subscription; use it when every message matters and
	// a lagging peer should reconnect instead of silently missing frames. |
	// SlowClose 关闭该订阅；当每条消息都重要、落后对端应重连而不是静默丢帧时使用。
	SlowClose
)

// String renders the policy name. | String 输出策略名。
func (p SlowPolicy) String() string {
	if p == SlowClose {
		return "close"
	}
	return "drop"
}

// ParseSlowPolicy maps a configuration value onto a policy. | ParseSlowPolicy 把配置取值
// 映射为策略。
func ParseSlowPolicy(s string) (SlowPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "drop":
		return SlowDrop, nil
	case "close":
		return SlowClose, nil
	default:
		return SlowDrop, errs.Detail(ErrInvalidOptions, "slow policy %q (want drop|close) | 慢消费者策略 %q（期望 drop|close）", s, s)
	}
}

// ErrInvalidOptions reports an option outside its accepted range. | ErrInvalidOptions
// 表示选项超出允许范围。
var ErrInvalidOptions = errs.New("realtime: invalid options | realtime：非法选项")

// Defaults of Options. | Options 的默认值。
const (
	// DefaultQueueSize bounds every subscription queue. | DefaultQueueSize 限制每个订阅队列。
	DefaultQueueSize = 256
	// DefaultMaxMessageBytes bounds one message. | DefaultMaxMessageBytes 限制单条消息。
	DefaultMaxMessageBytes = 1 << 20
	// DefaultChannelPrefix namespaces Redis channels. | DefaultChannelPrefix 为 Redis 频道加命名空间。
	DefaultChannelPrefix = "yd:rt:"
	// maxTopicLen bounds a topic name. | maxTopicLen 限制主题名长度。
	maxTopicLen = 128
)

// Message is one broadcast message. | Message 是一条广播消息。
type Message struct {
	// Topic is the subscription topic. | Topic 是订阅主题。
	Topic string
	// ID is unique within the deployment: "<node>:<seq>". | ID 在部署内唯一："<node>:<seq>"。
	ID string
	// Node is the publishing node id. | Node 是发布节点 id。
	Node string
	// Body is the payload; the hub never interprets it. | Body 是载荷；hub 从不解释它。
	Body []byte
}

// Sink writes one message body to one transport connection. | Sink 把一条消息正文写到一条
// 传输连接。
//
// Returning an error detaches the subscription, so a broken socket stops the
// fan-out without any extra bookkeeping. | 返回错误即解除订阅，断开的套接字因此自动停止
// 扇出，无需额外簿记。
type Sink func(msg Message) error

// Stats is a snapshot of hub counters. | Stats 是 hub 计数器的快照。
type Stats struct {
	Published  uint64
	Delivered  uint64
	Dropped    uint64
	ClosedSlow uint64
	Errors     uint64
	// Retried counts messages handed to the durable queue after a failed
	// backend publish. | Retried 统计后端发布失败后交给持久队列的消息数。
	Retried uint64
}

// Options configures a Hub. | Options 配置 Hub。
type Options struct {
	// NodeID identifies this node in message ids; empty derives one from the
	// hostname, the pid and a start timestamp, which is unique enough for one
	// deployment. | NodeID 在消息 id 中标识本节点；为空时由主机名、进程号与启动时间戳
	// 推导，对单个部署足够唯一。
	NodeID string
	// QueueSize bounds each subscription queue; <=0 takes DefaultQueueSize. |
	// QueueSize 限制每个订阅队列；<=0 取 DefaultQueueSize。
	QueueSize int
	// MaxMessageBytes bounds one message; <=0 takes DefaultMaxMessageBytes. |
	// MaxMessageBytes 限制单条消息；<=0 取 DefaultMaxMessageBytes。
	MaxMessageBytes int
	// SlowPolicy selects the full-queue behaviour. | SlowPolicy 选择队列满时的行为。
	SlowPolicy SlowPolicy
	// Retry, when non-nil, receives every message whose backend publish failed,
	// so a durable queue (asynq) can republish it later. It must not deliver the
	// message locally again: local delivery already happened before the publish. |
	// Retry 非 nil 时接收每条后端发布失败的消息，使持久队列（asynq）稍后重发。它不得再次
	// 本地投递：本地投递已在发布之前完成。
	Retry RetryQueue
	// Authorize, when non-nil, is consulted on Subscribe; a non-nil error
	// denies the subscription and is returned wrapped in ErrUnauthorized. |
	// Authorize 非 nil 时在 Subscribe 时调用；非 nil 错误拒绝订阅并以
	// ErrUnauthorized 包装返回。
	Authorize func(ctx context.Context, topic string) error
}

// normalize fills the defaults. | normalize 补齐默认值。
func (o Options) normalize() (Options, error) {
	if o.QueueSize <= 0 {
		o.QueueSize = DefaultQueueSize
	}
	if o.MaxMessageBytes <= 0 {
		o.MaxMessageBytes = DefaultMaxMessageBytes
	}
	if o.NodeID == "" {
		host, _ := os.Hostname()
		o.NodeID = host + "-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(startNanos(), 36)
	}
	if strings.ContainsAny(o.NodeID, ":|\x00") {
		return o, errs.Detail(ErrInvalidOptions, "node id %q contains a reserved separator | 节点 id %q 含保留分隔符", o.NodeID, o.NodeID)
	}
	return o, nil
}

// Backend is the cross-node transport. | Backend 是跨节点传输。
type Backend interface {
	// Publish sends msg to every other node subscribed to msg.Topic. | Publish 把
	// msg 发往订阅该主题的其它节点。
	Publish(ctx context.Context, msg Message) error
	// Subscribe starts delivering messages of topic on the returned channel.
	// Closing the returned function stops the delivery and releases resources. |
	// Subscribe 开始在返回的通道上投递 topic 的消息；调用返回的函数停止投递并释放资源。
	Subscribe(ctx context.Context, topic string) (<-chan Message, func(), error)
	// Close releases backend resources. | Close 释放后端资源。
	Close() error
}

// RetryQueue makes a failed cross-node publish durable. | RetryQueue 让失败的跨节点发布变得持久。
//
// The queue is for delivery recovery, not for fan-out: the hub has already
// delivered locally, and a worker that later calls PublishRemote must not touch
// local subscribers again. | 该队列用于投递恢复而非扇出：hub 已在本地投递，稍后调用
// PublishRemote 的工作器不得再次触碰本地订阅者。
type RetryQueue interface {
	// Enqueue stores one message for a later PublishRemote. | Enqueue 保存一条消息供稍后
	// PublishRemote 使用。
	Enqueue(ctx context.Context, msg Message) error
}

// Hub fans messages out to local subscribers and, optionally, across nodes. |
// Hub 把消息扇出给本地订阅者，并可选地跨节点传递。
type Hub struct {
	opts Options

	mu     sync.Mutex
	topics map[string]*topicState
	closed bool

	backend Backend
	seq     atomic.Uint64

	published  atomic.Uint64
	delivered  atomic.Uint64
	dropped    atomic.Uint64
	closedSlow atomic.Uint64
	errors     atomic.Uint64
	retried    atomic.Uint64
}

// topicState is one topic's local and remote subscription state. | topicState 是单个主题的
// 本地与远端订阅状态。
type topicState struct {
	subs     map[*Subscription]struct{}
	remote   <-chan Message
	stop     func()
	stopped  bool
	starting bool
}

// NewHub builds a hub. It is single-node until Use installs a Backend. | NewHub
// 构造 hub。在 Use 安装 Backend 之前它只服务单机。
func NewHub(o Options) *Hub {
	o, err := o.normalize()
	if err != nil {
		// normalize only rejects a malformed node id; fall back to a generated one
		// rather than failing construction, and keep the reason observable through
		// the first publish. | normalize 只拒绝格式错误的节点 id；回退到生成的 id 而不是
		// 让构造失败，原因仍可通过首次发布观察到。
		host, _ := os.Hostname()
		o.NodeID = host + "-" + strconv.Itoa(os.Getpid())
	}
	return &Hub{opts: o, topics: make(map[string]*topicState, 8)}
}

// Use installs the cross-node backend. It must be called before the first
// Subscribe; a nil backend restores single-node mode. | Use 安装跨节点后端。必须在首次
// Subscribe 之前调用；nil 后端恢复单机模式。
func (h *Hub) Use(b Backend) {
	h.mu.Lock()
	h.backend = b
	h.mu.Unlock()
}

// NodeID returns the id embedded in message ids. | NodeID 返回消息 id 中携带的节点 id。
func (h *Hub) NodeID() string { return h.opts.NodeID }

// SubscriberCount returns the number of local subscribers of topic. | SubscriberCount
// 返回 topic 的本地订阅者数量。
func (h *Hub) SubscriberCount(topic string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	if st := h.topics[topic]; st != nil {
		return len(st.subs)
	}
	return 0
}

// Stats returns a snapshot of the counters. | Stats 返回计数器快照。
func (h *Hub) Stats() Stats {
	return Stats{
		Published:  h.published.Load(),
		Delivered:  h.delivered.Load(),
		Dropped:    h.dropped.Load(),
		ClosedSlow: h.closedSlow.Load(),
		Errors:     h.errors.Load(),
		Retried:    h.retried.Load(),
	}
}

// validTopic reports whether topic is acceptable. | validTopic 报告主题是否合法。
func validTopic(topic string) bool {
	if topic == "" || len(topic) > maxTopicLen {
		return false
	}
	for i := 0; i < len(topic); i++ {
		c := topic[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '-' || c == ':' || c == '/':
		default:
			return false
		}
	}
	return true
}

// Publish assigns a message id, fans the body out locally and forwards it to
// the backend. | Publish 分配消息 id，把正文扇出到本地并转发给后端。
//
// Local delivery always happens first. A backend failure is returned after it,
// unless Options.Retry accepted the message, in which case Publish reports
// success and the durable queue owns the retry. | 本地投递总是先发生。后端失败在本地
// 投递之后返回；若 Options.Retry 已接收该消息，Publish 报告成功，由持久队列负责重试。
func (h *Hub) Publish(ctx context.Context, topic string, body []byte) error {
	if !validTopic(topic) {
		return errs.Detail(ErrInvalidTopic, "topic %q | 主题 %q", topic, topic)
	}
	if len(body) > h.opts.MaxMessageBytes {
		return errs.Detail(ErrMessageTooLarge, "topic %q length %d exceeds %d | 主题 %q 长度 %d 超过 %d",
			topic, len(body), h.opts.MaxMessageBytes, topic, len(body), h.opts.MaxMessageBytes)
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return ErrClosed
	}
	backend := h.backend
	h.mu.Unlock()

	msg := Message{
		Topic: topic,
		ID:    h.opts.NodeID + ":" + strconv.FormatUint(h.seq.Add(1), 10),
		Node:  h.opts.NodeID,
		Body:  body,
	}
	h.published.Add(1)
	h.fanOut(msg)
	if backend == nil {
		return nil
	}
	if err := backend.Publish(ctx, msg); err != nil {
		h.errors.Add(1)
		if h.opts.Retry != nil {
			if qerr := h.opts.Retry.Enqueue(ctx, msg); qerr == nil {
				h.retried.Add(1)
				return nil
			} else {
				return errors.Join(err, qerr)
			}
		}
		return err
	}
	return nil
}

// PublishRemote sends an already delivered message to the backend only. It is
// the entry point for a durable retry worker: local subscribers are not
// touched, and the message keeps its original id and node. | PublishRemote 只把
// 已本地投递过的消息发往后端。它是持久重试工作器的入口：不触碰本地订阅者，消息保留原始
// id 与节点。
func (h *Hub) PublishRemote(ctx context.Context, msg Message) error {
	if !validTopic(msg.Topic) {
		return errs.Detail(ErrInvalidTopic, "topic %q | 主题 %q", msg.Topic, msg.Topic)
	}
	if len(msg.Body) > h.opts.MaxMessageBytes {
		return errs.Detail(ErrMessageTooLarge, "length %d exceeds %d | 长度 %d 超过 %d",
			len(msg.Body), h.opts.MaxMessageBytes, len(msg.Body), h.opts.MaxMessageBytes)
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return ErrClosed
	}
	backend := h.backend
	h.mu.Unlock()
	if backend == nil {
		return nil
	}
	// A retried payload may have been serialized without its identity; fill it
	// so other nodes can still deduplicate the echo. | 重试载荷可能在序列化时丢失标识；
	// 这里补齐，使其它节点仍能识别回声。
	if msg.Node == "" {
		msg.Node = h.opts.NodeID
	}
	if msg.ID == "" {
		msg.ID = msg.Node + ":" + strconv.FormatUint(h.seq.Add(1), 10)
	}
	if err := backend.Publish(ctx, msg); err != nil {
		h.errors.Add(1)
		return err
	}
	return nil
}

// fanOut delivers one message to every local subscriber of its topic. | fanOut 把一条
// 消息投递给其主题的全部本地订阅者。
func (h *Hub) fanOut(msg Message) {
	h.mu.Lock()
	st := h.topics[msg.Topic]
	if st == nil {
		h.mu.Unlock()
		return
	}
	subs := make([]*Subscription, 0, len(st.subs))
	for sub := range st.subs {
		subs = append(subs, sub)
	}
	h.mu.Unlock()

	for _, sub := range subs {
		select {
		case sub.queue <- msg:
			h.delivered.Add(1)
		default:
			h.dropped.Add(1)
			if h.opts.SlowPolicy == SlowClose {
				h.closedSlow.Add(1)
				sub.Close()
			}
		}
	}
}

// Subscribe registers sink for topic. | Subscribe 为 topic 注册 sink。
//
// The sink runs on the subscription's own goroutine, in publish order. A sink
// error closes the subscription. | sink 在订阅自身的协程上按发布顺序运行；sink 返回错误
// 即关闭订阅。
func (h *Hub) Subscribe(ctx context.Context, topic string, sink Sink) (*Subscription, error) {
	if sink == nil {
		return nil, errs.Detail(ErrInvalidOptions, "nil sink | sink 为 nil")
	}
	if !validTopic(topic) {
		return nil, errs.Detail(ErrInvalidTopic, "topic %q | 主题 %q", topic, topic)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if h.opts.Authorize != nil {
		if err := h.opts.Authorize(ctx, topic); err != nil {
			return nil, errs.WrapDetail(err, ErrUnauthorized, "topic %q | 主题 %q", topic, topic)
		}
	}

	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, ErrClosed
	}
	st := h.topics[topic]
	if st == nil {
		st = &topicState{subs: make(map[*Subscription]struct{}, 4)}
		h.topics[topic] = st
	}
	sub := &Subscription{
		hub:   h,
		topic: topic,
		sink:  sink,
		queue: make(chan Message, h.opts.QueueSize),
		done:  make(chan struct{}),
	}
	st.subs[sub] = struct{}{}
	startRemote := st.remote == nil && !st.starting && h.backend != nil
	if startRemote {
		st.starting = true
	}
	h.mu.Unlock()

	if startRemote {
		h.startRemote(topic)
	}
	go sub.run()
	return sub, nil
}

// startRemote opens the backend subscription for topic and pumps it into the
// local fan-out. | startRemote 打开 topic 的后端订阅并把消息泵进本地扇出。
func (h *Hub) startRemote(topic string) {
	h.mu.Lock()
	backend := h.backend
	st := h.topics[topic]
	if backend == nil || st == nil || st.remote != nil || !st.starting {
		if st != nil {
			st.starting = false
		}
		h.mu.Unlock()
		return
	}
	h.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	ch, stop, err := backend.Subscribe(ctx, topic)
	if err != nil {
		cancel()
		h.errors.Add(1)
		h.mu.Lock()
		if cur := h.topics[topic]; cur != nil {
			cur.starting = false
		}
		h.mu.Unlock()
		return
	}
	h.mu.Lock()
	st = h.topics[topic]
	if st == nil {
		h.mu.Unlock()
		cancel()
		stop()
		return
	}
	st.starting = false
	if len(st.subs) == 0 {
		// Every subscriber left while the backend subscription was starting. |
		// 启动后端订阅期间所有订阅者都离开了。
		delete(h.topics, topic)
		h.mu.Unlock()
		cancel()
		stop()
		return
	}
	st.remote = ch
	st.stop = func() { cancel(); stop() }
	h.mu.Unlock()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-ch:
				if !ok {
					return
				}
				if msg.Node == h.opts.NodeID {
					// Already delivered locally by Publish. | Publish 已在本地投递。
					continue
				}
				if len(msg.Body) > h.opts.MaxMessageBytes {
					h.errors.Add(1)
					continue
				}
				h.fanOut(msg)
			}
		}
	}()
}

// remove detaches sub and stops the topic's remote subscription when the last
// local subscriber leaves. | remove 解除 sub，并在最后一个本地订阅者离开时停止该主题的
// 远程订阅。
func (h *Hub) remove(sub *Subscription) {
	h.mu.Lock()
	st := h.topics[sub.topic]
	if st != nil {
		delete(st.subs, sub)
		if len(st.subs) == 0 {
			if st.stop != nil && !st.stopped {
				st.stopped = true
				stop := st.stop
				st.stop = nil
				st.remote = nil
				h.mu.Unlock()
				stop()
				h.mu.Lock()
			}
			// Re-check identity: a Subscribe may have installed a fresh topic
			// state while the remote subscription was being stopped. |
			// 重新核对身份：停止远程订阅期间可能有新的 Subscribe 装入了新的主题状态。
			if cur := h.topics[sub.topic]; cur == st && (h.backend == nil || st.stopped) {
				delete(h.topics, sub.topic)
			}
		}
	}
	h.mu.Unlock()
}

// Close stops every subscription and the backend. It is idempotent. | Close 停止全部
// 订阅与后端。该方法是幂等的。
func (h *Hub) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	var subs []*Subscription
	var stops []func()
	for topic, st := range h.topics {
		for sub := range st.subs {
			subs = append(subs, sub)
		}
		if st.stop != nil && !st.stopped {
			st.stopped = true
			stops = append(stops, st.stop)
		}
		delete(h.topics, topic)
	}
	backend := h.backend
	h.backend = nil
	h.mu.Unlock()

	for _, stop := range stops {
		stop()
	}
	for _, sub := range subs {
		sub.Close()
	}
	if backend != nil {
		return backend.Close()
	}
	return nil
}

// Subscription is one sink attached to one topic. | Subscription 是挂在单个主题上的一个 sink。
type Subscription struct {
	hub   *Hub
	topic string
	sink  Sink
	queue chan Message
	done  chan struct{}

	closeOnce sync.Once
}

// run drains the queue into the sink. | run 把队列排空到 sink。
func (s *Subscription) run() {
	for {
		select {
		case <-s.done:
			return
		case msg := <-s.queue:
			if err := s.sink(msg); err != nil {
				s.hub.errors.Add(1)
				s.Close()
				return
			}
		}
	}
}

// Topic returns the subscription topic. | Topic 返回订阅主题。
func (s *Subscription) Topic() string { return s.topic }

// Close detaches the subscription; it is idempotent and safe to call from the
// sink itself. | Close 解除订阅；幂等，且可从 sink 内部调用。
func (s *Subscription) Close() {
	s.closeOnce.Do(func() {
		close(s.done)
		s.hub.remove(s)
	})
}

// startNanos is a seam for tests. | startNanos 是测试注入口。
var startNanos = func() int64 { return time.Now().UnixNano() }
