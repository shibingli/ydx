package sse

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/client"
	"github.com/shibingli/ydx/errs"
	ydxsse "github.com/shibingli/ydx/sse"
)

// ErrClosed indicates a fanout used after Close. | ErrClosed 表示在 Close 后使用扇出。
var ErrClosed = errs.New("client/sse: fanout closed | client/sse：扇出已关闭")

// Options configures a Fanout. | Options 配置 Fanout。
type Options struct {
	// Queue is each subscriber queue length; <=0 means 64. | Queue 是每个订阅者队列长度；<=0 表示 64。
	Queue int
	// Drop selects DropNewest or DropOldest. | Drop 选择 DropNewest 或 DropOldest。
	Drop client.DropPolicy
	// Writer is the base ydx/sse writer configuration. | Writer 是基础 ydx/sse writer 配置。
	Writer ydxsse.Options
	// WriteTimeout bounds one event write; <=0 means 30s. | WriteTimeout 限制单次事件写入；<=0 表示 30s。
	WriteTimeout time.Duration
}

// Fanout broadcasts parsed SSE events to independent sse.Writer subscribers. | Fanout 把解析后的 SSE 事件广播给独立的 sse.Writer 订阅者。
type Fanout struct {
	opts   Options
	mu     sync.RWMutex
	subs   map[*Subscription]struct{}
	closed bool
	drops  atomic.Uint64
}

// Subscription is one SSE subscriber. | Subscription 是一个 SSE 订阅者。
type Subscription struct {
	fanout    *Fanout
	writer    *ydxsse.Writer
	response  http.ResponseWriter
	timeout   time.Duration
	queue     chan client.Event
	closeOnce sync.Once
	mu        sync.RWMutex
	wg        sync.WaitGroup
	closing   bool
	closed    bool
}

// NewFanout builds a fanout with defaults. | NewFanout 使用默认值构建扇出。
func NewFanout(o Options) *Fanout {
	if o.Queue <= 0 {
		o.Queue = 64
	}
	if o.WriteTimeout <= 0 {
		o.WriteTimeout = 30 * time.Second
	}
	return &Fanout{opts: o, subs: make(map[*Subscription]struct{})}
}

// Add registers one response writer as a subscriber. | Add 把一个响应写入器注册为订阅者。
func (f *Fanout) Add(w http.ResponseWriter, opts ...ydxsse.Options) (*Subscription, error) {
	if f == nil || w == nil {
		return nil, ErrClosed
	}
	writerOpts := f.opts.Writer
	if len(opts) > 0 {
		writerOpts = opts[0]
	}
	f.mu.Lock()
	closed := f.closed
	f.mu.Unlock()
	if closed {
		return nil, ErrClosed
	}
	writer, err := ydxsse.NewWriter(w, writerOpts)
	if err != nil {
		return nil, err
	}
	sub := &Subscription{
		fanout:   f,
		writer:   writer,
		response: w,
		timeout:  f.opts.WriteTimeout,
		queue:    make(chan client.Event, f.opts.Queue),
	}
	sub.wg.Add(1)
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		sub.wg.Done()
		_ = writer.Close()
		return nil, ErrClosed
	}
	f.subs[sub] = struct{}{}
	f.mu.Unlock()
	go sub.run()
	return sub, nil
}

// Sink returns an EventSink that broadcasts to every subscriber. | Sink 返回向全部订阅者广播的 EventSink。
func (f *Fanout) Sink() client.EventSink {
	return &sink{fanout: f}
}

// Dropped reports the number of dropped events and failed writes. | Dropped 返回被丢弃的事件与失败写入数。
func (f *Fanout) Dropped() uint64 {
	if f == nil {
		return 0
	}
	return f.drops.Load()
}

// Close closes every subscriber. | Close 关闭全部订阅者。
func (f *Fanout) Close() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true
	subs := make([]*Subscription, 0, len(f.subs))
	for sub := range f.subs {
		subs = append(subs, sub)
	}
	f.mu.Unlock()
	for _, sub := range subs {
		_ = sub.Close()
	}
	return nil
}

// broadcast enqueues one event to every current subscriber. | broadcast 把一个事件投递给当前全部订阅者。
func (f *Fanout) broadcast(event client.Event) error {
	if f == nil {
		return ErrClosed
	}
	f.mu.RLock()
	if f.closed {
		f.mu.RUnlock()
		return ErrClosed
	}
	for sub := range f.subs {
		sub.enqueue(event)
	}
	f.mu.RUnlock()
	return nil
}

// remove unregisters a subscription. | remove 取消订阅注册。
func (f *Fanout) remove(sub *Subscription) {
	f.mu.Lock()
	delete(f.subs, sub)
	f.mu.Unlock()
}

// enqueue offers an event without blocking the primary. | enqueue 在不阻塞主流的情况下投递事件。
func (s *Subscription) enqueue(event client.Event) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		s.fanout.drops.Add(1)
		return
	}
	select {
	case s.queue <- event:
		return
	default:
	}
	if s.fanout.opts.Drop == client.DropOldest {
		select {
		case <-s.queue:
		default:
		}
		select {
		case s.queue <- event:
			return
		default:
		}
	}
	s.fanout.drops.Add(1)
}

// run writes queued events to the subscriber. | run 把队列中的事件写给订阅者。
func (s *Subscription) run() {
	defer s.wg.Done()
	defer func() { _ = s.writer.Close() }()
	for event := range s.queue {
		s.mu.RLock()
		closing := s.closing
		s.mu.RUnlock()
		if s.response != nil && s.timeout > 0 && !closing {
			// After Close, keep the short deadline it installed so a stalled
			// subscriber cannot block wg.Wait forever. | Close 之后保留其设置的短期限，
			// 避免停滞订阅者永久阻塞 wg.Wait。
			_ = http.NewResponseController(s.response).SetWriteDeadline(time.Now().Add(s.timeout))
		}
		err := s.writer.WriteEvent(ydxsse.Event{
			ID:      event.ID,
			Name:    event.Name,
			Comment: event.Comment,
			Data:    event.Data,
			Retry:   event.Retry,
		})
		if err != nil {
			s.fanout.drops.Add(1)
		}
	}
}

// Close unregisters and closes the subscription. | Close 取消注册并关闭订阅。
func (s *Subscription) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.fanout.remove(s)
		if s.response != nil {
			_ = http.NewResponseController(s.response).SetWriteDeadline(time.Now())
		}
		s.mu.Lock()
		s.closing = true
		s.closed = true
		close(s.queue)
		s.mu.Unlock()
		s.wg.Wait()
	})
	return nil
}

// sink adapts Fanout to client.EventSink. | sink 把 Fanout 适配为 client.EventSink。
type sink struct {
	fanout *Fanout
}

// WriteEvent broadcasts one event. | WriteEvent 广播一个事件。
func (s *sink) WriteEvent(ctx context.Context, event client.Event) error {
	_ = ctx
	return s.fanout.broadcast(event)
}

// Close closes the fanout. | Close 关闭扇出。
func (s *sink) Close() error {
	return s.fanout.Close()
}
