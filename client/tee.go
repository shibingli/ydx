package client

import (
	"context"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Sink receives raw response chunks from tee mirroring. | Sink 接收 tee 镜像的原始响应块。
type Sink interface {
	// WriteChunk consumes one chunk. | WriteChunk 消费一个块。
	WriteChunk(ctx context.Context, chunk []byte) error
	// Close releases the sink. | Close 释放 sink。
	Close() error
}

// EventSink receives parsed SSE events from tee mirroring. | EventSink 接收 tee 镜像解析后的事件。
type EventSink interface {
	// WriteEvent consumes one event. | WriteEvent 消费一个事件。
	WriteEvent(ctx context.Context, event Event) error
	// Close releases the sink. | Close 释放 sink。
	Close() error
}

// EventSinkFunc adapts a function into an EventSink. | EventSinkFunc 把函数适配为 EventSink。
type EventSinkFunc func(ctx context.Context, event Event) error

// WriteEvent calls f. | WriteEvent 调用 f。
func (f EventSinkFunc) WriteEvent(ctx context.Context, event Event) error {
	return f(ctx, event)
}

// Close implements EventSink and does nothing. | Close 实现 EventSink 且不做任何事。
func (f EventSinkFunc) Close() error { return nil }

// callSinkChunk invokes a user Sink with panic isolation. | callSinkChunk 以 panic 隔离调用用户 Sink。
func callSinkChunk(sink Sink, ctx context.Context, chunk []byte) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = errs.Detail(ErrHookPanic, "sink panic: %v | sink panic：%v", recovered, recovered)
		}
	}()
	return sink.WriteChunk(ctx, chunk)
}

// closeSink invokes a user Sink.Close with panic isolation. | closeSink 以 panic 隔离调用用户 Sink.Close。
func closeSink(sink Sink) {
	if sink == nil {
		return
	}
	defer func() { _ = recover() }()
	_ = sink.Close()
}

// callSinkEvent invokes a user EventSink with panic isolation. | callSinkEvent 以 panic 隔离调用用户 EventSink。
func callSinkEvent(sink EventSink, ctx context.Context, event Event) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = errs.Detail(ErrHookPanic, "event sink panic: %v | event sink panic：%v", recovered, recovered)
		}
	}()
	return sink.WriteEvent(ctx, event)
}

// closeEventSink invokes a user EventSink.Close with panic isolation. | closeEventSink 以 panic 隔离调用用户 EventSink.Close。
func closeEventSink(sink EventSink) {
	if sink == nil {
		return
	}
	defer func() { _ = recover() }()
	_ = sink.Close()
}

// SinkFunc adapts a function into a Sink. | SinkFunc 把函数适配为 Sink。
type SinkFunc func(ctx context.Context, chunk []byte) error

// WriteChunk calls f. | WriteChunk 调用 f。
func (f SinkFunc) WriteChunk(ctx context.Context, chunk []byte) error {
	return f(ctx, chunk)
}

// Close implements Sink and does nothing. | Close 实现 Sink 且不做任何事。
func (f SinkFunc) Close() error { return nil }

// teeSinkWorker owns one bounded queue and its consumer goroutine. | teeSinkWorker 拥有一个有界队列及其消费 goroutine。
type teeSinkWorker struct {
	sink    Sink
	ch      chan []byte
	done    chan struct{}
	drops   *atomic.Uint64
	drop    DropPolicy
	timeout time.Duration
	once    sync.Once
	mu      sync.RWMutex
	closed  bool
}

// newTeeSinkWorker starts one consumer. | newTeeSinkWorker 启动一个消费者。
func newTeeSinkWorker(sink Sink, queue int, drop DropPolicy, timeout time.Duration, drops *atomic.Uint64) *teeSinkWorker {
	if queue <= 0 {
		queue = 64
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	worker := &teeSinkWorker{
		sink:    sink,
		ch:      make(chan []byte, queue),
		done:    make(chan struct{}),
		drop:    drop,
		timeout: timeout,
		drops:   drops,
	}
	go worker.run()
	return worker
}

// enqueue offers a chunk without blocking the primary. | enqueue 在不阻塞主流的情况下投递块。
func (w *teeSinkWorker) enqueue(chunk []byte) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		w.drops.Add(1)
		return false
	}
	select {
	case w.ch <- chunk:
		return true
	default:
	}
	if w.drop == DropOldest {
		select {
		case <-w.ch:
		default:
		}
		select {
		case w.ch <- chunk:
			return true
		default:
		}
	}
	w.drops.Add(1)
	return false
}

// run consumes chunks until Close. | run 消费块直到 Close。
func (w *teeSinkWorker) run() {
	defer close(w.done)
	defer closeSink(w.sink)
	for chunk := range w.ch {
		ctx, cancel := context.WithTimeout(context.Background(), w.timeout)
		err := callSinkChunk(w.sink, ctx, chunk)
		cancel()
		if err != nil {
			w.drops.Add(1)
		}
	}
}

// Close closes the queue and waits up to one sink timeout for the consumer. | Close
// 关闭队列并最多等待一个 sink 超时。
func (w *teeSinkWorker) Close() {
	w.once.Do(func() {
		w.mu.Lock()
		w.closed = true
		close(w.ch)
		w.mu.Unlock()
		select {
		case <-w.done:
		case <-time.After(w.timeout):
		}
	})
}

// eventSinkWorker owns one bounded event queue and its consumer goroutine. | eventSinkWorker 拥有一个有界事件队列及其消费 goroutine。
type eventSinkWorker struct {
	sink    EventSink
	ch      chan Event
	done    chan struct{}
	drops   *atomic.Uint64
	drop    DropPolicy
	timeout time.Duration
	once    sync.Once
	mu      sync.RWMutex
	closed  bool
}

// newEventSinkWorker starts one event consumer. | newEventSinkWorker 启动一个事件消费者。
func newEventSinkWorker(sink EventSink, queue int, drop DropPolicy, timeout time.Duration, drops *atomic.Uint64) *eventSinkWorker {
	if queue <= 0 {
		queue = 64
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	worker := &eventSinkWorker{
		sink:    sink,
		ch:      make(chan Event, queue),
		done:    make(chan struct{}),
		drop:    drop,
		timeout: timeout,
		drops:   drops,
	}
	go worker.run()
	return worker
}

// enqueue offers an event without blocking the primary. | enqueue 在不阻塞主流的情况下投递事件。
func (w *eventSinkWorker) enqueue(event Event) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		w.drops.Add(1)
		return false
	}
	select {
	case w.ch <- event:
		return true
	default:
	}
	if w.drop == DropOldest {
		select {
		case <-w.ch:
		default:
		}
		select {
		case w.ch <- event:
			return true
		default:
		}
	}
	w.drops.Add(1)
	return false
}

// run consumes events until Close. | run 消费事件直到 Close。
func (w *eventSinkWorker) run() {
	defer close(w.done)
	defer closeEventSink(w.sink)
	for event := range w.ch {
		ctx, cancel := context.WithTimeout(context.Background(), w.timeout)
		err := callSinkEvent(w.sink, ctx, event)
		cancel()
		if err != nil {
			w.drops.Add(1)
		}
	}
}

// Close closes the queue and waits up to one sink timeout for the consumer. | Close
// 关闭队列并最多等待一个 sink 超时。
func (w *eventSinkWorker) Close() {
	w.once.Do(func() {
		w.mu.Lock()
		w.closed = true
		close(w.ch)
		w.mu.Unlock()
		select {
		case <-w.done:
		case <-time.After(w.timeout):
		}
	})
}

// sseEventPump parses raw SSE chunks and fans events to workers. | sseEventPump 解析原始 SSE 块并把事件扇出到 worker。
type sseEventPump struct {
	writer  *io.PipeWriter
	done    chan struct{}
	workers []*eventSinkWorker
	once    sync.Once
}

// startSSEEventPump starts the parsing goroutine. | startSSEEventPump 启动解析 goroutine。
func startSSEEventPump(workers []*eventSinkWorker) *sseEventPump {
	reader, writer := io.Pipe()
	pump := &sseEventPump{writer: writer, done: make(chan struct{}), workers: workers}
	go func() {
		defer close(pump.done)
		defer reader.Close()
		events := NewEventReader(reader)
		for {
			event, err := events.Next()
			if err != nil {
				return
			}
			for _, worker := range workers {
				worker.enqueue(event)
			}
		}
	}()
	return pump
}

// Write offers raw chunks to the parser. | Write 把原始块投递给解析器。
func (p *sseEventPump) Write(chunk []byte) {
	if p == nil || len(chunk) == 0 {
		return
	}
	_, _ = p.writer.Write(chunk)
}

// Close stops parsing and waits for every event worker. | Close 停止解析并等待全部事件 worker。
func (p *sseEventPump) Close() {
	if p == nil {
		return
	}
	p.once.Do(func() {
		_ = p.writer.Close()
		<-p.done
		for _, worker := range p.workers {
			worker.Close()
		}
	})
}

// teeBody forwards reads to the primary body and mirrors each chunk. | teeBody 把读取转给主流正文并镜像每个块。
type teeBody struct {
	body    io.ReadCloser
	workers []*teeSinkWorker
	once    sync.Once
}

// Read reads the primary body and fans the chunk out. | Read 读取主流正文并扇出块。
func (t *teeBody) Read(p []byte) (int, error) {
	n, err := t.body.Read(p)
	if n > 0 {
		chunk := append([]byte(nil), p[:n]...)
		for _, worker := range t.workers {
			worker.enqueue(chunk)
		}
	}
	if err != nil {
		t.closeSinks()
	}
	return n, err
}

// Close closes the sinks and the primary body. | Close 关闭 sink 与主流正文。
func (t *teeBody) Close() error {
	t.closeSinks()
	return t.body.Close()
}

// closeSinks closes every worker exactly once. | closeSinks 只关闭每个 worker 一次。
func (t *teeBody) closeSinks() {
	t.once.Do(func() {
		for _, worker := range t.workers {
			worker.Close()
		}
	})
}

// applyTee wraps a response body when the rule uses tee mirroring. | applyTee 在规则使用 tee 镜像时包装响应正文。
func (e *engine) applyTee(req *http.Request, rule *Rule, resp *http.Response) *http.Response {
	if resp == nil || resp.Body == nil || req == nil {
		return resp
	}
	policy, ok := e.mirrorFor(rule)
	if !ok || policy == nil || policy.Mode != MirrorTee ||
		!mirrorSampled(req.URL, rule, policy.Percent) {
		return resp
	}
	workers := e.teeSinks(policy)
	if len(workers) == 0 {
		return resp
	}
	resp.Body = &teeBody{body: resp.Body, workers: workers}
	return resp
}

// teeSinks builds workers for an existing stream (used by SSE forwarding). | teeSinks 为已有流构建 worker（供 SSE 转发使用）。
func (e *engine) teeSinks(policy *MirrorPolicy) []*teeSinkWorker {
	if policy == nil || len(policy.TeeSinks) == 0 {
		return nil
	}
	workers := make([]*teeSinkWorker, 0, len(policy.TeeSinks))
	for _, sink := range policy.TeeSinks {
		workers = append(workers, newTeeSinkWorker(sink, policy.TeeQueue, policy.TeeDrop, policy.TeeTimeout, &e.mirrorDrops))
	}
	return workers
}

// writeTeeChunk fans one raw chunk to workers. | writeTeeChunk 把一个原始块扇出到 worker。
func writeTeeChunk(workers []*teeSinkWorker, chunk []byte) {
	for _, worker := range workers {
		worker.enqueue(chunk)
	}
}

// closeTeeWorkers closes and waits for all workers. | closeTeeWorkers 关闭并等待全部 worker。
func closeTeeWorkers(workers []*teeSinkWorker) {
	for _, worker := range workers {
		worker.Close()
	}
}
