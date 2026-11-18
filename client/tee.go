package client

import (
	"context"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Sink receives raw response chunks from tee mirroring. | Sink 接收 tee 镜像的原始响应块。
type Sink interface {
	// WriteChunk consumes one chunk. | WriteChunk 消费一个块。
	WriteChunk(ctx context.Context, chunk []byte) error
	// Close releases the sink. | Close 释放 sink。
	Close() error
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
	drop    DropPolicy
	timeout time.Duration
	drops   *atomic.Uint64
	once    sync.Once
	wg      sync.WaitGroup
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
		drop:    drop,
		timeout: timeout,
		drops:   drops,
	}
	worker.wg.Add(1)
	go worker.run()
	return worker
}

// enqueue offers a chunk without blocking the primary. | enqueue 在不阻塞主流的情况下投递块。
func (w *teeSinkWorker) enqueue(chunk []byte) bool {
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
	defer w.wg.Done()
	defer func() { _ = w.sink.Close() }()
	for chunk := range w.ch {
		ctx, cancel := context.WithTimeout(context.Background(), w.timeout)
		err := w.sink.WriteChunk(ctx, chunk)
		cancel()
		if err != nil {
			w.drops.Add(1)
		}
	}
}

// Close closes the queue and waits for the consumer. | Close 关闭队列并等待消费者。
func (w *teeSinkWorker) Close() {
	w.once.Do(func() {
		close(w.ch)
		w.wg.Wait()
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
func (e *engine) applyTee(rule *Rule, resp *http.Response) *http.Response {
	if resp == nil || resp.Body == nil {
		return resp
	}
	policy, ok := e.mirrorFor(rule)
	if !ok || policy.Mode != MirrorTee || len(policy.TeeSinks) == 0 {
		return resp
	}
	workers := make([]*teeSinkWorker, 0, len(policy.TeeSinks))
	for _, sink := range policy.TeeSinks {
		workers = append(workers, newTeeSinkWorker(sink, policy.TeeQueue, policy.TeeDrop, policy.TeeTimeout, &e.mirrorDrops))
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
