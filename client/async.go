package client

import (
	"context"
	"net/http"
	"sync"

	"github.com/shibingli/ydx/errs"
)

// Future is the result of an asynchronous request. | Future 是异步请求的结果。
type Future struct {
	err  error
	done chan struct{}
	resp *Response
	once sync.Once
}

// Wait waits for the future or ctx. | Wait 等待 Future 或 ctx。
func (f *Future) Wait(ctx context.Context) (*Response, error) {
	if f == nil {
		return nil, ErrInvalidRequest
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-f.done:
		return f.resp, f.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Done returns a channel closed when the future completes. | Done 返回 Future 完成时关闭的通道。
func (f *Future) Done() <-chan struct{} {
	if f == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return f.done
}

// complete finishes the future exactly once. | complete 只完成 Future 一次。
func (f *Future) complete(resp *Response, err error) {
	f.once.Do(func() {
		f.resp = resp
		f.err = err
		close(f.done)
	})
}

// Submit starts an asynchronous request under the client async limit. | Submit 在客户端异步限制下启动异步请求。
func (c *Client) Submit(ctx context.Context, req *http.Request, cb func(*Response, error)) *Future {
	future := &Future{done: make(chan struct{})}
	if c == nil {
		future.complete(nil, ErrClosed)
		return future
	}
	if c.engine == nil {
		future.complete(nil, ErrInvalidConfig)
		return future
	}
	if req == nil || req.URL == nil {
		future.complete(nil, ErrInvalidRequest)
		return future
	}
	if ctx == nil {
		ctx = context.Background()
	}
	c.asyncMu.Lock()
	if c.closed.Load() {
		c.asyncMu.Unlock()
		future.complete(nil, ErrClosed)
		return future
	}
	select {
	case c.asyncSem <- struct{}{}:
	default:
		c.asyncMu.Unlock()
		future.complete(nil, ErrBusy)
		return future
	}
	runCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.rootCtx, cancel)
	c.asyncWG.Add(1)
	c.asyncMu.Unlock()
	go func() {
		defer func() { <-c.asyncSem }()
		defer cancel()
		defer stop()
		resp, err := c.DoWithMeta(req.WithContext(runCtx))
		future.complete(resp, err)
		// Release the close barrier before running user code so a callback that
		// calls Close cannot wait on its own goroutine. | 先释放关闭屏障再执行用户
		// 回调，避免回调调用 Close 时等待自身。
		c.asyncWG.Done()
		if cb != nil {
			func() {
				defer func() { _ = recover() }()
				cb(resp, err)
			}()
		}
	}()
	return future
}

// WithMaxAsync sets the async concurrency limit. | WithMaxAsync 设置异步并发上限。
func WithMaxAsync(n int) Option {
	return func(o *options) error {
		if n <= 0 {
			return errs.Detail(ErrInvalidConfig, "max async must be positive | 最大异步并发必须为正")
		}
		o.MaxAsync = n
		return nil
	}
}
