package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// GroupOption configures a Group. | GroupOption 配置 Group。
type GroupOption func(*groupConfig)

// groupConfig is the mutable group configuration. | groupConfig 是 Group 的可变配置。
type groupConfig struct {
	maxParallel int
	maxBody     int64
}

// WithGroupMaxParallel caps concurrent HTTP tasks in one group. | WithGroupMaxParallel 限制单个 Group 的并发 HTTP 任务。
func WithGroupMaxParallel(n int) GroupOption {
	return func(c *groupConfig) {
		if n > 0 {
			c.maxParallel = n
		}
	}
}

// WithGroupMaxBodyBytes caps buffered group response bodies. | WithGroupMaxBodyBytes 限制 Group 缓冲的响应正文。
func WithGroupMaxBodyBytes(n int64) GroupOption {
	return func(c *groupConfig) {
		if n > 0 {
			c.maxBody = n
		}
	}
}

// Group runs a dynamic set of parallel requests and functions. | Group 运行动态的并行请求与函数集合。
type Group struct {
	ctx     context.Context
	client  *Client
	sem     chan struct{}
	names   map[string]struct{}
	results map[string]*StepResult
	order   []string
	errs    []error

	wg      sync.WaitGroup
	maxBody int64

	mu sync.Mutex
}

// GroupTask is one group task handle. | GroupTask 是一个 Group 任务句柄。
type GroupTask struct {
	err    error
	done   chan struct{}
	result *StepResult
	once   sync.Once
}

// Wait waits for the task or ctx. | Wait 等待任务或 ctx。
func (t *GroupTask) Wait(ctx context.Context) (*StepResult, error) {
	if t == nil {
		return nil, ErrInvalidRequest
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-t.done:
		return t.result, t.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// complete finishes the task exactly once. | complete 只完成任务一次。
func (t *GroupTask) complete(result *StepResult, err error) {
	t.once.Do(func() {
		t.result = result
		t.err = err
		close(t.done)
	})
}

// NewGroup creates a group bound to ctx. | NewGroup 创建绑定 ctx 的 Group。
func (c *Client) NewGroup(ctx context.Context, opts ...GroupOption) *Group {
	cfg := groupConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	maxParallel := cfg.maxParallel
	if maxParallel <= 0 && c != nil {
		maxParallel = c.opts.MaxParallel
	}
	if maxParallel <= 0 {
		maxParallel = 32
	}
	maxBody := cfg.maxBody
	if maxBody <= 0 {
		maxBody = 4 << 20
	}
	return &Group{
		ctx:     ctx,
		client:  c,
		sem:     make(chan struct{}, maxParallel),
		maxBody: maxBody,
		names:   make(map[string]struct{}),
		results: make(map[string]*StepResult),
	}
}

// GoRequest starts one HTTP task. | GoRequest 启动一个 HTTP 任务。
func (g *Group) GoRequest(name, method, rawURL string, body any, opts ...RequestOption) *GroupTask {
	task := &GroupTask{done: make(chan struct{})}
	if g == nil || g.client == nil {
		task.complete(&StepResult{Name: name, Err: ErrClosed}, ErrClosed)
		return task
	}
	if err := g.reserve(name); err != nil {
		task.complete(&StepResult{Name: name, Err: err}, err)
		return task
	}
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		start := time.Now()
		select {
		case g.sem <- struct{}{}:
		case <-g.ctx.Done():
			result := &StepResult{Name: name, Err: g.ctx.Err(), Duration: time.Since(start)}
			g.finish(name, result)
			task.complete(result, result.Err)
			return
		}
		resp, err := g.client.Send(g.ctx, method, rawURL, body, opts...)
		<-g.sem
		result := &StepResult{Name: name, Duration: time.Since(start)}
		if err != nil {
			result.Err = err
			g.finish(name, result)
			task.complete(result, err)
			return
		}
		data, err := resp.BytesLimit(g.maxBody)
		if err != nil {
			if errors.Is(err, ErrResponseTooLarge) {
				err = errs.Detail(ErrPipelineBodyTooLarge, "max %d bytes | 上限 %d 字节", g.maxBody, g.maxBody)
			}
			result.Status = resp.StatusCode
			result.Headers = resp.Header.Clone()
			result.Err = err
			g.finish(name, result)
			task.complete(result, err)
			return
		}
		copied := *resp.Response
		copied.Body = io.NopCloser(bytes.NewReader(data))
		copied.ContentLength = int64(len(data))
		result.Status = resp.StatusCode
		result.Headers = resp.Header.Clone()
		result.Body = data
		result.Response = &Response{Response: &copied, Meta: resp.Meta}
		result.Attempts = resp.Meta.Attempts
		g.finish(name, result)
		task.complete(result, nil)
	}()
	return task
}

// GoFunc starts one non-HTTP task. | GoFunc 启动一个非 HTTP 任务。
func (g *Group) GoFunc(name string, fn func(context.Context) error) *GroupTask {
	task := &GroupTask{done: make(chan struct{})}
	if g == nil {
		task.complete(&StepResult{Name: name, Err: ErrClosed}, ErrClosed)
		return task
	}
	if err := g.reserve(name); err != nil {
		task.complete(&StepResult{Name: name, Err: err}, err)
		return task
	}
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		start := time.Now()
		var runErr error
		if fn != nil {
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						runErr = errs.Detail(ErrHookPanic, "panic: %v | panic：%v", recovered, recovered)
					}
				}()
				runErr = fn(g.ctx)
			}()
		}
		result := &StepResult{Name: name, Err: runErr, Duration: time.Since(start)}
		g.finish(name, result)
		task.complete(result, runErr)
	}()
	return task
}

// Wait waits for every task and joins errors. | Wait 等待全部任务并聚合错误。
func (g *Group) Wait() error {
	if g == nil {
		return ErrClosed
	}
	g.wg.Wait()
	g.mu.Lock()
	errs := append([]error(nil), g.errs...)
	g.mu.Unlock()
	return errors.Join(errs...)
}

// Result returns one recorded result. | Result 返回一个已记录结果。
func (g *Group) Result(name string) (*StepResult, bool) {
	if g == nil {
		return nil, false
	}
	g.mu.Lock()
	result, ok := g.results[name]
	g.mu.Unlock()
	return result, ok
}

// Results returns a snapshot of all recorded results. | Results 返回全部已记录结果的快照。
func (g *Group) Results() map[string]*StepResult {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	results := make(map[string]*StepResult, len(g.results))
	for name, result := range g.results {
		results[name] = result
	}
	g.mu.Unlock()
	return results
}

// reserve claims a unique task name. | reserve 占用唯一任务名。
func (g *Group) reserve(name string) error {
	if name == "" {
		return errs.Detail(ErrPipelineStep, "empty group task name | 空 Group 任务名")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, exists := g.names[name]; exists {
		err := errs.Detail(ErrPipelineStep, "duplicate group task %q | 重复 Group 任务 %q", name, name)
		g.errs = append(g.errs, err)
		return err
	}
	g.names[name] = struct{}{}
	return nil
}

// finish records one task result. | finish 记录一个任务结果。
func (g *Group) finish(name string, result *StepResult) {
	g.mu.Lock()
	g.results[name] = result
	g.order = append(g.order, name)
	if result != nil && result.Err != nil {
		g.errs = append(g.errs, result.Err)
	}
	g.mu.Unlock()
}
