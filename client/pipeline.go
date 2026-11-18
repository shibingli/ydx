package client

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Node is one pipeline execution unit. | Node 是一个 Pipeline 执行单元。
type Node interface {
	run(*runState) error
}

// PipelineOptions configures a Pipeline. | PipelineOptions 配置 Pipeline。
type PipelineOptions struct {
	// Hooks observes step transitions. | Hooks 观测步骤状态。
	Hooks PipelineHooks
	// Timeout bounds the whole pipeline; <=0 disables it. | Timeout 限制整个 Pipeline；<=0 禁用。
	Timeout time.Duration
	// MaxBodyBytes caps each step body; <=0 means 4 MiB. | MaxBodyBytes 限制步骤正文；<=0 表示 4 MiB。
	MaxBodyBytes int64
	// MaxParallel caps concurrent HTTP steps; 0 uses the client limit. | MaxParallel 限制并发 HTTP 步骤；0 使用客户端上限。
	MaxParallel int
	// ContinueOnError runs remaining nodes after a failure; zero is fail-fast. | ContinueOnError 在失败后继续运行剩余节点；零值为快速失败。
	ContinueOnError bool
}

// PipelineHooks observes pipeline execution. | PipelineHooks 观测 Pipeline 执行。
type PipelineHooks struct {
	// OnStepStart runs when a step begins. | OnStepStart 在步骤开始时运行。
	OnStepStart func(context.Context, string)
	// OnStepDone runs when a step finishes, including failures. | OnStepDone 在步骤完成时运行（含失败）。
	OnStepDone func(context.Context, *StepResult)
	// OnSkip runs when a step is skipped. | OnSkip 在步骤跳过时运行。
	OnSkip func(context.Context, string)
	// OnComplete runs after the pipeline finishes. | OnComplete 在 Pipeline 完成后运行。
	OnComplete func(context.Context, *PipelineResult)
}

// StepResult is the recorded outcome of one step. | StepResult 是一个步骤的记录结果。
type StepResult struct {
	// Err is the step error. | Err 是步骤错误。
	Err error
	// Headers are the response headers. | Headers 是响应头。
	Headers http.Header
	// Response is a replayable response view. | Response 是可重放的响应视图。
	Response *Response
	// Name is the step name. | Name 是步骤名。
	Name string
	// Body is the buffered response body. | Body 是缓冲的响应正文。
	Body []byte
	// Status is the response status code, or zero. | Status 是响应状态码（或 0）。
	Status int
	// Duration is the step duration. | Duration 是步骤耗时。
	Duration time.Duration
	// Attempts is the number of upstream attempts. | Attempts 是上游尝试次数。
	Attempts int
	// Skipped reports a When condition that skipped the step. | Skipped 报告 When 条件跳过步骤。
	Skipped bool
}

// PipelineResult is the snapshot returned by Run. | PipelineResult 是 Run 返回的快照。
type PipelineResult struct {
	// Vars is the final variable snapshot. | Vars 是最终变量快照。
	Vars *Vars
	// Steps maps step names to results. | Steps 把步骤名映射到结果。
	Steps map[string]*StepResult
	// Order records step completion order. | Order 记录步骤完成顺序。
	Order []string
	// Duration is the total pipeline duration. | Duration 是 Pipeline 总耗时。
	Duration time.Duration
}

// PipelineError wraps one failed step. | PipelineError 包装一个失败步骤。
type PipelineError struct {
	// Err is the underlying cause. | Err 是底层原因。
	Err error
	// Step is the failed step name. | Step 是失败步骤名。
	Step string
}

// Error implements error. | Error 实现 error 接口。
func (e *PipelineError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return "pipeline step " + e.Step + ": " + e.Err.Error()
}

// Unwrap returns the underlying cause. | Unwrap 返回底层原因。
func (e *PipelineError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Pipeline executes a tree of serial and parallel steps. | Pipeline 执行串行与并行步骤树。
type Pipeline struct {
	opts  PipelineOptions
	nodes []Node
}

// NewPipeline builds a pipeline with options and top-level nodes. | NewPipeline 用选项与顶层节点构建 Pipeline。
func NewPipeline(opts PipelineOptions, nodes ...Node) *Pipeline {
	return &Pipeline{nodes: nodes, opts: opts}
}

// Add appends top-level nodes. | Add 追加顶层节点。
func (p *Pipeline) Add(nodes ...Node) *Pipeline {
	if p != nil {
		p.nodes = append(p.nodes, nodes...)
	}
	return p
}

// Run executes the pipeline against c. | Run 在 c 上执行 Pipeline。
func (p *Pipeline) Run(ctx context.Context, c *Client) (*PipelineResult, error) {
	if p == nil || c == nil {
		return nil, errs.Detail(ErrPipelineStep, "nil pipeline or client | 空 Pipeline 或客户端")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	start := time.Now()
	var cancel context.CancelFunc
	if p.opts.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, p.opts.Timeout)
		defer cancel()
	}
	if err := validateNodes(p.nodes...); err != nil {
		return &PipelineResult{Vars: NewVars(), Steps: make(map[string]*StepResult)}, err
	}
	maxParallel := p.opts.MaxParallel
	if maxParallel <= 0 {
		maxParallel = c.opts.MaxParallel
	}
	if maxParallel <= 0 {
		maxParallel = 32
	}
	shared := &runShared{
		client:  c,
		vars:    NewVars(),
		results: make(map[string]*StepResult),
		limit:   make(chan struct{}, maxParallel),
		opts:    p.opts,
		hooks:   p.opts.Hooks,
	}
	rs := &runState{ctx: ctx, shared: shared}
	var errs []error
	for _, node := range p.nodes {
		if err := node.run(rs); err != nil {
			errs = append(errs, err)
			if !p.opts.ContinueOnError {
				break
			}
		}
	}
	result := shared.snapshot(time.Since(start))
	if p.opts.Hooks.OnComplete != nil {
		p.opts.Hooks.OnComplete(ctx, result)
	}
	return result, errors.Join(errs...)
}

// runShared is the mutable state shared by every node in one run. | runShared 是一次运行中所有节点共享的可变状态。
type runShared struct {
	opts    PipelineOptions
	hooks   PipelineHooks
	client  *Client
	vars    *Vars
	results map[string]*StepResult
	limit   chan struct{}
	order   []string
	mu      sync.Mutex
}

// runState is one node's context plus the shared run state. | runState 是一个节点的 context 与共享运行状态。
type runState struct {
	ctx    context.Context
	shared *runShared
}

// withContext derives a sibling run state sharing all mutable state. | withContext 派生共享全部可变状态的兄弟状态。
func (rs *runState) withContext(ctx context.Context) *runState {
	return &runState{ctx: ctx, shared: rs.shared}
}

// acquire takes one parallel HTTP slot. | acquire 获取一个并行 HTTP 名额。
func (rs *runState) acquire(ctx context.Context) error {
	select {
	case rs.shared.limit <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// release returns one parallel HTTP slot. | release 归还一个并行 HTTP 名额。
func (rs *runState) release() {
	<-rs.shared.limit
}

// record stores a step result and completion order. | record 存储步骤结果与完成顺序。
func (rs *runState) record(result *StepResult) {
	if result == nil {
		return
	}
	shared := rs.shared
	shared.mu.Lock()
	if _, exists := shared.results[result.Name]; !exists {
		shared.order = append(shared.order, result.Name)
	}
	shared.results[result.Name] = result
	shared.mu.Unlock()
}

// snapshot builds the final result. | snapshot 构建最终结果。
func (s *runShared) snapshot(duration time.Duration) *PipelineResult {
	s.mu.Lock()
	results := make(map[string]*StepResult, len(s.results))
	for name, result := range s.results {
		results[name] = result
	}
	order := append([]string(nil), s.order...)
	vars := s.vars.Clone()
	s.mu.Unlock()
	return &PipelineResult{Vars: vars, Steps: results, Order: order, Duration: duration}
}

// stepStart fires OnStepStart. | stepStart 触发 OnStepStart。
func (rs *runState) stepStart(name string) {
	if rs.shared.hooks.OnStepStart != nil {
		rs.shared.hooks.OnStepStart(rs.ctx, name)
	}
}

// stepDone fires OnStepDone. | stepDone 触发 OnStepDone。
func (rs *runState) stepDone(result *StepResult) {
	if rs.shared.hooks.OnStepDone != nil && result != nil {
		rs.shared.hooks.OnStepDone(rs.ctx, result)
	}
}

// stepSkip fires OnSkip. | stepSkip 触发 OnSkip。
func (rs *runState) stepSkip(name string) {
	if rs.shared.hooks.OnSkip != nil {
		rs.shared.hooks.OnSkip(rs.ctx, name)
	}
}

// serialNode runs nodes in order. | serialNode 顺序运行节点。
type serialNode struct {
	nodes []Node
}

// Serial groups nodes in order. | Serial 按顺序组合节点。
func Serial(nodes ...Node) Node {
	return &serialNode{nodes: nodes}
}

// run implements Node. | run 实现 Node。
func (s *serialNode) run(rs *runState) error {
	var errs []error
	for _, node := range s.nodes {
		if err := node.run(rs); err != nil {
			errs = append(errs, err)
			if !rs.shared.opts.ContinueOnError {
				break
			}
		}
	}
	return errors.Join(errs...)
}

// parallelNode runs nodes concurrently. | parallelNode 并发运行节点。
type parallelNode struct {
	nodes []Node
}

// Parallel groups nodes concurrently. | Parallel 并发组合节点。
func Parallel(nodes ...Node) Node {
	return &parallelNode{nodes: nodes}
}

// run implements Node. | run 实现 Node。
func (p *parallelNode) run(rs *runState) error {
	ctx, cancel := context.WithCancel(rs.ctx)
	defer cancel()
	sub := rs.withContext(ctx)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error
	for _, node := range p.nodes {
		wg.Add(1)
		go func(node Node) {
			defer wg.Done()
			if err := node.run(sub); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				if !rs.shared.opts.ContinueOnError {
					cancel()
				}
			}
		}(node)
	}
	wg.Wait()
	return errors.Join(errs...)
}

// funcNode runs an arbitrary function. | funcNode 运行任意函数。
type funcNode struct {
	fn   func(context.Context, *Vars) error
	name string
}

// Func creates a non-HTTP step. | Func 创建非 HTTP 步骤。
func Func(name string, fn func(context.Context, *Vars) error) Node {
	return &funcNode{name: name, fn: fn}
}

// run implements Node. | run 实现 Node。
func (f *funcNode) run(rs *runState) error {
	if f == nil || f.name == "" {
		return errs.Detail(ErrPipelineStep, "empty function step | 空函数步骤")
	}
	start := time.Now()
	rs.stepStart(f.name)
	var runErr error
	if f.fn == nil {
		runErr = errs.Detail(ErrPipelineStep, "nil function step %q | 空函数步骤 %q", f.name, f.name)
	} else {
		runErr = f.fn(rs.ctx, rs.shared.vars)
	}
	result := &StepResult{Name: f.name, Err: runErr, Duration: time.Since(start)}
	rs.record(result)
	rs.stepDone(result)
	if runErr != nil {
		return &PipelineError{Step: f.name, Err: runErr}
	}
	return nil
}

// validateNodes rejects empty and duplicate step names. | validateNodes 拒绝空名与重复步骤名。
func validateNodes(nodes ...Node) error {
	seen := make(map[string]bool)
	var walk func(Node) error
	walk = func(node Node) error {
		switch typed := node.(type) {
		case *StepBuilder:
			if typed == nil {
				return errs.Detail(ErrPipelineStep, "nil step | 空步骤")
			}
			return registerStepName(typed.name, seen)
		case *funcNode:
			if typed == nil {
				return errs.Detail(ErrPipelineStep, "nil function step | 空函数步骤")
			}
			return registerStepName(typed.name, seen)
		case *serialNode:
			if typed == nil {
				return errs.Detail(ErrPipelineStep, "nil serial node | 空串行节点")
			}
			for _, child := range typed.nodes {
				if err := walk(child); err != nil {
					return err
				}
			}
		case *parallelNode:
			if typed == nil {
				return errs.Detail(ErrPipelineStep, "nil parallel node | 空并行节点")
			}
			for _, child := range typed.nodes {
				if err := walk(child); err != nil {
					return err
				}
			}
		case nil:
			return errs.Detail(ErrPipelineStep, "nil pipeline node | 空 Pipeline 节点")
		default:
			return errs.Detail(ErrPipelineStep, "unknown pipeline node | 未知 Pipeline 节点")
		}
		return nil
	}
	for _, node := range nodes {
		if err := walk(node); err != nil {
			return err
		}
	}
	return nil
}

// registerStepName adds one name to the seen set. | registerStepName 把一个名字加入集合。
func registerStepName(name string, seen map[string]bool) error {
	if name == "" {
		return errs.Detail(ErrPipelineStep, "empty step name | 空步骤名")
	}
	if seen[name] {
		return errs.Detail(ErrPipelineStep, "duplicate step name %q | 重复步骤名 %q", name, name)
	}
	seen[name] = true
	return nil
}
