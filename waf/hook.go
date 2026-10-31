package waf

import (
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
)

// HookPoint identifies a lifecycle event delivered to hooks and plugins. | HookPoint 标识投递给
// 钩子与插件的生命周期事件。
type HookPoint uint8

// Lifecycle hook points. | 生命周期钩子点。
const (
	HookBeforePhase HookPoint = iota
	HookAfterPhase
	HookRuleMatch
	HookBeforeInterrupt
	HookAfterInterrupt
	HookReload
	HookPluginError
	HookRequestComplete
)

// hookPointCount is the number of lifecycle hook points. | hookPointCount 是生命周期钩子点数量。
const hookPointCount = int(HookRequestComplete) + 1

// String returns the hook point name used in logs. | String 返回日志中使用的钩子点名称。
func (p HookPoint) String() string {
	switch p {
	case HookBeforePhase:
		return "before_phase"
	case HookAfterPhase:
		return "after_phase"
	case HookRuleMatch:
		return "rule_match"
	case HookBeforeInterrupt:
		return "before_interrupt"
	case HookAfterInterrupt:
		return "after_interrupt"
	case HookReload:
		return "reload"
	case HookPluginError:
		return "plugin_error"
	case HookRequestComplete:
		return "request_complete"
	default:
		return "unknown"
	}
}

// Hook handles one lifecycle event. Implementations must be safe for concurrent use.
// | Hook 处理一个生命周期事件；实现必须并发安全。
type Hook interface {
	Name() string
	Priority() int
	Handle(*HookContext) error
}

// HookFunc adapts a function to Hook. | HookFunc 把函数适配为 Hook。
type HookFunc struct {
	Fn       func(*HookContext) error
	HookName string
	// HookPoints restricts the hook to selected points; empty selects every point.
	// | HookPoints 把钩子限定到选定的点；为空选择全部。
	HookPoints   []HookPoint
	HookPriority int
}

// Name returns the configured hook name. | Name 返回配置的钩子名称。
func (h HookFunc) Name() string {
	if h.HookName == "" {
		return "hook"
	}
	return h.HookName
}

// Priority returns the configured ordering priority. | Priority 返回配置的排序优先级。
func (h HookFunc) Priority() int { return h.HookPriority }

// Points implements pointSubscriber. | Points 实现 pointSubscriber。
func (h HookFunc) Points() []HookPoint { return h.HookPoints }

// Handle calls the function. | Handle 调用函数。
func (h HookFunc) Handle(ctx *HookContext) error {
	if h.Fn == nil {
		return nil
	}
	return h.Fn(ctx)
}

// HookContext is the request-scoped view delivered to hooks. It is valid only during the call.
// | HookContext 是投递给钩子的请求级视图，仅在调用期间有效。
type HookContext struct {
	Err error

	Tx           *Transaction
	Request      *http.Request
	Rule         *Rule
	Match        *Match
	Interruption *Interruption

	tx      *transaction
	Version string
	Point   HookPoint
	Phase   Phase
}

// GetVar returns a TX variable value. | GetVar 返回 TX 变量取值。
func (h *HookContext) GetVar(name string) string {
	if h == nil || h.tx == nil {
		return ""
	}
	return h.tx.lastTX(name)
}

// SetVar replaces a TX variable. | SetVar 替换 TX 变量。
func (h *HookContext) SetVar(name, value string) {
	if h == nil || h.tx == nil {
		return
	}
	h.tx.setTXValue(name, value, 0)
}

// AddVar appends a TX variable value. | AddVar 追加 TX 变量取值。
func (h *HookContext) AddVar(name, value string) {
	if h == nil || h.tx == nil {
		return
	}
	h.tx.addTX(name, value, 0)
}

// DeleteVar removes a TX variable. | DeleteVar 删除 TX 变量。
func (h *HookContext) DeleteVar(name string) {
	if h == nil || h.tx == nil {
		return
	}
	h.tx.deleteTX(name)
}

// Deny requests interruption with the given status. A zero status selects 403. | Deny 以指定状态
// 请求中断；状态为零时选择 403。
func (h *HookContext) Deny(status int, message string) {
	if h == nil {
		return
	}
	if status <= 0 {
		status = http.StatusForbidden
	}
	interruption := h.Interruption
	if interruption == nil {
		interruption = &Interruption{}
	}
	interruption.Action = "deny"
	interruption.Status = status
	interruption.Message = message
	interruption.Phase = h.Phase
	if h.Rule != nil {
		interruption.RuleID = h.Rule.ID
		interruption.Severity = h.Rule.Severity
		interruption.Tags = h.Rule.Tags
	}
	h.Interruption = interruption
	if h.tx != nil {
		h.tx.interruption = interruption
	}
}

// Drop requests a connection drop with the given status. A zero status selects 403.
// | Drop 以指定状态请求断开连接；状态为零时选择 403。
func (h *HookContext) Drop(status int, message string) {
	h.Deny(status, message)
	if h.Interruption != nil {
		h.Interruption.Action = "drop"
	}
}

// hookSet is an immutable hook list grouped by point. | hookSet 是按事件点分组的不可变钩子列表。
type hookSet struct {
	points [hookPointCount][]Hook
}

// buildHookSet sorts hooks by priority, stable within equal priorities. | buildHookSet 按优先级排序，
// 相同优先级保持注册顺序。
func buildHookSet(hooks []Hook) *hookSet {
	set := &hookSet{}
	byPoint := make([][]Hook, hookPointCount)
	for _, hook := range hooks {
		if hook == nil {
			continue
		}
		// A hook without a point subscription is registered for every point.
		// | 未声明事件点订阅的钩子会注册到所有事件点。
		if subscriber, ok := hook.(pointSubscriber); ok {
			if subscribed := subscriber.Points(); len(subscribed) > 0 {
				for _, point := range subscribed {
					if int(point) < hookPointCount {
						byPoint[point] = append(byPoint[point], hook)
					}
				}
				continue
			}
		}
		for point := range byPoint {
			byPoint[point] = append(byPoint[point], hook)
		}
	}
	for point := range byPoint {
		sort.SliceStable(byPoint[point], func(i, j int) bool {
			return byPoint[point][i].Priority() < byPoint[point][j].Priority()
		})
		set.points[point] = byPoint[point]
	}
	return set
}

// pointSubscriber lets a hook restrict itself to selected points. | pointSubscriber 让钩子限定到
// 选定的事件点。
type pointSubscriber interface {
	Points() []HookPoint
}

// hookRegistry owns the mutable hook configuration and the immutable serving snapshot.
// | hookRegistry 持有可变钩子配置与不可变服务快照。
type hookRegistry struct {
	current  atomic.Pointer[hookSet]
	logger   *log.Logger
	counters *counters
	hooks    []Hook
	timeout  time.Duration

	mu sync.Mutex
}

// newHookRegistry builds a registry and its initial snapshot. | newHookRegistry 构建注册表及其初始快照。
func newHookRegistry(hooks []Hook, logger *log.Logger, counters *counters, timeout time.Duration) *hookRegistry {
	registry := &hookRegistry{logger: logger, counters: counters, timeout: timeout}
	registry.hooks = append([]Hook(nil), hooks...)
	registry.current.Store(buildHookSet(registry.hooks))
	return registry
}

// Add registers a hook. It reports ErrInvalidOption for a nil or unnamed hook and a duplicate name.
// | Add 注册钩子；对空钩子、无名称或重名钩子返回 ErrInvalidOption。
func (r *hookRegistry) Add(hook Hook) error {
	if hook == nil || hook.Name() == "" {
		return ErrInvalidOption
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.hooks {
		if existing.Name() == hook.Name() {
			return errs.Detail(ErrInvalidOption, "duplicate hook %q | 重复的钩子 %q", hook.Name(), hook.Name())
		}
	}
	r.hooks = append(r.hooks, hook)
	r.current.Store(buildHookSet(r.hooks))
	return nil
}

// Remove removes every hook with the given name. | Remove 删除所有指定名称的钩子。
func (r *hookRegistry) Remove(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	kept := r.hooks[:0]
	removed := false
	for _, hook := range r.hooks {
		if hook.Name() == name {
			removed = true
			continue
		}
		kept = append(kept, hook)
	}
	r.hooks = kept
	r.current.Store(buildHookSet(r.hooks))
	return removed
}

// Replace replaces the whole hook list. | Replace 替换整个钩子列表。
func (r *hookRegistry) Replace(hooks []Hook) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hooks = append([]Hook(nil), hooks...)
	r.current.Store(buildHookSet(r.hooks))
}

// has reports whether any hook subscribes to a point. | has 报告是否有钩子订阅某个事件点。
func (r *hookRegistry) has(point HookPoint) bool {
	if r == nil || int(point) >= hookPointCount {
		return false
	}
	set := r.current.Load()
	return set != nil && len(set.points[point]) > 0
}

// run dispatches one hook event. Panics and errors are isolated and counted.
// | run 分派一个钩子事件；panic 与错误会被隔离并计数。
func (r *hookRegistry) run(ctx *HookContext) {
	if r == nil || ctx == nil {
		return
	}
	set := r.current.Load()
	if set == nil || int(ctx.Point) >= hookPointCount {
		return
	}
	hooks := set.points[ctx.Point]
	for _, hook := range hooks {
		r.invoke(hook, ctx)
	}
}

// invoke calls one hook with panic isolation. | invoke 在 panic 隔离下调用一个钩子。
func (r *hookRegistry) invoke(hook Hook, ctx *HookContext) {
	start := time.Now()
	defer func() {
		if recovered := recover(); recovered != nil {
			if r.counters != nil {
				r.counters.errors.Add(1)
			}
			r.logger.Error("waf hook panicked | WAF 钩子发生 panic",
				log.Str("hook", hook.Name()), log.Any("panic", recovered))
		}
		if r.timeout > 0 && time.Since(start) > r.timeout {
			r.logger.Warn("waf hook exceeded timeout | WAF 钩子超过超时时间",
				log.Str("hook", hook.Name()), log.Dur("duration", time.Since(start)),
				log.Dur("timeout", r.timeout))
		}
	}()
	if err := hook.Handle(ctx); err != nil {
		if r.counters != nil {
			r.counters.errors.Add(1)
		}
		r.logger.Error("waf hook failed | WAF 钩子失败",
			log.Str("hook", hook.Name()), log.Err(err))
	}
}
