package waf

import (
	"context"
	"net/http"
	"strconv"

	"github.com/shibingli/ydx/client"
	"github.com/shibingli/ydx/errs"
	ydxwaf "github.com/shibingli/ydx/waf"
)

// ErrNilEngine indicates a missing underlying WAF instance. | ErrNilEngine 表示缺少底层 WAF 实例。
var ErrNilEngine = errs.New("client/waf: nil WAF engine | client/waf：空 WAF 引擎")

// Options configures the WAF guard. | Options 配置 WAF 守卫。
type Options struct {
	// Engine is the underlying WAF instance. | Engine 是底层 WAF 实例。
	Engine *ydxwaf.WAF
	// InspectBody enables request body inspection; false leaves the body untouched. | InspectBody 启用请求正文检查；false 保持正文不动。
	InspectBody bool
	// FailOpen allows the request when Evaluate fails. | FailOpen 在 Evaluate 失败时放行。
	FailOpen bool
}

// Guard adapts a WAF instance into client.Guard. | Guard 把 WAF 实例适配为 client.Guard。
type Guard struct {
	engine      *ydxwaf.WAF
	inspectBody bool
	failOpen    bool
}

// New builds a WAF guard. | New 构建 WAF 守卫。
func New(o Options) (*Guard, error) {
	if o.Engine == nil {
		return nil, ErrNilEngine
	}
	return &Guard{engine: o.Engine, inspectBody: o.InspectBody, failOpen: o.FailOpen}, nil
}

// Check evaluates one logical request without writing a response. | Check 评估一个逻辑请求且不写响应。
func (g *Guard) Check(ctx context.Context, req *http.Request) (client.GuardDecision, error) {
	_ = ctx
	if g == nil || g.engine == nil {
		return client.GuardDecision{Allowed: false, Status: http.StatusServiceUnavailable, Message: "nil WAF guard"}, ErrNilEngine
	}
	inspectBody := g.inspectBody
	if inspectBody && req != nil {
		if _, capped := req.Body.(interface{ LimitedBody() }); capped {
			// Let the access policy enforce its streaming cap; consuming the
			// capped body here would turn a 413 into a body-loss fail-open. | 让访问
			// 策略执行流式上限；此处消费带限正文会把 413 变成丢失正文的放行。
			inspectBody = false
		}
	}
	var restore func()
	if !inspectBody && req != nil && req.Body != nil && req.Body != http.NoBody {
		original := req.Body
		req.Body = http.NoBody
		restore = func() { req.Body = original }
		defer restore()
	}
	decision, err := g.engine.Evaluate(req)
	if err != nil {
		if g.failOpen {
			return client.GuardDecision{Allowed: true}, nil
		}
		return client.GuardDecision{
			Allowed: false,
			Status:  decision.Status,
			RuleID:  decision.RuleID,
			Action:  decision.Action,
			Message: decision.Message,
		}, err
	}
	matched := make([]string, 0, len(decision.Matches))
	for _, match := range decision.Matches {
		matched = append(matched, strconv.Itoa(match.RuleID))
	}
	return client.GuardDecision{
		Allowed: !decision.Blocked,
		Status:  decision.Status,
		RuleID:  decision.RuleID,
		Action:  decision.Action,
		Message: decision.Message,
		Matched: matched,
	}, nil
}
