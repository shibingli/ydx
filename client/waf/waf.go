package waf

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/shibingli/ydx/client"
	"github.com/shibingli/ydx/errs"
	ydxwaf "github.com/shibingli/ydx/waf"
)

// ErrNilEngine indicates a missing underlying WAF instance. | ErrNilEngine 表示缺少底层 WAF 实例。
var ErrNilEngine = errs.New("client/waf: nil WAF engine | client/waf：空 WAF 引擎")

// ErrBodyInspect indicates that the request body could not be buffered for
// inspection. | ErrBodyInspect 表示无法为检查缓冲请求正文。
var ErrBodyInspect = errs.New("client/waf: body inspection failed | client/waf：请求正文检查失败")

// maxInspectBody bounds the request-body prefix buffered for inspection. | maxInspectBody
// 限制为检查而缓冲的请求正文前缀。
const maxInspectBody = 1 << 20

// replayBody replays a buffered prefix before continuing with the original
// body. | replayBody 先重放缓存的正文前缀，再继续读取原始正文。
type replayBody struct {
	prefix []byte
	rest   io.ReadCloser
}

// Read reads the prefix first, then the original body. | Read 先读前缀，再读原始正文。
func (b *replayBody) Read(p []byte) (int, error) {
	if len(b.prefix) > 0 {
		n := copy(p, b.prefix)
		b.prefix = b.prefix[n:]
		return n, nil
	}
	return b.rest.Read(p)
}

// Close closes the original body. | Close 关闭原始正文。
func (b *replayBody) Close() error { return b.rest.Close() }

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
	var restore func()
	if g.inspectBody && req != nil && req.Body != nil && req.Body != http.NoBody {
		// Buffer a bounded prefix for inspection and replay it before the
		// original stream so the upstream still receives every byte. | 为检查缓冲
		// 有界前缀，并在原始流之前重放，确保上游仍收到全部字节。
		original := req.Body
		originalLength := req.ContentLength
		prefix, readErr := io.ReadAll(io.LimitReader(original, maxInspectBody))
		if readErr != nil {
			_ = original.Close()
			if errors.Is(readErr, client.ErrRequestTooLarge) {
				return client.GuardDecision{}, readErr
			}
			return client.GuardDecision{}, errs.Wrap(readErr, ErrBodyInspect)
		}
		req.Body = io.NopCloser(bytes.NewReader(prefix))
		req.ContentLength = int64(len(prefix))
		restore = func() {
			req.Body = &replayBody{prefix: prefix, rest: original}
			req.ContentLength = originalLength
		}
		defer restore()
	} else if req != nil && req.Body != nil && req.Body != http.NoBody {
		original := req.Body
		originalLength := req.ContentLength
		req.Body = http.NoBody
		req.ContentLength = 0
		restore = func() {
			req.Body = original
			req.ContentLength = originalLength
		}
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
