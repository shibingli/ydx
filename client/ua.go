package client

import (
	"math/rand/v2"
	"net/http"

	"github.com/shibingli/ydx/errs"
)

// UAMode names a User-Agent selection strategy. | UAMode 命名 User-Agent 选择策略。
type UAMode string

const (
	// UAFixed always sends the first configured User-Agent. | UAFixed 始终发送第一个配置的 User-Agent。
	UAFixed UAMode = "fixed"
	// UARandom picks a User-Agent randomly for each request. | UARandom 为每个请求随机选择 User-Agent。
	UARandom UAMode = "random"
	// UARotate cycles through the configured list. | UARotate 轮换配置列表。
	UARotate UAMode = "rotate"
	// UAWeighted picks a User-Agent by configured weights. | UAWeighted 按配置权重选择 User-Agent。
	UAWeighted UAMode = "weighted"
)

// builtinUserAgents are realistic desktop and mobile strings used when List is empty. | builtinUserAgents 是 List 为空时使用的真实桌面与移动 UA。
var builtinUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36",
}

// UAPolicy configures User-Agent simulation. | UAPolicy 配置 User-Agent 模拟。
type UAPolicy struct {
	// Companion headers are applied with the User-Agent when missing. | Companion 在缺失时随 User-Agent 一起应用。
	Companion http.Header
	// Mode selects the strategy; empty means random. | Mode 选择策略；为空表示随机。
	Mode UAMode
	// List overrides the built-in User-Agent list. | List 覆盖内置 User-Agent 列表。
	List []string
	// Weights matches List for weighted selection. | Weights 与 List 对应，用于加权选择。
	Weights []int
	// Force overwrites an explicitly set User-Agent. | Force 覆盖显式设置的 User-Agent。
	Force bool
}

// WithUserAgent enables User-Agent simulation. | WithUserAgent 启用 User-Agent 模拟。
func WithUserAgent(policy UAPolicy) Option {
	policy.List = append([]string(nil), policy.List...)
	policy.Weights = append([]int(nil), policy.Weights...)
	if policy.Companion != nil {
		policy.Companion = policy.Companion.Clone()
	}
	return func(o *options) error {
		cloned := policy
		o.UserAgent = &cloned
		return nil
	}
}

// prepareUA validates and defaults a User-Agent policy. | prepareUA 校验并补全 UA 策略。
func prepareUA(policy *UAPolicy) (*UAPolicy, error) {
	if policy == nil {
		return nil, nil
	}
	prepared := *policy
	prepared.List = append([]string(nil), policy.List...)
	prepared.Weights = append([]int(nil), policy.Weights...)
	if prepared.Mode == "" {
		prepared.Mode = UARandom
	}
	switch prepared.Mode {
	case UAFixed, UARandom, UARotate, UAWeighted:
	default:
		return nil, errs.Detail(ErrInvalidConfig, "unknown UA mode %q | 未知 UA 模式 %q", prepared.Mode, prepared.Mode)
	}
	if len(prepared.List) == 0 {
		prepared.List = append([]string(nil), builtinUserAgents...)
	}
	for _, ua := range prepared.List {
		if ua == "" {
			return nil, errs.Detail(ErrInvalidConfig, "empty User-Agent | 空 User-Agent")
		}
	}
	if len(prepared.Weights) > 0 {
		if len(prepared.Weights) != len(prepared.List) {
			return nil, errs.Detail(ErrInvalidConfig, "UA weights must match list length | UA 权重必须与列表长度一致")
		}
		for _, weight := range prepared.Weights {
			if weight < 0 {
				return nil, errs.Detail(ErrInvalidConfig, "negative UA weight | UA 权重为负")
			}
		}
	}
	if prepared.Companion != nil {
		prepared.Companion = prepared.Companion.Clone()
	}
	return &prepared, nil
}

// uaApplies reports whether applying policy would change req. | uaApplies 报告应用策略是否会改变 req。
func uaApplies(req *http.Request, policy *UAPolicy) bool {
	if req == nil || policy == nil {
		return false
	}
	if policy.Force || req.Header.Get("User-Agent") == "" {
		return true
	}
	for key := range policy.Companion {
		if req.Header.Get(key) == "" {
			return true
		}
	}
	return false
}

// applyUA sets the User-Agent on a request clone. | applyUA 在请求克隆上设置 User-Agent。
func (e *engine) applyUA(req *http.Request, policy *UAPolicy) {
	if req == nil || policy == nil {
		return
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	if !policy.Force && req.Header.Get("User-Agent") != "" {
		return
	}
	req.Header.Set("User-Agent", e.chooseUA(policy))
	for key, values := range policy.Companion {
		if !policy.Force && req.Header.Get(key) != "" {
			continue
		}
		for _, value := range values {
			req.Header.Set(key, value)
		}
	}
}

// chooseUA selects one User-Agent under the policy. | chooseUA 按策略选择一个 User-Agent。
func (e *engine) chooseUA(policy *UAPolicy) string {
	if len(policy.List) == 0 {
		return ""
	}
	switch policy.Mode {
	case UAFixed:
		return policy.List[0]
	case UARotate:
		index := (e.uaCounter.Add(1) - 1) % uint64(len(policy.List))
		return policy.List[index]
	case UAWeighted:
		if len(policy.Weights) == len(policy.List) {
			total := 0
			for _, weight := range policy.Weights {
				total += weight
			}
			if total > 0 {
				pick := rand.IntN(total)
				for i, weight := range policy.Weights {
					if pick < weight {
						return policy.List[i]
					}
					pick -= weight
				}
			}
		}
		return policy.List[rand.IntN(len(policy.List))]
	default:
		return policy.List[rand.IntN(len(policy.List))]
	}
}
