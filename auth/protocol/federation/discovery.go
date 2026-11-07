package federation

import (
	"math/rand/v2"
	"time"
)

// discoveryPolicy is the effective OIDC discovery cache policy assembled from
// provider and broker settings. | discoveryPolicy 是由提供方与代理设置合并得到的生效
// OIDC 发现缓存策略。
type discoveryPolicy struct {
	ttl      time.Duration
	minTTL   time.Duration
	maxTTL   time.Duration
	maxStale time.Duration
	jitter   float64
}

// enabled reports whether periodic discovery refresh is configured. | enabled 报告是否
// 配置了周期性发现刷新。
func (p discoveryPolicy) enabled() bool {
	return p.ttl > 0
}

// effectiveTTL clamps the configured TTL into the configured bounds. | effectiveTTL 把
// 配置的 TTL 限制在配置的上下界内。
func (p discoveryPolicy) effectiveTTL() time.Duration {
	ttl := p.ttl
	if ttl <= 0 {
		return 0
	}
	if p.minTTL > 0 && ttl < p.minTTL {
		ttl = p.minTTL
	}
	if p.maxTTL > 0 && ttl > p.maxTTL {
		ttl = p.maxTTL
	}
	return ttl
}

// nextTTL returns one jittered cache lifetime. Jitter is a fraction of the effective
// TTL and is clamped back into the configured bounds. | nextTTL 返回一个带抖动的缓存
// 有效期。抖动是生效 TTL 的比例，并会被重新限制到配置的上下界内。
func (p discoveryPolicy) nextTTL() time.Duration {
	ttl := p.effectiveTTL()
	if ttl <= 0 {
		return 0
	}
	if p.jitter > 0 {
		offset := (rand.Float64()*2 - 1) * p.jitter
		ttl = time.Duration(float64(ttl) * (1 + offset))
	}
	if p.minTTL > 0 && ttl < p.minTTL {
		ttl = p.minTTL
	}
	if p.maxTTL > 0 && ttl > p.maxTTL {
		ttl = p.maxTTL
	}
	if ttl <= 0 {
		ttl = time.Nanosecond
	}
	return ttl
}

// problem reports a cross-field configuration conflict. Empty strings mean the policy
// is usable. | problem 报告跨字段配置冲突；返回空字符串表示策略可用。
func (p discoveryPolicy) problem() (string, string) {
	if p.minTTL > 0 && p.maxTTL > 0 && p.minTTL > p.maxTTL {
		return "DiscoveryTTLMin exceeds DiscoveryTTLMax", "DiscoveryTTLMin 大于 DiscoveryTTLMax"
	}
	return "", ""
}

// discoverySettingsProblem validates raw discovery fields. Empty strings mean valid.
// discoverySettingsProblem 校验原始发现字段；返回空字符串表示合法。
func discoverySettingsProblem(ttl, minTTL, maxTTL time.Duration, jitter float64) (string, string) {
	switch {
	case ttl < 0:
		return "DiscoveryTTL must not be negative", "DiscoveryTTL 不能为负"
	case minTTL < 0:
		return "DiscoveryTTLMin must not be negative", "DiscoveryTTLMin 不能为负"
	case maxTTL < 0:
		return "DiscoveryTTLMax must not be negative", "DiscoveryTTLMax 不能为负"
	case jitter < 0 || jitter > 1:
		return "DiscoveryJitter must be between 0 and 1", "DiscoveryJitter 必须介于 0 与 1 之间"
	case minTTL > 0 && maxTTL > 0 && minTTL > maxTTL:
		return "DiscoveryTTLMin exceeds DiscoveryTTLMax", "DiscoveryTTLMin 大于 DiscoveryTTLMax"
	default:
		return "", ""
	}
}

// discoveryPolicyFor merges provider-level discovery settings over broker defaults.
// Zero provider values inherit the broker value; a negative provider DiscoveryMaxStale
// explicitly disables stale fallback. | discoveryPolicyFor 把提供方级发现设置合并到代理
// 默认值之上。提供方零值继承代理值；提供方 DiscoveryMaxStale 为负时显式禁用过期回退。
func discoveryPolicyFor(b *Broker, p *Provider) discoveryPolicy {
	var policy discoveryPolicy
	if b != nil {
		policy = discoveryPolicy{
			ttl:      b.DiscoveryTTL,
			minTTL:   b.DiscoveryTTLMin,
			maxTTL:   b.DiscoveryTTLMax,
			maxStale: b.DiscoveryMaxStale,
			jitter:   b.DiscoveryJitter,
		}
	}
	if p == nil {
		return policy
	}
	if p.DiscoveryTTL != 0 {
		policy.ttl = p.DiscoveryTTL
	}
	if p.DiscoveryTTLMin != 0 {
		policy.minTTL = p.DiscoveryTTLMin
	}
	if p.DiscoveryTTLMax != 0 {
		policy.maxTTL = p.DiscoveryTTLMax
	}
	if p.DiscoveryMaxStale != 0 {
		policy.maxStale = p.DiscoveryMaxStale
	}
	if p.DiscoveryJitter != 0 {
		policy.jitter = p.DiscoveryJitter
	}
	return policy
}
