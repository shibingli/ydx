package cn

import (
	"context"

	"github.com/shibingli/ydx/errs"
)

// ErrRealNameProvider reports a transport, signing or decoding failure of a real-name provider. | ErrRealNameProvider 表示实名认证服务方的传输、签名或解码失败。
var ErrRealNameProvider = errs.New("cn: real-name provider failure | cn：实名认证服务方故障")

// RealNameRequest is one two- or three-factor real-name verification request. | RealNameRequest 是一次两要素或三要素实名认证请求。
type RealNameRequest struct {
	// Name is the person's legal name. | Name 是法定姓名。
	Name string `json:"name"`
	// IDNumber is the resident identity card number. | IDNumber 是居民身份证号码。
	IDNumber string `json:"idNumber"`
	// Mobile is the optional mobile number bound to the identity. | Mobile 是可选的身份绑定手机号。
	Mobile string `json:"mobile,omitempty"`
}

// RealNameResult is the provider's answer. | RealNameResult 是服务方的应答。
type RealNameResult struct {
	// Verified reports whether the provider matched the supplied factors. | Verified 表示服务方是否匹配了提交的要素。
	Verified bool `json:"verified"`
	// Provider identifies the verification service. | Provider 标识核验服务方。
	Provider string `json:"provider,omitempty"`
	// RequestID is the provider's trace identifier. | RequestID 是服务方的追踪标识。
	RequestID string `json:"requestId,omitempty"`
	// Message is a provider-supplied explanation that must not contain raw identity values. | Message 是服务方给出的说明，不得包含身份原文。
	Message string `json:"message,omitempty"`
}

// RealNameVerifier verifies a name against an identity number, optionally with a mobile number. | RealNameVerifier 用身份证号码核验姓名，可选附带手机号。
type RealNameVerifier interface {
	// Verify returns the provider result for req. A negative result is (result, nil), not an error;
	// errors are reserved for transport and provider failures. | Verify 返回 req 的服务方结果。
	// 核验不通过是 (result, nil) 而非错误；错误只用于传输与服务方故障。
	Verify(ctx context.Context, req RealNameRequest) (*RealNameResult, error)
}

// RealNameFunc adapts a function to RealNameVerifier. | RealNameFunc 把函数适配为 RealNameVerifier。
type RealNameFunc func(ctx context.Context, req RealNameRequest) (*RealNameResult, error)

// Verify calls f. A nil f returns ErrInvalidConfig. | Verify 调用 f。f 为 nil 时返回 ErrInvalidConfig。
func (f RealNameFunc) Verify(ctx context.Context, req RealNameRequest) (*RealNameResult, error) {
	if f == nil {
		return nil, errs.Detail(ErrInvalidConfig, "real-name verifier function is nil | 实名认证函数为空")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return f(ctx, req)
}

// StaticVerifier is a deterministic verifier for tests and offline flows. | StaticVerifier 是用于测试与离线流程的确定性核验器。
type StaticVerifier struct {
	// Result is returned on success. | Result 在成功时返回。
	Result RealNameResult
	// Err, when non-nil, is returned instead of Result. | Err 非空时返回它而不是 Result。
	Err error
}

// Verify returns a copy of the configured result or the configured error. | Verify 返回配置结果的副本或配置的错误。
func (v StaticVerifier) Verify(ctx context.Context, req RealNameRequest) (*RealNameResult, error) {
	if v.Err != nil {
		return nil, v.Err
	}
	result := v.Result
	if result.Provider == "" {
		result.Provider = "static"
	}
	return &result, nil
}
