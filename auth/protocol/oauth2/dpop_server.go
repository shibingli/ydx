package oauth2

import (
	"context"
	"net/http"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// tokenDPoPContextKey carries the token-endpoint proof verified before grant processing. |
// tokenDPoPContextKey 携带在授权处理之前完成的令牌端点证明校验结果。
type tokenDPoPContextKey struct{}

// tokenDPoPProof is the result of token-endpoint proof pre-verification. | tokenDPoPProof 是令牌
// 端点证明预校验的结果。
type tokenDPoPProof struct {
	// jkt is the verified proof thumbprint. | jkt 是已校验的证明指纹。
	jkt string
	// verified reports whether a proof was present and verified. | verified 报告是否提供了证明并
	// 通过校验。
	verified bool
}

// preverifyTokenDPoP verifies the optional token-endpoint proof before any grant consumes
// single-use state, so a use_dpop_nonce challenge never destroys an authorization code or device
// code that the client is about to retry. | preverifyTokenDPoP 在任何授权消费一次性状态之前校验
// 可选的令牌端点证明，因此 use_dpop_nonce 挑战绝不会销毁客户端即将重试的授权码或设备码。
func (s *Server) preverifyTokenDPoP(r *http.Request) (*http.Request, error) {
	if r == nil {
		return nil, errs.Detail(ErrInvalidRequest, "request is nil | 请求为空")
	}
	jkt, err := s.dpopForTokenRequest(r.Context(), r, "", "")
	if err != nil {
		return nil, err
	}
	verified := strings.TrimSpace(r.Header.Get("DPoP")) != ""
	if verified && jkt == "" {
		return nil, errs.Detail(ErrInvalidDPoPProof, "verifier returned an empty thumbprint | 校验器返回空指纹")
	}
	proof := tokenDPoPProof{jkt: jkt, verified: verified}
	return r.WithContext(context.WithValue(r.Context(), tokenDPoPContextKey{}, proof)), nil
}

// dpopForTokenRequest validates an optional DPoP proof on a token request. | dpopForTokenRequest
// 校验令牌请求上的可选 DPoP 证明。
//
// expectedJKT is non-empty when the authorization code or refresh token was already bound to a key;
// the proof must then present the same thumbprint. When Server.Token already verified the proof, the
// cached result is reused so the proof jti is not rejected as a replay and a challenge cannot occur
// after a grant was consumed. | 当授权码或刷新令牌已绑定密钥时 expectedJKT 非空；此时证明必须呈现
// 相同指纹。当 Server.Token 已校验证明时复用缓存结果，避免证明 jti 被当作重放拒绝，也避免在授权
// 被消费后才出现挑战。
func (s *Server) dpopForTokenRequest(ctx context.Context, r *http.Request, expectedJKT, accessToken string) (string, error) {
	if ctx != nil {
		if pre, ok := ctx.Value(tokenDPoPContextKey{}).(tokenDPoPProof); ok {
			if !pre.verified {
				if expectedJKT != "" {
					return "", errs.Detail(ErrInvalidDPoPProof, "bound token requires a DPoP proof | 绑定令牌要求 DPoP 证明")
				}
				if s.config.DPoPRequired {
					return "", errs.Detail(ErrInvalidDPoPProof, "DPoP proof is required | 必须提供 DPoP 证明")
				}
				return "", nil
			}
			if expectedJKT != "" && pre.jkt != expectedJKT {
				return "", errs.Detail(ErrInvalidDPoPProof, "DPoP thumbprint does not match the bound key | DPoP 指纹与绑定密钥不匹配")
			}
			return pre.jkt, nil
		}
	}
	proof := ""
	if r != nil {
		proof = strings.TrimSpace(r.Header.Get("DPoP"))
	}
	if proof == "" {
		if expectedJKT != "" {
			return "", errs.Detail(ErrInvalidDPoPProof, "bound token requires a DPoP proof | 绑定令牌要求 DPoP 证明")
		}
		if s.config.DPoPRequired {
			return "", errs.Detail(ErrInvalidDPoPProof, "DPoP proof is required | 必须提供 DPoP 证明")
		}
		return "", nil
	}
	if s.config.DPoPVerifier == nil {
		return "", errs.Detail(ErrInvalidDPoPProof, "DPoP verifier is not configured | 未配置 DPoP 校验器")
	}
	jkt, err := s.config.DPoPVerifier.VerifyProof(ctx, proof, r.Method, requestTarget(r), accessToken)
	if err != nil {
		return "", errs.Wrap(err, ErrInvalidDPoPProof)
	}
	if expectedJKT != "" && jkt != expectedJKT {
		return "", errs.Detail(ErrInvalidDPoPProof, "DPoP thumbprint does not match the bound key | DPoP 指纹与绑定密钥不匹配")
	}
	return jkt, nil
}

// dpopForAuthorization adds the authorization-endpoint dpop_jkt binding. | dpopForAuthorization
// 添加授权端点的 dpop_jkt 绑定。
func (s *Server) dpopForAuthorization(req *AuthorizationRequest) (string, error) {
	if req == nil {
		return "", nil
	}
	jkt := strings.TrimSpace(req.Raw.Get("dpop_jkt"))
	if jkt == "" {
		if s.config.DPoPRequired {
			return "", errs.Detail(ErrInvalidDPoPProof, "dpop_jkt is required | 必须提供 dpop_jkt")
		}
		return "", nil
	}
	if len(jkt) < 32 || len(jkt) > 128 {
		return "", errs.Detail(ErrInvalidDPoPProof, "dpop_jkt length is invalid | dpop_jkt 长度非法")
	}
	return jkt, nil
}
