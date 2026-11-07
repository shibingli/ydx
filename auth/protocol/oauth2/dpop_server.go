package oauth2

import (
	"context"
	"net/http"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// dpopForTokenRequest validates an optional DPoP proof on a token request. | dpopForTokenRequest
// 校验令牌请求上的可选 DPoP 证明。
//
// expectedJKT is non-empty when the authorization code or refresh token was already bound to a key;
// the proof must then present the same thumbprint. | 当授权码或刷新令牌已绑定密钥时 expectedJKT 非空；
// 此时证明必须呈现相同指纹。
func (s *Server) dpopForTokenRequest(ctx context.Context, r *http.Request, expectedJKT, accessToken string) (string, error) {
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
