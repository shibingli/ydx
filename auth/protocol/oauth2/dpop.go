package oauth2

import (
	"net/http"

	"github.com/shibingli/ydx/errs"
)

// DPoPSigner signs RFC 9449 DPoP proofs for the client implementation. | DPoPSigner 为客户端实现签名 RFC 9449 DPoP 证明。
type DPoPSigner interface {
	// SignDPoP returns a compact DPoP proof for method and target. | SignDPoP 返回 method 与 target 的紧凑 DPoP 证明。
	SignDPoP(method, target, accessToken string) (string, error)
	// Thumbprint returns the RFC 7638 JWK thumbprint bound into access tokens. | Thumbprint 返回绑定进访问令牌的 RFC 7638 JWK 指纹。
	Thumbprint() (string, error)
}

// DPoPNonceSigner is a DPoPSigner that can embed the RFC 9449 nonce claim. | DPoPNonceSigner 是能
// 嵌入 RFC 9449 nonce 声明的 DPoPSigner。
//
// A client only retries a use_dpop_nonce response when its signer implements this interface, because
// a proof without the nonce claim would be rejected again. | 只有当签名器实现本接口时，客户端才会重试
// use_dpop_nonce 响应，因为不含 nonce 声明的证明会再次被拒绝。
type DPoPNonceSigner interface {
	DPoPSigner
	// SignDPoPWithNonce returns a compact DPoP proof carrying nonce. | SignDPoPWithNonce 返回携带
	// nonce 的紧凑 DPoP 证明。
	SignDPoPWithNonce(method, target, accessToken, nonce string) (string, error)
}

// applyDPoP attaches a DPoP proof to req. | applyDPoP 把 DPoP 证明附加到 req。
func (c *OAuthClient) applyDPoP(req *http.Request) error {
	if c == nil || c.config.DPoPKey == nil || req == nil {
		return nil
	}
	// RFC 9449 section 4.2: htu excludes the query and fragment components. | RFC 9449 第 4.2 节：
	// htu 不包含查询与片段部分。
	target := ""
	if req.URL != nil {
		stripped := *req.URL
		stripped.RawQuery = ""
		stripped.ForceQuery = false
		stripped.Fragment = ""
		stripped.RawFragment = ""
		target = stripped.String()
	}
	var proof string
	var err error
	if nonce := c.DPoPNonce(); nonce != "" {
		if signer, ok := c.config.DPoPKey.(DPoPNonceSigner); ok {
			proof, err = signer.SignDPoPWithNonce(req.Method, target, "", nonce)
		} else {
			proof, err = c.config.DPoPKey.SignDPoP(req.Method, target, "")
		}
	} else {
		proof, err = c.config.DPoPKey.SignDPoP(req.Method, target, "")
	}
	if err != nil {
		return errs.Wrap(err, ErrInvalidDPoPProof)
	}
	req.Header.Set("DPoP", proof)
	return nil
}
