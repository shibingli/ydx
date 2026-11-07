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

// applyDPoP attaches a DPoP proof to req. | applyDPoP 把 DPoP 证明附加到 req。
func (c *OAuthClient) applyDPoP(req *http.Request) error {
	if c == nil || c.config.DPoPKey == nil || req == nil {
		return nil
	}
	proof, err := c.config.DPoPKey.SignDPoP(req.Method, req.URL.String(), "")
	if err != nil {
		return errs.Wrap(err, ErrInvalidDPoPProof)
	}
	req.Header.Set("DPoP", proof)
	return nil
}
