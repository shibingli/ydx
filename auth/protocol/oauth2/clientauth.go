package oauth2

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// ClientAssertionTypeJWTBearer is the RFC 7523 assertion type. | ClientAssertionTypeJWTBearer 是 RFC 7523 断言类型。
const ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// authenticateClient authenticates the client of a token, introspection or revocation request.
// endpointPath is the configured path of the calling endpoint; it forms the RFC 7523 assertion
// audience at the actual mount point. | authenticateClient 认证令牌、自省或撤销请求的客户端。
// endpointPath 是调用端点的配置路径，用于在实际挂载点构成 RFC 7523 断言受众。
func (s *Server) authenticateClient(ctx context.Context, r *http.Request, form url.Values, endpointPath string) (*Client, error) {
	basicID, basicSecret, hasBasic := basicCredentials(r)
	formID := strings.TrimSpace(form.Get("client_id"))
	formSecret := form.Get("client_secret")
	if hasBasic && formSecret != "" {
		return nil, errs.Detail(ErrInvalidClient, "multiple client authentication methods | 多种客户端认证方法")
	}
	clientID := formID
	secret := formSecret
	if hasBasic {
		clientID = basicID
		secret = basicSecret
		if formID != "" && formID != basicID {
			return nil, errs.Detail(ErrInvalidRequest, "client_id does not match Authorization header | client_id 与 Authorization 头不匹配")
		}
	}
	assertion := form.Get("client_assertion")
	assertionType := form.Get("client_assertion_type")
	if assertion != "" {
		if secret != "" || hasBasic {
			return nil, errs.Detail(ErrInvalidClient, "client assertion cannot be combined with a secret | 客户端断言不能与密钥同时使用")
		}
		if assertionType != ClientAssertionTypeJWTBearer {
			return nil, errs.Detail(ErrInvalidRequest, "unsupported client_assertion_type | 不支持的 client_assertion_type")
		}
		if clientID == "" {
			return nil, errs.Detail(ErrInvalidClient, "client_id is required with a client assertion | 客户端断言必须带 client_id")
		}
		if s.config.ClientAssertionVerifier == nil && s.clientSecretJWT == nil {
			return nil, errs.Detail(ErrInvalidClient, "client assertions are not configured | 未配置客户端断言校验")
		}
		client, err := s.config.Clients.GetClient(ctx, clientID)
		if err != nil {
			return nil, err
		}
		// Assertions may only be used by clients registered for a JWT client authentication
		// method. A client registered for a shared-secret method must not bypass the secret by
		// presenting an assertion, and a client registered for none is public by definition. |
		// 只有注册为 JWT 客户端认证方法的客户端可以使用断言。注册为共享密钥方法的客户端不得用断言
		// 绕过密钥，注册为 none 的客户端按定义是公共客户端。
		switch registeredAuthMethod(client) {
		case ClientSecretJWT:
			if s.clientSecretJWT == nil {
				return nil, errs.Detail(ErrInvalidClient, "client_secret_jwt is not enabled; configure ServerConfig.ClientSecretJWT with a secret resolver | 未启用 client_secret_jwt；请用密钥解析器配置 ServerConfig.ClientSecretJWT")
			}
			if err := s.clientSecretJWT.VerifyClientAssertion(ctx, client, assertion, s.Endpoint(endpointPath)); err != nil {
				return nil, errs.Wrap(err, ErrInvalidClient)
			}
			return client, nil
		case PrivateKeyJWT:
			if s.config.ClientAssertionVerifier == nil {
				return nil, errs.Detail(ErrInvalidClient, "private_key_jwt is not configured | 未配置 private_key_jwt")
			}
			if err := s.config.ClientAssertionVerifier.VerifyClientAssertion(ctx, client, assertion, s.Endpoint(endpointPath)); err != nil {
				return nil, errs.Wrap(err, ErrInvalidClient)
			}
			return client, nil
		default:
			return nil, errs.Detail(ErrInvalidClient, "client is not registered for a JWT client assertion method | 客户端未注册 JWT 客户端断言方法")
		}
	}
	if clientID == "" {
		return nil, errs.Detail(ErrInvalidClient, "client_id is missing | 缺少 client_id")
	}
	client, err := s.config.Clients.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	method := registeredAuthMethod(client)
	switch method {
	case ClientAuthNone:
		if secret != "" {
			return nil, errs.Detail(ErrInvalidClient, "public client must not send a secret | 公共客户端不得发送密钥")
		}
		return client, nil
	case TLSClientAuth, SelfSignedTLSClientAuth:
		if secret != "" {
			return nil, errs.Detail(ErrInvalidClient, "mTLS client must not send a secret | mTLS 客户端不得发送密钥")
		}
		if err := verifyTLSClient(r, client, method); err != nil {
			return nil, err
		}
		return client, nil
	case ClientSecretBasic:
		if !hasBasic {
			return nil, errs.Detail(ErrInvalidClient, "client_secret_basic requires HTTP Basic authentication | client_secret_basic 必须使用 HTTP Basic 认证")
		}
		if !verifyClientSecret(client, secret) {
			return nil, errs.Detail(ErrInvalidClient, "client authentication failed | 客户端认证失败")
		}
		return client, nil
	case ClientSecretPost:
		if hasBasic {
			return nil, errs.Detail(ErrInvalidClient, "client_secret_post must not use HTTP Basic authentication | client_secret_post 不得使用 HTTP Basic 认证")
		}
		if !verifyClientSecret(client, secret) {
			return nil, errs.Detail(ErrInvalidClient, "client authentication failed | 客户端认证失败")
		}
		return client, nil
	case ClientSecretJWT:
		if s.clientSecretJWT == nil {
			return nil, errs.Detail(ErrInvalidClient, "client_secret_jwt is not enabled; configure ServerConfig.ClientSecretJWT with a secret resolver | 未启用 client_secret_jwt；请用密钥解析器配置 ServerConfig.ClientSecretJWT")
		}
		return nil, errs.Detail(ErrInvalidClient, "client assertion is required for client_secret_jwt | client_secret_jwt 要求客户端断言")
	case PrivateKeyJWT:
		return nil, errs.Detail(ErrInvalidClient, "client assertion is required for the registered authentication method | 注册的认证方法要求客户端断言")
	default:
		return nil, errs.Detail(ErrInvalidClient, "unsupported client authentication method %[1]q | 不支持的客户端认证方法 %[1]q", method)
	}
}

// registeredAuthMethod returns the effective registered client authentication method. | registeredAuthMethod
// 返回实际生效的已注册客户端认证方法。
func registeredAuthMethod(client *Client) string {
	method := client.TokenEndpointAuthMethod
	if method == "" {
		if client.Public {
			return ClientAuthNone
		}
		return ClientSecretBasic
	}
	return method
}

// verifyClientSecret compares a presented secret with the stored hash. | verifyClientSecret 用存储的哈希比较提交的密钥。
func verifyClientSecret(client *Client, secret string) bool {
	if secret == "" {
		return false
	}
	return client.VerifySecret(secret)
}

// basicCredentials extracts RFC 6749 Basic credentials. | basicCredentials 提取 RFC 6749 Basic 凭据。
func basicCredentials(r *http.Request) (string, string, bool) {
	if r == nil {
		return "", "", false
	}
	values := r.Header.Values("Authorization")
	if len(values) == 0 {
		return "", "", false
	}
	if len(values) > 1 {
		return "", "", false
	}
	header := values[0]
	if len(header) < 6 || !strings.EqualFold(header[:6], "Basic ") {
		return "", "", false
	}
	username, password, ok := r.BasicAuth()
	if !ok {
		return "", "", false
	}
	if decoded, err := url.QueryUnescape(username); err == nil {
		username = decoded
	}
	if decoded, err := url.QueryUnescape(password); err == nil {
		password = decoded
	}
	return username, password, true
}

// verifyTLSClient checks the RFC 8705 certificate binding. A client registered for mTLS must have
// at least one registered binding; otherwise any certificate trusted by the TLS listener would
// authenticate as it, so an unbound client fails closed. Self-signed certificates are additionally
// checked for their validity period because the TLS stack does not verify a self-signed chain. |
// verifyTLSClient 校验 RFC 8705 证书绑定。注册为 mTLS 的客户端必须至少有一个已注册绑定；否则
// TLS 监听器信任的任何证书都能以该客户端身份认证，因此未绑定客户端按失败关闭处理。自签名证书
// 还会校验有效期，因为 TLS 栈不会校验自签名链。
func verifyTLSClient(r *http.Request, client *Client, method string) error {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return errs.Detail(ErrInvalidClient, "client certificate is missing | 缺少客户端证书")
	}
	cert := r.TLS.PeerCertificates[0]
	if len(client.TLSClientAuthSubjectDN) == 0 && len(client.TLSClientAuthSANs) == 0 {
		return errs.Detail(ErrInvalidClient, "client has no certificate binding | 客户端没有证书绑定")
	}
	if len(client.TLSClientAuthSubjectDN) > 0 && cert.Subject.String() != client.TLSClientAuthSubjectDN {
		return errs.Detail(ErrInvalidClient, "client certificate subject does not match | 客户端证书主体不匹配")
	}
	if len(client.TLSClientAuthSANs) > 0 {
		matched := false
		for _, san := range client.TLSClientAuthSANs {
			for _, dns := range cert.DNSNames {
				if dns == san {
					matched = true
					break
				}
			}
			if !matched {
				for _, ip := range cert.IPAddresses {
					if ip.String() == san {
						matched = true
						break
					}
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return errs.Detail(ErrInvalidClient, "client certificate SAN does not match | 客户端证书 SAN 不匹配")
		}
	}
	if method == SelfSignedTLSClientAuth {
		now := time.Now()
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return errs.Detail(ErrInvalidClient, "self-signed client certificate is not valid at the current time | 自签名客户端证书当前无效")
		}
		if err := cert.CheckSignatureFrom(cert); err != nil {
			return errs.Wrap(err, ErrInvalidClient)
		}
	}
	_ = x509.Certificate{}
	return nil
}
