package cas

import (
	"context"
	"net/http"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
)

// LoginRequest carries the credentials and protocol parameters of a login POST. | LoginRequest
// 携带登录 POST 的凭据与协议参数。
type LoginRequest struct {
	// ResponseWriter is the originating response writer. | ResponseWriter 是原始响应写入器。
	ResponseWriter http.ResponseWriter
	// Request is the originating HTTP request; it supplies session metadata. | Request 是原始 HTTP 请求；用于提供会话元数据。
	Request *http.Request
	// Username is the submitted login name. | Username 是提交的登录名。
	Username string
	// Password is the submitted plaintext password. Implementations must not retain or log it. |
	// Password 是提交的明文口令。实现不得保留或记录它。
	Password string
	// Service is the target service URL, empty when the user only wants a CAS session. | Service
	// 是目标服务 URL；用户仅需要 CAS 会话时为空。
	Service string
	// Renew reports a forced re-authentication. | Renew 表示强制重新认证。
	Renew bool
	// Gateway reports a gateway login attempt; a gateway POST should not occur in practice. |
	// Gateway 表示网关登录尝试；实践中不应出现网关 POST。
	Gateway bool
	// RememberMe reports a persistent login request. | RememberMe 表示持久登录请求。
	RememberMe bool
	// Warn reports the CAS 1.0 warn parameter. | Warn 表示 CAS 1.0 warn 参数。
	Warn bool
}

// Authenticator verifies end-user credentials during login. | Authenticator 在登录时校验最终用户凭据。
type Authenticator interface {
	// Authenticate returns the authenticated principal or an error. The returned principal must
	// carry a stable Subject and, when available, a Username. | Authenticate 返回已认证主体或错误。
	// 返回的主体必须带有稳定的 Subject，并在可用时带有 Username。
	Authenticate(ctx context.Context, req *LoginRequest) (*auth.Principal, error)
}

// AuthenticatorFunc adapts a function to Authenticator. | AuthenticatorFunc 把函数适配为 Authenticator。
type AuthenticatorFunc func(ctx context.Context, req *LoginRequest) (*auth.Principal, error)

// Authenticate calls f. | Authenticate 调用 f。
func (f AuthenticatorFunc) Authenticate(ctx context.Context, req *LoginRequest) (*auth.Principal, error) {
	if f == nil {
		return nil, errs.Detail(ErrInvalidConfig, "authenticator function is nil | 认证函数为空")
	}
	return f(ctx, req)
}

// ServiceAuthenticator adapts auth.Service.Authenticate to the CAS Authenticator interface. |
// ServiceAuthenticator 把 auth.Service.Authenticate 适配为 CAS 的 Authenticator 接口。
//
// The adapter creates a normal auth session, records the usual audit events and copies user
// metadata into Principal.Attributes so the CAS server can release it as protocol attributes. A
// login that still requires a second factor returns auth.ErrMFARequired; interactive MFA is not
// part of the CAS login form. | 适配器创建常规 auth 会话、记录常规审计事件，并把用户元数据复制到
// Principal.Attributes，以便 CAS 服务端将其作为协议属性发布。仍需要第二因素的登录返回
// auth.ErrMFARequired；CAS 登录表单不包含交互式多因素流程。
type ServiceAuthenticator struct {
	service  *auth.Service
	clientID string
}

// NewServiceAuthenticator returns an Authenticator over svc. | NewServiceAuthenticator 返回基于 svc 的 Authenticator。
func NewServiceAuthenticator(svc *auth.Service) *ServiceAuthenticator {
	return &ServiceAuthenticator{service: svc, clientID: "cas"}
}

// SetClientID overrides the client identifier recorded on auth sessions. | SetClientID 覆盖记录在 auth 会话上的客户端标识。
func (a *ServiceAuthenticator) SetClientID(clientID string) {
	if a != nil {
		a.clientID = clientID
	}
}

// Authenticate implements Authenticator. | Authenticate 实现 Authenticator。
func (a *ServiceAuthenticator) Authenticate(ctx context.Context, req *LoginRequest) (*auth.Principal, error) {
	if a == nil || a.service == nil {
		return nil, errs.Detail(ErrInvalidConfig, "auth service is nil | auth 服务为空")
	}
	if req == nil {
		return nil, errs.Detail(ErrInvalidRequest, "login request is nil | 登录请求为空")
	}
	result, err := a.service.Authenticate(ctx, auth.AuthenticateInput{
		Login:    req.Username,
		Password: req.Password,
		ClientID: a.clientID,
		Request:  req.Request,
	})
	if err != nil {
		return nil, err
	}
	if result.MFARequired {
		return nil, auth.ErrMFARequired
	}
	principal := auth.DefaultPrincipal(result.User, result.Session)
	if principal != nil && len(result.User.Metadata) > 0 {
		principal.Attributes = cloneStrings(result.User.Metadata)
	}
	return principal, nil
}

// PrincipalProvider refreshes the principal of an authenticated ticket. | PrincipalProvider 刷新
// 已认证票据的主体。
//
// It is optional. When set, the server calls it on every validation so attribute changes take
// effect immediately; when nil, the principal snapshot stored in the ticket is used. | 它是可选的。
// 设置后，服务端在每次校验时调用它，使属性变更立即生效；为空时使用票据中保存的主体快照。
type PrincipalProvider interface {
	// Principal returns the current principal for userID. | Principal 返回 userID 的当前主体。
	Principal(ctx context.Context, userID string) (*auth.Principal, error)
}

// PrincipalProviderFunc adapts a function to PrincipalProvider. | PrincipalProviderFunc 把函数适配为 PrincipalProvider。
type PrincipalProviderFunc func(ctx context.Context, userID string) (*auth.Principal, error)

// Principal calls f. | Principal 调用 f。
func (f PrincipalProviderFunc) Principal(ctx context.Context, userID string) (*auth.Principal, error) {
	if f == nil {
		return nil, errs.Detail(ErrInvalidConfig, "principal provider function is nil | 主体提供函数为空")
	}
	return f(ctx, userID)
}

// ServicePrincipalProvider resolves principals from an auth.Service user store. | ServicePrincipalProvider
// 从 auth.Service 用户存储解析主体。
type ServicePrincipalProvider struct {
	service *auth.Service
}

// NewServicePrincipalProvider returns a PrincipalProvider over svc. | NewServicePrincipalProvider
// 返回基于 svc 的 PrincipalProvider。
func NewServicePrincipalProvider(svc *auth.Service) *ServicePrincipalProvider {
	return &ServicePrincipalProvider{service: svc}
}

// Principal implements PrincipalProvider. | Principal 实现 PrincipalProvider。
func (p *ServicePrincipalProvider) Principal(ctx context.Context, userID string) (*auth.Principal, error) {
	if p == nil || p.service == nil {
		return nil, errs.Detail(ErrInvalidConfig, "auth service is nil | auth 服务为空")
	}
	user, err := p.service.Stores().Users.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	principal := p.service.PrincipalForUser(user)
	if principal != nil && len(user.Metadata) > 0 {
		principal.Attributes = cloneStrings(user.Metadata)
	}
	return principal, nil
}
