package oidc

import (
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// ClientMetadata is the RFC 7591 client metadata document. | ClientMetadata 是 RFC 7591 客户端元数据文档。
type ClientMetadata struct {
	// ClientID is echoed by RFC 7592 management requests and must match the path. | ClientID 由
	// RFC 7592 管理请求回显，且必须与路径一致。
	ClientID string `json:"client_id,omitempty"`
	// RedirectURIs are the allowed redirect URIs. | RedirectURIs 是允许的重定向 URI。
	RedirectURIs []string `json:"redirect_uris,omitempty"`
	// TokenEndpointAuthMethod is the token-endpoint authentication method. | TokenEndpointAuthMethod 是令牌端点认证方法。
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`
	// GrantTypes lists the allowed grant types. | GrantTypes 列出允许的授权类型。
	GrantTypes []string `json:"grant_types,omitempty"`
	// ResponseTypes lists the allowed response types. | ResponseTypes 列出允许的响应类型。
	ResponseTypes []string `json:"response_types,omitempty"`
	// ClientName is the human-readable application name. | ClientName 是人类可读应用名。
	ClientName string `json:"client_name,omitempty"`
	// ClientURI points to the client home page. | ClientURI 指向客户端主页。
	ClientURI string `json:"client_uri,omitempty"`
	// LogoURI points to a client logo. | LogoURI 指向客户端徽标。
	LogoURI string `json:"logo_uri,omitempty"`
	// PolicyURI points to the client privacy policy. | PolicyURI 指向客户端隐私政策。
	PolicyURI string `json:"policy_uri,omitempty"`
	// TOSURI points to the client terms of service. | TOSURI 指向客户端服务条款。
	TOSURI string `json:"tos_uri,omitempty"`
	// Contacts lists administrative email addresses. | Contacts 列出管理邮箱地址。
	Contacts []string `json:"contacts,omitempty"`
	// Scope is the space-delimited default scope. | Scope 是空格分隔的默认作用域。
	Scope string `json:"scope,omitempty"`
	// SubjectType is public or pairwise. | SubjectType 取值为 public 或 pairwise。
	SubjectType string `json:"subject_type,omitempty"`
	// SectorIdentifierURI groups pairwise clients that share a subject. | SectorIdentifierURI
	// 用于把共享同一假名主体的客户端分组。
	SectorIdentifierURI string `json:"sector_identifier_uri,omitempty"`
	// ApplicationType is web or native. | ApplicationType 取值为 web 或 native。
	ApplicationType string `json:"application_type,omitempty"`
	// IDTokenSignedResponseAlg is the required ID-token signing algorithm. | IDTokenSignedResponseAlg 是要求的 ID 令牌签名算法。
	IDTokenSignedResponseAlg string `json:"id_token_signed_response_alg,omitempty"`
	// IDTokenEncryptedResponseAlg is the required ID-token key-management algorithm. | IDTokenEncryptedResponseAlg 是要求的 ID 令牌密钥管理算法。
	IDTokenEncryptedResponseAlg string `json:"id_token_encrypted_response_alg,omitempty"`
	// IDTokenEncryptedResponseEnc is the required ID-token content-encryption algorithm. | IDTokenEncryptedResponseEnc 是要求的 ID 令牌内容加密算法。
	IDTokenEncryptedResponseEnc string `json:"id_token_encrypted_response_enc,omitempty"`
	// UserInfoSignedResponseAlg is the required UserInfo signing algorithm. | UserInfoSignedResponseAlg 是要求的 UserInfo 签名算法。
	UserInfoSignedResponseAlg string `json:"userinfo_signed_response_alg,omitempty"`
	// UserInfoEncryptedResponseAlg is the required UserInfo key-management algorithm. | UserInfoEncryptedResponseAlg 是要求的 UserInfo 密钥管理算法。
	UserInfoEncryptedResponseAlg string `json:"userinfo_encrypted_response_alg,omitempty"`
	// UserInfoEncryptedResponseEnc is the required UserInfo content-encryption algorithm. | UserInfoEncryptedResponseEnc 是要求的 UserInfo 内容加密算法。
	UserInfoEncryptedResponseEnc string `json:"userinfo_encrypted_response_enc,omitempty"`
	// RequestObjectSigningAlg is the required request-object signing algorithm. | RequestObjectSigningAlg 是要求的请求对象签名算法。
	RequestObjectSigningAlg string `json:"request_object_signing_alg,omitempty"`
	// RequestURIs are the RFC 9101 by-reference request object URLs the client may use. |
	// RequestURIs 是客户端可使用的 RFC 9101 按引用请求对象 URL。
	RequestURIs []string `json:"request_uris,omitempty"`
	// AuthorizationSignedResponseAlg selects the JARM response JWS algorithm. | AuthorizationSignedResponseAlg
	// 选择 JARM 响应 JWS 算法。
	AuthorizationSignedResponseAlg string `json:"authorization_signed_response_alg,omitempty"`
	// TokenEndpointAuthSigningAlg is the required client-assertion signing algorithm. | TokenEndpointAuthSigningAlg 是要求的客户端断言签名算法。
	TokenEndpointAuthSigningAlg string `json:"token_endpoint_auth_signing_alg,omitempty"`
	// JWKSURI points to the client's public keys. | JWKSURI 指向客户端公钥。
	JWKSURI string `json:"jwks_uri,omitempty"`
	// JWKS is an inline client key set. | JWKS 是内联客户端密钥集。
	JWKS map[string]any `json:"jwks,omitempty"`
	// PostLogoutRedirectURIs are the allowed logout redirect URIs. | PostLogoutRedirectURIs 是允许的登出重定向 URI。
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty"`
	// FrontchannelLogoutURI is the front-channel logout endpoint. | FrontchannelLogoutURI 是前端通道登出端点。
	FrontchannelLogoutURI string `json:"frontchannel_logout_uri,omitempty"`
	// FrontchannelLogoutSessionRequired requires the sid parameter at logout. | FrontchannelLogoutSessionRequired 要求登出时携带 sid 参数。
	FrontchannelLogoutSessionRequired bool `json:"frontchannel_logout_session_required,omitempty"`
	// BackchannelLogoutURI is the back-channel logout endpoint. | BackchannelLogoutURI 是后端通道登出端点。
	BackchannelLogoutURI string `json:"backchannel_logout_uri,omitempty"`
	// BackchannelLogoutSessionRequired requires the sid parameter at logout. | BackchannelLogoutSessionRequired 要求登出时携带 sid 参数。
	BackchannelLogoutSessionRequired bool `json:"backchannel_logout_session_required,omitempty"`
	// TLSClientAuthSubjectDN is the allowed subject DN for tls_client_auth. Registrations using
	// tls_client_auth or self_signed_tls_client_auth must supply it or TLSClientAuthSANs. |
	// TLSClientAuthSubjectDN 是 tls_client_auth 允许的主体 DN。使用 tls_client_auth 或
	// self_signed_tls_client_auth 的注册必须提供它或 TLSClientAuthSANs。
	TLSClientAuthSubjectDN string `json:"tls_client_auth_subject_dn,omitempty"`
	// TLSClientAuthSANs are allowed DNS/IP SANs for tls_client_auth. | TLSClientAuthSANs 是 tls_client_auth 允许的 DNS/IP SAN。
	TLSClientAuthSANs []string `json:"tls_client_auth_san_dns,omitempty"`
}

// RegistrationResponse is the RFC 7591 registration response. | RegistrationResponse 是 RFC 7591 注册响应。
type RegistrationResponse struct {
	// ClientID is the issued client identifier. | ClientID 是签发的客户端标识。
	ClientID string `json:"client_id"`
	// ClientSecret is returned once for confidential clients. | ClientSecret 对机密客户端返回一次。
	ClientSecret string `json:"client_secret,omitempty"`
	// ClientIDIssuedAt is the client-id issue time in Unix seconds. | ClientIDIssuedAt 是客户端标识签发时间（Unix 秒）。
	ClientIDIssuedAt int64 `json:"client_id_issued_at"`
	// ClientSecretExpiresAt is the secret expiry in Unix seconds; zero means no expiry. | ClientSecretExpiresAt 是密钥过期时间（Unix 秒）；零表示不过期。
	ClientSecretExpiresAt int64 `json:"client_secret_expires_at"`
	// RegistrationAccessToken protects the management endpoint. | RegistrationAccessToken 保护管理端点。
	RegistrationAccessToken string `json:"registration_access_token,omitempty"`
	// RegistrationClientURI is the management endpoint. | RegistrationClientURI 是管理端点。
	RegistrationClientURI string `json:"registration_client_uri,omitempty"`
	// ClientMetadata is the registered metadata. | ClientMetadata 是已注册元数据。
	ClientMetadata
}

// RegisterClient handles RFC 7591 dynamic client registration. | RegisterClient 处理 RFC 7591 动态客户端注册。
func (p *Provider) RegisterClient(w http.ResponseWriter, r *http.Request) {
	if !p.config.EnableRegistration {
		writeError(w, http.StatusNotFound, "invalid_request", "registration is disabled | 注册已禁用")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed | 方法不允许")
		return
	}
	if p.config.RegistrationInitialAccessToken != "" {
		token, err := auth.BearerToken(r)
		if err != nil || !auth.SecureEqual(token, p.config.RegistrationInitialAccessToken) {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "invalid_token", "initial access token is invalid | 初始访问令牌无效")
			return
		}
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		badRequest(w, "cannot read registration body | 无法读取注册正文")
		return
	}
	var metadata ClientMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_client_metadata", "metadata is not valid JSON | 元数据不是合法 JSON")
		return
	}
	if err := validateClientMetadataFor(&metadata, p.oauth); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}
	client := &oauth2.Client{
		ID:        auth.NewID("client"),
		CreatedAt: p.Now(),
		UpdatedAt: p.Now(),
	}
	secret, err := applyClientMetadata(client, &metadata, true)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}
	registrationToken, err := auth.RandomToken(32)
	if err != nil {
		invalidConfig(w, err)
		return
	}
	client.RegistrationAccessTokenHash = auth.HashToken(registrationToken)
	client.RegistrationClientURI = p.Endpoint(p.config.RegistrationPath) + "/" + url.PathEscape(client.ID)
	if err := p.oauth.Config().Clients.CreateClient(r.Context(), client); err != nil {
		invalidConfig(w, err)
		return
	}
	if secret != "" && client.TokenEndpointAuthMethod == oauth2.ClientSecretJWT {
		if err := p.oauth.RegisterClientSecret(r.Context(), client.ID, secret); err != nil {
			// The client row is useless without a resolver-visible secret, so undo it instead of
			// leaving a registration that can never authenticate. | 缺少解析器可见密钥的客户端记录
			// 无法认证，因此回滚，而不是留下一条永远无法认证的注册。
			_ = p.oauth.Config().Clients.DeleteClient(r.Context(), client.ID)
			invalidConfig(w, err)
			return
		}
	}
	response := RegistrationResponse{
		ClientID:                client.ID,
		ClientSecret:            secret,
		ClientIDIssuedAt:        client.CreatedAt.Unix(),
		ClientSecretExpiresAt:   0,
		RegistrationAccessToken: registrationToken,
		RegistrationClientURI:   client.RegistrationClientURI,
		ClientMetadata:          metadataFromClient(client),
	}
	writeJSON(w, http.StatusCreated, response)
}

// ClientConfiguration handles RFC 7592 read, update and delete. | ClientConfiguration 处理 RFC 7592 读取、更新与删除。
func (p *Provider) ClientConfiguration(w http.ResponseWriter, r *http.Request) {
	if !p.config.EnableRegistration {
		writeError(w, http.StatusNotFound, "invalid_request", "registration is disabled | 注册已禁用")
		return
	}
	clientID := clientIDFromPath(r.URL.Path, p.Path(p.config.RegistrationPath))
	if clientID == "" {
		badRequest(w, "client_id is missing | 缺少 client_id")
		return
	}
	client, err := p.oauth.Config().Clients.GetClient(r.Context(), clientID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token", "client is unknown | 客户端未知")
		return
	}
	token, err := auth.BearerToken(r)
	if err != nil || client.RegistrationAccessTokenHash == "" || !auth.TokenHashMatches(client.RegistrationAccessTokenHash, token) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeError(w, http.StatusUnauthorized, "invalid_token", "registration access token is invalid | 注册访问令牌无效")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, RegistrationResponse{
			ClientID:              client.ID,
			ClientIDIssuedAt:      client.CreatedAt.Unix(),
			RegistrationClientURI: client.RegistrationClientURI,
			ClientMetadata:        metadataFromClient(client),
		})
	case http.MethodPut:
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			badRequest(w, "cannot read registration body | 无法读取注册正文")
			return
		}
		var metadata ClientMetadata
		if err := json.Unmarshal(body, &metadata); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_client_metadata", "metadata is not valid JSON | 元数据不是合法 JSON")
			return
		}
		if metadata.ClientID == "" {
			writeError(w, http.StatusBadRequest, "invalid_client_metadata", "client_id is required | client_id 必填")
			return
		}
		if metadata.ClientID != clientID {
			writeError(w, http.StatusBadRequest, "invalid_client_metadata", "client_id does not match the path | client_id 与路径不匹配")
			return
		}
		if err := validateClientMetadataFor(&metadata, p.oauth); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
			return
		}
		updated := cloneOIDCClient(client)
		updated.UpdatedAt = p.Now()
		method := metadata.TokenEndpointAuthMethod
		if method == "" {
			method = oauth2.ClientSecretBasic
		}
		// Switching to client_secret_jwt needs a fresh registrar-persisted secret because a
		// previously issued shared secret may be unknown to the deployment resolver. | 切换到
		// client_secret_jwt 需要新的、由注册器保存的密钥，因为部署解析器可能不知道此前签发的共享密钥。
		issueSecret := method == oauth2.ClientSecretJWT && (client.TokenEndpointAuthMethod != oauth2.ClientSecretJWT || client.SecretHash == "")
		secret, err := applyClientMetadata(updated, &metadata, issueSecret)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
			return
		}
		updated.RegistrationAccessTokenHash = client.RegistrationAccessTokenHash
		updated.RegistrationClientURI = client.RegistrationClientURI
		if err := p.oauth.Config().Clients.UpdateClient(r.Context(), updated); err != nil {
			invalidConfig(w, err)
			return
		}
		if secret != "" && updated.TokenEndpointAuthMethod == oauth2.ClientSecretJWT {
			if err := p.oauth.RegisterClientSecret(r.Context(), updated.ID, secret); err != nil {
				_ = p.oauth.Config().Clients.UpdateClient(r.Context(), client)
				invalidConfig(w, err)
				return
			}
		}
		writeJSON(w, http.StatusOK, RegistrationResponse{
			ClientID:              updated.ID,
			ClientSecret:          secret,
			ClientIDIssuedAt:      updated.CreatedAt.Unix(),
			RegistrationClientURI: updated.RegistrationClientURI,
			ClientMetadata:        metadataFromClient(updated),
		})
	case http.MethodDelete:
		if err := p.oauth.Config().Clients.DeleteClient(r.Context(), client.ID); err != nil {
			invalidConfig(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		writeError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed | 方法不允许")
	}
}

// clientIDFromPath extracts the identifier after prefix. | clientIDFromPath 提取前缀后的标识。
func clientIDFromPath(path, prefix string) string {
	path = strings.TrimPrefix(path, prefix)
	path = strings.TrimPrefix(path, "/")
	if index := strings.IndexByte(path, '/'); index >= 0 {
		path = path[:index]
	}
	if decoded, err := url.PathUnescape(path); err == nil {
		return decoded
	}
	return path
}

// validateClientMetadata validates registration metadata with client_secret_jwt disabled. Servers
// that enable the method must call validateClientMetadataFor with their OAuth server. |
// validateClientMetadata 在 client_secret_jwt 禁用时校验注册元数据。启用该方法的服务器必须调用
// validateClientMetadataFor 并传入其 OAuth 服务器。
func validateClientMetadata(metadata *ClientMetadata) error {
	return validateClientMetadataFor(metadata, nil)
}

// validateClientMetadataFor validates registration metadata against server capabilities. A nil
// server keeps client_secret_jwt disabled, which is the safe default. |
// validateClientMetadataFor 依据服务器能力校验注册元数据。server 为空时 client_secret_jwt 保持
// 禁用，这是安全默认。
func validateClientMetadataFor(metadata *ClientMetadata, server *oauth2.Server) error {
	if metadata == nil {
		return errs.Detail(ErrInvalidRequest, "metadata is nil | 元数据为空")
	}
	needsRedirectURIs := len(metadata.GrantTypes) == 0
	for _, grant := range metadata.GrantTypes {
		switch grant {
		case oauth2.GrantAuthorizationCode:
			needsRedirectURIs = true
		case oauth2.GrantRefreshToken, oauth2.GrantClientCredentials, oauth2.GrantDeviceCode,
			oauth2.GrantJWTBearer, oauth2.GrantTokenExchange:
		default:
			return errs.Detail(ErrInvalidRequest, "unsupported grant_type %[1]q | 不支持的 grant_type %[1]q", grant)
		}
	}
	if needsRedirectURIs && len(metadata.RedirectURIs) == 0 {
		return errs.Detail(ErrInvalidRequest, "redirect_uris is required for the authorization-code flow | 授权码流程必须提供 redirect_uris")
	}
	for _, raw := range metadata.RedirectURIs {
		if err := validateRedirectURI(raw, false); err != nil {
			return err
		}
	}
	for _, raw := range metadata.PostLogoutRedirectURIs {
		if err := validateRedirectURI(raw, false); err != nil {
			return err
		}
	}
	for _, responseType := range metadata.ResponseTypes {
		if err := validateResponseType(responseType); err != nil {
			return err
		}
	}
	switch metadata.TokenEndpointAuthMethod {
	case "", oauth2.ClientSecretBasic, oauth2.ClientSecretPost, oauth2.PrivateKeyJWT, oauth2.ClientAuthNone, oauth2.TLSClientAuth, oauth2.SelfSignedTLSClientAuth:
	case oauth2.ClientSecretJWT:
		// The method is accepted only when the server enables it and a registrar can persist the
		// issued plaintext secret. Without persistence no resolver could verify a later
		// assertion, and storing plaintext by default would weaken the client store. | 只有服务器
		// 启用该方法且注册器能保存签发的明文密钥时才接受。缺少持久化时解析器无法校验后续断言，
		// 而默认保存明文会削弱客户端存储。
		if server == nil || !server.ClientSecretJWTEnabled() {
			return errs.Detail(ErrInvalidRequest, "client_secret_jwt is not enabled by the server | 服务器未启用 client_secret_jwt")
		}
		if !server.ClientSecretJWTRegistrarEnabled() {
			return errs.Detail(ErrInvalidRequest, "client_secret_jwt registration cannot persist the issued secret; register a preconfigured client instead | client_secret_jwt 注册无法保存签发的密钥；请改为预配置客户端")
		}
		if metadata.TokenEndpointAuthSigningAlg != "" {
			switch metadata.TokenEndpointAuthSigningAlg {
			case "HS256", "HS384", "HS512":
			default:
				return errs.Detail(ErrInvalidRequest, "token_endpoint_auth_signing_alg %[1]q is not valid for client_secret_jwt | token_endpoint_auth_signing_alg %[1]q 不适用于 client_secret_jwt", metadata.TokenEndpointAuthSigningAlg)
			}
		}
	default:
		return errs.Detail(ErrInvalidRequest, "unsupported token_endpoint_auth_method | 不支持的 token_endpoint_auth_method")
	}
	if metadata.TokenEndpointAuthMethod == oauth2.TLSClientAuth || metadata.TokenEndpointAuthMethod == oauth2.SelfSignedTLSClientAuth {
		// The runtime pairing is fail-closed without a binding, so reject such registrations
		// instead of creating a client that can never authenticate. | 运行时在缺少绑定时按失败
		// 关闭处理，因此拒绝这类注册，而不是创建一个永远无法认证的客户端。
		hasSubject := strings.TrimSpace(metadata.TLSClientAuthSubjectDN) != ""
		hasSAN := false
		for _, san := range metadata.TLSClientAuthSANs {
			if strings.TrimSpace(san) != "" {
				hasSAN = true
				break
			}
		}
		if !hasSubject && !hasSAN {
			return errs.Detail(ErrInvalidRequest, "tls_client_auth and self_signed_tls_client_auth require tls_client_auth_subject_dn or tls_client_auth_san_dns | tls_client_auth 与 self_signed_tls_client_auth 需要 tls_client_auth_subject_dn 或 tls_client_auth_san_dns")
		}
	}
	switch metadata.SubjectType {
	case "", SubjectTypePublic, SubjectTypePairwise:
	default:
		return errs.Detail(ErrInvalidRequest, "unsupported subject_type | 不支持的 subject_type")
	}
	if metadata.ApplicationType != "" && metadata.ApplicationType != "web" && metadata.ApplicationType != "native" {
		return errs.Detail(ErrInvalidRequest, "unsupported application_type | 不支持的 application_type")
	}
	if len(metadata.JWKS) > 0 && metadata.JWKSURI != "" {
		// OpenID Connect Registration section 2 forbids using both. | OpenID Connect 注册
		// 第 2 节禁止同时使用两者。
		return errs.Detail(ErrInvalidRequest, "jwks and jwks_uri are mutually exclusive | jwks 与 jwks_uri 互斥")
	}
	if metadata.JWKSURI != "" {
		if err := validateSecureURL(metadata.JWKSURI); err != nil {
			return err
		}
	}
	for _, raw := range metadata.RequestURIs {
		// RFC 9101 requires request_uri values to be absolute HTTPS URLs; the runtime fetch also
		// refuses redirects and non-public addresses. | RFC 9101 要求 request_uri 为绝对 HTTPS URL；
		// 运行时抓取还会拒绝重定向与非公网地址。
		if err := validateSecureURL(raw); err != nil {
			return err
		}
	}
	if metadata.AuthorizationSignedResponseAlg == "none" {
		// JARM section 2.3.1 forbids an unsigned authorization response. | JARM 第 2.3.1 节禁止
		// 无签名授权响应。
		return errs.Detail(ErrInvalidRequest, "authorization_signed_response_alg must not be none | authorization_signed_response_alg 不得为 none")
	}
	if metadata.SectorIdentifierURI != "" {
		if err := validateSectorIdentifier(metadata.SectorIdentifierURI, metadata.RedirectURIs); err != nil {
			return err
		}
	}
	return nil
}

// validateSecureURL requires an absolute HTTPS URL without userinfo or fragment. | validateSecureURL
// 要求不带用户信息与片段的绝对 HTTPS URL。
func validateSecureURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return errs.Detail(ErrInvalidRequest, "%[1]q must be an absolute https URL | %[1]q 必须是绝对 https URL", raw)
	}
	return nil
}

// validateSectorIdentifier checks the OIDC pairwise sector URI and its host constraint. | validateSectorIdentifier
// 校验 OIDC 假名扇区 URI 及其主机约束。
func validateSectorIdentifier(raw string, redirectURIs []string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return errs.Detail(ErrInvalidRequest, "sector_identifier_uri must be an absolute https URL | sector_identifier_uri 必须是绝对 https URL")
	}
	host := strings.ToLower(parsed.Hostname())
	for _, redirect := range redirectURIs {
		u, err := url.Parse(redirect)
		if err != nil {
			continue
		}
		if u.Host == "" {
			continue
		}
		if strings.ToLower(u.Hostname()) != host {
			return errs.Detail(ErrInvalidRequest, "sector_identifier_uri host must match every redirect URI host | sector_identifier_uri 主机必须与所有重定向 URI 主机一致")
		}
	}
	return nil
}

// validateResponseType validates an RFC 6749 response_type value. | validateResponseType 校验 RFC 6749
// response_type 取值。
func validateResponseType(raw string) error {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return errs.Detail(ErrInvalidRequest, "response_type is empty | response_type 为空")
	}
	seenNone := false
	seen := make(map[string]bool, len(fields))
	for _, field := range fields {
		switch field {
		case "code", "token", "id_token":
		case "none":
			seenNone = true
		default:
			return errs.Detail(ErrInvalidRequest, "unsupported response_type %[1]q | 不支持的 response_type %[1]q", field)
		}
		if seen[field] {
			return errs.Detail(ErrInvalidRequest, "duplicate response_type %[1]q | 重复的 response_type %[1]q", field)
		}
		seen[field] = true
	}
	if seenNone && len(fields) > 1 {
		return errs.Detail(ErrInvalidRequest, "response_type none cannot be combined | response_type none 不能组合")
	}
	return nil
}

// dangerousRedirectSchemes are never acceptable as OAuth redirect URIs. | dangerousRedirectSchemes
// 永远不能作为 OAuth 重定向 URI。
var dangerousRedirectSchemes = map[string]bool{
	"javascript": true,
	"data":       true,
	"vbscript":   true,
	"file":       true,
	"blob":       true,
	"about":      true,
}

// validateRedirectURI validates an absolute redirect URI. | validateRedirectURI 校验绝对重定向 URI。
func validateRedirectURI(raw string, allowFragment bool) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" {
		return errs.Detail(ErrInvalidRequest, "redirect URI %[1]q is not absolute | 重定向 URI %[1]q 不是绝对 URI", raw)
	}
	if parsed.Fragment != "" && !allowFragment {
		return errs.Detail(ErrInvalidRequest, "redirect URI must not contain a fragment | 重定向 URI 不得包含片段")
	}
	if parsed.User != nil {
		return errs.Detail(ErrInvalidRequest, "redirect URI must not contain userinfo | 重定向 URI 不得包含用户信息")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if dangerousRedirectSchemes[scheme] {
		return errs.Detail(ErrInvalidRequest, "redirect URI scheme %[1]q is not allowed | 不允许重定向 URI 方案 %[1]q", scheme)
	}
	switch scheme {
	case "https":
		if parsed.Host == "" {
			return errs.Detail(ErrInvalidRequest, "https redirect URI must contain a host | https 重定向 URI 必须包含主机")
		}
	case "http":
		if parsed.Host == "" {
			return errs.Detail(ErrInvalidRequest, "http redirect URI must contain a host | http 重定向 URI 必须包含主机")
		}
		host := parsed.Hostname()
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return errs.Detail(ErrInvalidRequest, "http redirect URI must use loopback | HTTP 重定向 URI 必须使用回环地址")
		}
	default:
		// A native application's private-use scheme. It must carry an opaque part or
		// path so it cannot be confused with a scheme-only URI. | 原生应用的私有方案必须
		// 携带不透明部分或路径，避免与仅含方案的 URI 混淆。
		if parsed.Opaque == "" && parsed.Path == "" && parsed.Host == "" {
			return errs.Detail(ErrInvalidRequest, "redirect URI %[1]q has no target | 重定向 URI %[1]q 没有目标", raw)
		}
	}
	return nil
}

// applyClientMetadata copies metadata into client and returns a newly issued secret. | applyClientMetadata
// 把元数据复制到 client，并返回新签发的密钥。
func applyClientMetadata(client *oauth2.Client, metadata *ClientMetadata, issueSecret bool) (string, error) {
	client.Name = metadata.ClientName
	client.RedirectURIs = append([]string(nil), metadata.RedirectURIs...)
	client.GrantTypes = append([]string(nil), metadata.GrantTypes...)
	if len(client.GrantTypes) == 0 {
		client.GrantTypes = []string{oauth2.GrantAuthorizationCode}
	}
	client.ResponseTypes = append([]string(nil), metadata.ResponseTypes...)
	if len(client.ResponseTypes) == 0 {
		client.ResponseTypes = []string{oauth2.ResponseCode}
	}
	client.Scopes = oauth2.ParseScope(metadata.Scope)
	client.TokenEndpointAuthMethod = metadata.TokenEndpointAuthMethod
	if client.TokenEndpointAuthMethod == "" {
		client.TokenEndpointAuthMethod = oauth2.ClientSecretBasic
	}
	client.Public = client.TokenEndpointAuthMethod == oauth2.ClientAuthNone
	client.SubjectType = metadata.SubjectType
	client.SectorIdentifierURI = metadata.SectorIdentifierURI
	client.IDTokenSignedResponseAlg = metadata.IDTokenSignedResponseAlg
	client.IDTokenEncryptedResponseAlg = metadata.IDTokenEncryptedResponseAlg
	client.IDTokenEncryptedResponseEnc = metadata.IDTokenEncryptedResponseEnc
	client.UserInfoSignedResponseAlg = metadata.UserInfoSignedResponseAlg
	client.UserInfoEncryptedResponseAlg = metadata.UserInfoEncryptedResponseAlg
	client.UserInfoEncryptedResponseEnc = metadata.UserInfoEncryptedResponseEnc
	client.RequestObjectSigningAlg = metadata.RequestObjectSigningAlg
	client.RequestURIs = append([]string(nil), metadata.RequestURIs...)
	client.AuthorizationSignedResponseAlg = metadata.AuthorizationSignedResponseAlg
	client.TokenEndpointAuthSigningAlg = metadata.TokenEndpointAuthSigningAlg
	client.ApplicationType = metadata.ApplicationType
	client.Contacts = append([]string(nil), metadata.Contacts...)
	client.LogoURI = metadata.LogoURI
	client.PolicyURI = metadata.PolicyURI
	client.TOSURI = metadata.TOSURI
	client.ClientURI = metadata.ClientURI
	client.JWKSURI = metadata.JWKSURI
	client.PostLogoutRedirectURIs = append([]string(nil), metadata.PostLogoutRedirectURIs...)
	client.FrontchannelLogoutURI = metadata.FrontchannelLogoutURI
	client.FrontchannelLogoutSessionRequired = metadata.FrontchannelLogoutSessionRequired
	client.BackchannelLogoutURI = metadata.BackchannelLogoutURI
	client.BackchannelLogoutSessionRequired = metadata.BackchannelLogoutSessionRequired
	client.TLSClientAuthSubjectDN = metadata.TLSClientAuthSubjectDN
	client.TLSClientAuthSANs = append([]string(nil), metadata.TLSClientAuthSANs...)
	// RFC 7592 PUT replaces the whole metadata document, so an omitted jwks must clear a value
	// stored by an earlier registration instead of surviving next to a new jwks_uri. | RFC 7592
	// PUT 替换整个元数据文档，因此省略的 jwks 必须清除先前注册保存的值，而不是与新 jwks_uri 并存。
	client.JWKS = nil
	if len(metadata.JWKS) > 0 {
		raw, err := json.Marshal(metadata.JWKS)
		if err != nil {
			return "", errs.Wrap(err, ErrInvalidRequest)
		}
		client.JWKS = raw
	}
	if client.Public {
		client.SecretHash = ""
		return "", nil
	}
	switch client.TokenEndpointAuthMethod {
	case oauth2.ClientSecretBasic, oauth2.ClientSecretPost:
	case oauth2.ClientSecretJWT:
		// HS512 signs with a 64-byte key, so a client_secret_jwt secret carries 64 random bytes
		// to keep every enabled algorithm usable. The client store still keeps only its hash; the
		// plaintext reaches the resolver through ClientSecretRegistrar. | HS512 使用 64 字节密钥
		// 签名，因此 client_secret_jwt 密钥包含 64 个随机字节，使所有启用算法可用。客户端存储仍只
		// 保存其哈希；明文经 ClientSecretRegistrar 到达解析器。
		if !issueSecret && client.SecretHash != "" {
			return "", nil
		}
		secret, err := auth.RandomToken(64)
		if err != nil {
			return "", err
		}
		client.SetSecret(secret)
		return secret, nil
	default:
		// private_key_jwt and mTLS clients authenticate with keys or certificates, so a
		// shared secret would be unused and should not be minted. | private_key_jwt 与
		// mTLS 客户端使用密钥或证书认证，共享密钥不会被使用，不应签发。
		client.SecretHash = ""
		return "", nil
	}
	if !issueSecret && client.SecretHash != "" {
		return "", nil
	}
	secret, err := auth.RandomToken(32)
	if err != nil {
		return "", err
	}
	client.SetSecret(secret)
	return secret, nil
}

// metadataFromClient projects a registered client into metadata. | metadataFromClient 把已注册客户端投影为元数据。
func metadataFromClient(client *oauth2.Client) ClientMetadata {
	if client == nil {
		return ClientMetadata{}
	}
	out := ClientMetadata{
		RedirectURIs:                      append([]string(nil), client.RedirectURIs...),
		TokenEndpointAuthMethod:           client.TokenEndpointAuthMethod,
		GrantTypes:                        append([]string(nil), client.GrantTypes...),
		ResponseTypes:                     append([]string(nil), client.ResponseTypes...),
		ClientName:                        client.Name,
		ClientURI:                         client.ClientURI,
		LogoURI:                           client.LogoURI,
		PolicyURI:                         client.PolicyURI,
		TOSURI:                            client.TOSURI,
		Contacts:                          append([]string(nil), client.Contacts...),
		Scope:                             oauth2.ScopeString(client.Scopes),
		SubjectType:                       client.SubjectType,
		SectorIdentifierURI:               client.SectorIdentifierURI,
		ApplicationType:                   client.ApplicationType,
		IDTokenSignedResponseAlg:          client.IDTokenSignedResponseAlg,
		IDTokenEncryptedResponseAlg:       client.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:       client.IDTokenEncryptedResponseEnc,
		UserInfoSignedResponseAlg:         client.UserInfoSignedResponseAlg,
		UserInfoEncryptedResponseAlg:      client.UserInfoEncryptedResponseAlg,
		UserInfoEncryptedResponseEnc:      client.UserInfoEncryptedResponseEnc,
		RequestObjectSigningAlg:           client.RequestObjectSigningAlg,
		RequestURIs:                       append([]string(nil), client.RequestURIs...),
		AuthorizationSignedResponseAlg:    client.AuthorizationSignedResponseAlg,
		TokenEndpointAuthSigningAlg:       client.TokenEndpointAuthSigningAlg,
		JWKSURI:                           client.JWKSURI,
		PostLogoutRedirectURIs:            append([]string(nil), client.PostLogoutRedirectURIs...),
		FrontchannelLogoutURI:             client.FrontchannelLogoutURI,
		FrontchannelLogoutSessionRequired: client.FrontchannelLogoutSessionRequired,
		BackchannelLogoutURI:              client.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired:  client.BackchannelLogoutSessionRequired,
		TLSClientAuthSubjectDN:            client.TLSClientAuthSubjectDN,
		TLSClientAuthSANs:                 append([]string(nil), client.TLSClientAuthSANs...),
	}
	if len(client.JWKS) > 0 {
		_ = json.Unmarshal(client.JWKS, &out.JWKS)
	}
	return out
}

// CloneForOIDC returns a deep copy of client. | CloneForOIDC 返回客户端深拷贝。
func cloneOIDCClient(c *oauth2.Client) *oauth2.Client {
	// The oauth2 client clone method is unexported; reconstruct through the JSON-free field copy
	// performed by the store on read plus a manual slice copy here. | oauth2 客户端的克隆方法未导出；
	// 通过存储读取时的字段副本加此处的切片手工复制重建。
	if c == nil {
		return nil
	}
	out := *c
	out.RedirectURIs = append([]string(nil), c.RedirectURIs...)
	out.GrantTypes = append([]string(nil), c.GrantTypes...)
	out.ResponseTypes = append([]string(nil), c.ResponseTypes...)
	out.Scopes = append([]string(nil), c.Scopes...)
	out.RequestURIs = append([]string(nil), c.RequestURIs...)
	out.PostLogoutRedirectURIs = append([]string(nil), c.PostLogoutRedirectURIs...)
	out.Contacts = append([]string(nil), c.Contacts...)
	out.TLSClientAuthSANs = append([]string(nil), c.TLSClientAuthSANs...)
	out.JWKS = append([]byte(nil), c.JWKS...)
	if len(c.Metadata) > 0 {
		out.Metadata = make(map[string]string, len(c.Metadata))
		for key, value := range c.Metadata {
			out.Metadata[key] = value
		}
	}
	return &out
}
