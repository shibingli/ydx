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
	// GrantTypes and ResponseTypes list the allowed grants and responses. | GrantTypes 与 ResponseTypes 列出允许的授权与响应类型。
	GrantTypes    []string `json:"grant_types,omitempty"`
	ResponseTypes []string `json:"response_types,omitempty"`
	// ClientName, ClientURI, LogoURI, PolicyURI and TOSURI are display metadata. | ClientName、ClientURI、LogoURI、PolicyURI 与 TOSURI 是展示元数据。
	ClientName string `json:"client_name,omitempty"`
	ClientURI  string `json:"client_uri,omitempty"`
	LogoURI    string `json:"logo_uri,omitempty"`
	PolicyURI  string `json:"policy_uri,omitempty"`
	TOSURI     string `json:"tos_uri,omitempty"`
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
	// IDTokenSignedResponseAlg and related fields select per-client JOSE algorithms. | IDTokenSignedResponseAlg 及相关字段选择每客户端 JOSE 算法。
	IDTokenSignedResponseAlg     string `json:"id_token_signed_response_alg,omitempty"`
	IDTokenEncryptedResponseAlg  string `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenEncryptedResponseEnc  string `json:"id_token_encrypted_response_enc,omitempty"`
	UserInfoSignedResponseAlg    string `json:"userinfo_signed_response_alg,omitempty"`
	UserInfoEncryptedResponseAlg string `json:"userinfo_encrypted_response_alg,omitempty"`
	UserInfoEncryptedResponseEnc string `json:"userinfo_encrypted_response_enc,omitempty"`
	RequestObjectSigningAlg      string `json:"request_object_signing_alg,omitempty"`
	// RequestURIs are the RFC 9101 by-reference request object URLs the client may use. |
	// RequestURIs 是客户端可使用的 RFC 9101 按引用请求对象 URL。
	RequestURIs []string `json:"request_uris,omitempty"`
	// AuthorizationSignedResponseAlg selects the JARM response JWS algorithm. | AuthorizationSignedResponseAlg
	// 选择 JARM 响应 JWS 算法。
	AuthorizationSignedResponseAlg string `json:"authorization_signed_response_alg,omitempty"`
	TokenEndpointAuthSigningAlg    string `json:"token_endpoint_auth_signing_alg,omitempty"`
	// JWKSURI and JWKS carry the client's public keys. | JWKSURI 与 JWKS 携带客户端公钥。
	JWKSURI string         `json:"jwks_uri,omitempty"`
	JWKS    map[string]any `json:"jwks,omitempty"`
	// PostLogoutRedirectURIs are the allowed logout redirect URIs. | PostLogoutRedirectURIs 是允许的登出重定向 URI。
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty"`
	// FrontchannelLogoutURI and BackchannelLogoutURI configure logout delivery. | FrontchannelLogoutURI 与 BackchannelLogoutURI 配置登出投递。
	FrontchannelLogoutURI             string `json:"frontchannel_logout_uri,omitempty"`
	FrontchannelLogoutSessionRequired bool   `json:"frontchannel_logout_session_required,omitempty"`
	BackchannelLogoutURI              string `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired  bool   `json:"backchannel_logout_session_required,omitempty"`
	// TLSClientAuthSubjectDN and TLSClientAuthSANs configure mTLS registration. | TLSClientAuthSubjectDN 与 TLSClientAuthSANs 配置 mTLS 注册。
	TLSClientAuthSubjectDN string   `json:"tls_client_auth_subject_dn,omitempty"`
	TLSClientAuthSANs      []string `json:"tls_client_auth_san_dns,omitempty"`
}

// RegistrationResponse is the RFC 7591 registration response. | RegistrationResponse 是 RFC 7591 注册响应。
type RegistrationResponse struct {
	// ClientID is the issued client identifier. | ClientID 是签发的客户端标识。
	ClientID string `json:"client_id"`
	// ClientSecret is returned once for confidential clients. | ClientSecret 对机密客户端返回一次。
	ClientSecret string `json:"client_secret,omitempty"`
	// ClientIDIssuedAt and ClientSecretExpiresAt are Unix seconds; zero means no expiry. | ClientIDIssuedAt 与 ClientSecretExpiresAt 是 Unix 秒；零表示不过期。
	ClientIDIssuedAt      int64 `json:"client_id_issued_at"`
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
	if err := validateClientMetadata(&metadata); err != nil {
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
		if err := validateClientMetadata(&metadata); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
			return
		}
		updated := cloneOIDCClient(client)
		updated.UpdatedAt = p.Now()
		if _, err := applyClientMetadata(updated, &metadata, false); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
			return
		}
		updated.RegistrationAccessTokenHash = client.RegistrationAccessTokenHash
		updated.RegistrationClientURI = client.RegistrationClientURI
		if err := p.oauth.Config().Clients.UpdateClient(r.Context(), updated); err != nil {
			invalidConfig(w, err)
			return
		}
		writeJSON(w, http.StatusOK, RegistrationResponse{
			ClientID:              updated.ID,
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

// validateClientMetadata validates registration metadata. | validateClientMetadata 校验注册元数据。
func validateClientMetadata(metadata *ClientMetadata) error {
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
	default:
		return errs.Detail(ErrInvalidRequest, "unsupported token_endpoint_auth_method | 不支持的 token_endpoint_auth_method")
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
	if client.TokenEndpointAuthMethod != oauth2.ClientSecretBasic && client.TokenEndpointAuthMethod != oauth2.ClientSecretPost {
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
