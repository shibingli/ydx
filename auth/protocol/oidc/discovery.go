package oidc

import (
	"net/http"

	"github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/json"
)

// DiscoveryDocument is the OpenID Connect Provider metadata document. | DiscoveryDocument 是 OpenID
// Connect 提供方元数据文档。
type DiscoveryDocument struct {
	// ServerMetadata carries the shared OAuth 2.0 metadata fields. | ServerMetadata 携带共享的 OAuth 2.0 元数据字段。
	*oauth2.ServerMetadata
	// UserInfoEndpoint is the UserInfo endpoint. | UserInfoEndpoint 是 UserInfo 端点。
	UserInfoEndpoint string `json:"userinfo_endpoint"`
	// EndSessionEndpoint is the RP-initiated logout endpoint. | EndSessionEndpoint 是 RP 发起登出端点。
	EndSessionEndpoint string `json:"end_session_endpoint,omitempty"`
	// CheckSessionIframe is the session-management iframe. | CheckSessionIframe 是会话管理 iframe。
	CheckSessionIframe string `json:"check_session_iframe,omitempty"`
	// SubjectTypesSupported lists public and pairwise. | SubjectTypesSupported 列出 public 与 pairwise。
	SubjectTypesSupported []string `json:"subject_types_supported"`
	// IDTokenSigningAlgValuesSupported lists ID-token JWS algorithms. | IDTokenSigningAlgValuesSupported 列出 ID 令牌 JWS 算法。
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	// IDTokenEncryptionAlgValuesSupported lists ID-token key-management algorithms. | IDTokenEncryptionAlgValuesSupported 列出 ID 令牌密钥管理算法。
	IDTokenEncryptionAlgValuesSupported []string `json:"id_token_encryption_alg_values_supported,omitempty"`
	// IDTokenEncryptionEncValuesSupported lists ID-token content-encryption algorithms. | IDTokenEncryptionEncValuesSupported 列出 ID 令牌内容加密算法。
	IDTokenEncryptionEncValuesSupported []string `json:"id_token_encryption_enc_values_supported,omitempty"`
	// UserInfoSigningAlgValuesSupported lists UserInfo JWS algorithms. | UserInfoSigningAlgValuesSupported 列出 UserInfo JWS 算法。
	UserInfoSigningAlgValuesSupported []string `json:"userinfo_signing_alg_values_supported,omitempty"`
	// UserInfoEncryptionAlgValuesSupported lists UserInfo key-management algorithms. | UserInfoEncryptionAlgValuesSupported 列出 UserInfo 密钥管理算法。
	UserInfoEncryptionAlgValuesSupported []string `json:"userinfo_encryption_alg_values_supported,omitempty"`
	// UserInfoEncryptionEncValuesSupported lists UserInfo content-encryption algorithms. | UserInfoEncryptionEncValuesSupported 列出 UserInfo 内容加密算法。
	UserInfoEncryptionEncValuesSupported []string `json:"userinfo_encryption_enc_values_supported,omitempty"`
	// ClaimsSupported lists the claim names the OP can supply. | ClaimsSupported 列出 OP 可提供的声明名。
	ClaimsSupported []string `json:"claims_supported"`
	// ClaimTypesSupported is normally ["normal"]. | ClaimTypesSupported 通常为 ["normal"]。
	ClaimTypesSupported []string `json:"claim_types_supported"`
	// RequestParameterSupported reports RFC 9101 request-object support. | RequestParameterSupported 报告 RFC 9101 请求对象支持。
	RequestParameterSupported bool `json:"request_parameter_supported"`
	// RequestURIParameterSupported reports request_uri support. | RequestURIParameterSupported 报告 request_uri 支持。
	RequestURIParameterSupported bool `json:"request_uri_parameter_supported"`
	// RequireRequestURIRegistration reports whether request_uri must be pre-registered. | RequireRequestURIRegistration 报告 request_uri 是否必须预注册。
	RequireRequestURIRegistration bool `json:"require_request_uri_registration"`
	// FrontchannelLogoutSupported reports front-channel logout support. | FrontchannelLogoutSupported 报告前端登出支持。
	FrontchannelLogoutSupported bool `json:"frontchannel_logout_supported"`
	// FrontchannelLogoutSessionSupported reports whether front-channel logout carries sid. | FrontchannelLogoutSessionSupported 报告前端登出是否携带 sid。
	FrontchannelLogoutSessionSupported bool `json:"frontchannel_logout_session_supported"`
	// BackchannelLogoutSupported reports back-channel logout support. | BackchannelLogoutSupported 报告后端登出支持。
	BackchannelLogoutSupported bool `json:"backchannel_logout_supported"`
	// BackchannelLogoutSessionSupported reports whether logout tokens carry sid. | BackchannelLogoutSessionSupported 报告登出令牌是否携带 sid。
	BackchannelLogoutSessionSupported bool `json:"backchannel_logout_session_supported"`
}

// Standard claims. | 标准声明。
var standardClaims = []string{
	"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "azp",
	"name", "given_name", "family_name", "middle_name", "nickname", "preferred_username",
	"profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at",
	"email", "email_verified", "phone_number", "phone_number_verified", "address",
}

// DiscoveryDocument builds the OpenID Provider metadata. | DiscoveryDocument 构建 OpenID 提供方元数据。
func (p *Provider) DiscoveryDocument() *DiscoveryDocument {
	base := p.oauth.MetadataDocument()
	subjectTypes := []string{SubjectTypePublic}
	if p.config.SubjectType == SubjectTypePairwise {
		subjectTypes = append(subjectTypes, SubjectTypePairwise)
	}
	claims := p.config.ClaimsSupported
	if len(claims) == 0 {
		claims = append([]string(nil), standardClaims...)
	}
	signingAlgs := p.signingAlgs()
	encryptionAlgs := []string{"RSA-OAEP", "RSA-OAEP-256", "A128KW", "A192KW", "A256KW", "dir"}
	encryptionEncs := []string{"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", "A192GCM", "A256GCM"}
	doc := &DiscoveryDocument{
		ServerMetadata:                       base,
		UserInfoEndpoint:                     p.Endpoint(p.config.UserInfoPath),
		SubjectTypesSupported:                subjectTypes,
		IDTokenSigningAlgValuesSupported:     signingAlgs,
		IDTokenEncryptionAlgValuesSupported:  encryptionAlgs,
		IDTokenEncryptionEncValuesSupported:  encryptionEncs,
		UserInfoSigningAlgValuesSupported:    signingAlgs,
		UserInfoEncryptionAlgValuesSupported: encryptionAlgs,
		UserInfoEncryptionEncValuesSupported: encryptionEncs,
		ClaimsSupported:                      claims,
		ClaimTypesSupported:                  []string{"normal"},
		// The OAuth metadata reflects the RFC 9101 configuration; PAR-issued request URIs are
		// advertised separately through pushed_authorization_request_endpoint. | OAuth 元数据反映
		// RFC 9101 配置；PAR 签发的请求 URI 通过 pushed_authorization_request_endpoint 单独公布。
		RequestParameterSupported:          base.RequestParameterSupported,
		RequestURIParameterSupported:       base.RequestURIParameterSupported,
		RequireRequestURIRegistration:      base.RequireRequestURIRegistration,
		FrontchannelLogoutSupported:        p.config.FrontchannelLogout,
		FrontchannelLogoutSessionSupported: p.config.FrontchannelLogout,
		BackchannelLogoutSupported:         p.config.BackchannelLogout,
		BackchannelLogoutSessionSupported:  p.config.BackchannelLogout,
	}
	if p.config.EnableLogout {
		doc.EndSessionEndpoint = p.Endpoint(p.config.EndSessionPath)
	}
	if p.config.SessionManagement {
		doc.CheckSessionIframe = p.Endpoint(p.config.CheckSessionPath)
	}
	if p.config.EnableRegistration {
		doc.RegistrationEndpoint = p.Endpoint(p.config.RegistrationPath)
	}
	return doc
}

// signingAlgs returns every JWS algorithm the provider can sign ID tokens and UserInfo with. | signingAlgs
// 返回提供方可用于签名 ID 令牌与 UserInfo 的全部 JWS 算法。
func (p *Provider) signingAlgs() []string {
	out := make([]string, 0, len(p.keys.Keys)+1)
	seen := make(map[string]bool, len(p.keys.Keys)+1)
	add := func(alg string) {
		if alg == "" || seen[alg] {
			return
		}
		seen[alg] = true
		out = append(out, alg)
	}
	add(p.signingAlg)
	for _, key := range p.keys.Keys {
		if key == nil || key.Use == "enc" {
			continue
		}
		add(key.Alg)
	}
	return out
}

// Discovery serves the OpenID Provider metadata document. | Discovery 提供 OpenID 提供方元数据文档。
func (p *Provider) Discovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed | 方法不允许")
		return
	}
	writeJSON(w, http.StatusOK, p.DiscoveryDocument())
}

// JWKS serves the published JWK Set. | JWKS 提供发布的 JWK Set。
func (p *Provider) JWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed | 方法不允许")
		return
	}
	// Always project the configured set onto public material here instead of relying on the JOSE
	// handler: the provider key set also holds the signing private key, and a regression in the
	// shared publisher must not turn this endpoint into a key-disclosure oracle. Symmetric keys
	// are omitted entirely because an "oct" key has no public half; serializing "k" would
	// disclose the HMAC secret. | 在这里始终把配置的密钥集投影为公开材料，而不依赖 JOSE
	// 处理器：提供方密钥集同时保存签名私钥，共享发布器出现回归时不能让该端点变成密钥泄露
	// 渠道。对称密钥完全省略，因为 oct 密钥没有公开部分，序列化 k 会泄露 HMAC 密钥。
	p.publicKeys().Handler().ServeHTTP(w, r)
}

// publicKeys returns the publication-only projection of the provider key set. | publicKeys 返回
// 提供方密钥集的公开发布投影。
func (p *Provider) publicKeys() *jose.KeySet {
	if p == nil || p.keys == nil {
		return &jose.KeySet{Keys: []*jose.Key{}}
	}
	out := &jose.KeySet{Keys: make([]*jose.Key, 0, len(p.keys.Keys))}
	for _, key := range p.keys.Keys {
		if key == nil || key.Kty == jose.KeyTypeOct {
			continue
		}
		out.Keys = append(out.Keys, key.Public())
	}
	return out
}

// writeJSON writes a no-store JSON response. | writeJSON 写入禁止缓存的 JSON 响应。
func writeJSON(w http.ResponseWriter, status int, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

// writeError writes an OAuth-style JSON error. | writeError 写入 OAuth 风格 JSON 错误。
func writeError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

// badRequest writes a 400 invalid_request. | badRequest 写入 400 invalid_request。
func badRequest(w http.ResponseWriter, description string) {
	writeError(w, http.StatusBadRequest, "invalid_request", description)
}

// unauthorized writes a 401 invalid_token. | unauthorized 写入 401 invalid_token。
func unauthorized(w http.ResponseWriter, description string) {
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	writeError(w, http.StatusUnauthorized, "invalid_token", description)
}

// invalidConfig converts a configuration error into a server_error response. | invalidConfig 把配置错误转换为 server_error 响应。
func invalidConfig(w http.ResponseWriter, _ error) {
	writeError(w, http.StatusInternalServerError, "server_error", "server error | 服务器错误")
}
