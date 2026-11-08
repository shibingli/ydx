package federation

import "strings"

// ExtraMicrosoftTenant selects the Microsoft Entra ID tenant. | ExtraMicrosoftTenant 选择 Microsoft Entra ID 租户。
const ExtraMicrosoftTenant = "microsoft_tenant"

// applyPreset constructs a preset provider and applies config and options. | applyPreset
// 构建预设提供方并应用配置与选项。
func applyPreset(name, displayName, kind string, defaults Provider, config ProviderConfig, options []ProviderOption) *Provider {
	p := &Provider{
		Name:            name,
		DisplayName:     displayName,
		Kind:            kind,
		Scopes:          append([]string(nil), defaults.Scopes...),
		ScopeSeparator:  defaults.ScopeSeparator,
		AuthURL:         defaults.AuthURL,
		TokenURL:        defaults.TokenURL,
		UserInfoURL:     defaults.UserInfoURL,
		JWKSURL:         defaults.JWKSURL,
		Issuer:          defaults.Issuer,
		UseOIDC:         defaults.UseOIDC,
		PKCE:            defaults.PKCE,
		Nonce:           defaults.Nonce,
		AuthStyle:       defaults.AuthStyle,
		AuthParams:      cloneMap(defaults.AuthParams),
		TokenParams:     cloneMap(defaults.TokenParams),
		UserInfoHeaders: cloneMap(defaults.UserInfoHeaders),
		Extra:           cloneMap(defaults.Extra),
		PrivateKey:      defaults.PrivateKey,
		AuthURLHook:     defaults.AuthURLHook,
		ExchangeHook:    defaults.ExchangeHook,
		UserInfoHook:    defaults.UserInfoHook,
		Adapter:         defaults.Adapter,
	}
	if config.Name != "" {
		p.Name = strings.TrimSpace(config.Name)
	}
	if config.DisplayName != "" {
		p.DisplayName = config.DisplayName
	}
	if config.Kind != "" {
		p.Kind = config.Kind
	}
	p.ClientID = config.ClientID
	p.ClientSecret = config.ClientSecret
	p.RedirectURL = config.RedirectURL
	if len(config.Scopes) > 0 {
		p.Scopes = append([]string(nil), config.Scopes...)
	}
	if config.AuthURL != "" {
		p.AuthURL = config.AuthURL
	}
	if config.TokenURL != "" {
		p.TokenURL = config.TokenURL
	}
	if config.UserInfoURL != "" {
		p.UserInfoURL = config.UserInfoURL
	}
	if config.JWKSURL != "" {
		p.JWKSURL = config.JWKSURL
	}
	if config.Issuer != "" {
		p.Issuer = config.Issuer
	}
	if config.UseOIDC {
		p.UseOIDC = true
	}
	if config.PKCE {
		p.PKCE = true
	}
	if config.Nonce {
		p.Nonce = true
	}
	if config.DiscoveryTTL != 0 {
		p.DiscoveryTTL = config.DiscoveryTTL
	}
	if config.DiscoveryTTLMin != 0 {
		p.DiscoveryTTLMin = config.DiscoveryTTLMin
	}
	if config.DiscoveryTTLMax != 0 {
		p.DiscoveryTTLMax = config.DiscoveryTTLMax
	}
	if config.DiscoveryJitter != 0 {
		p.DiscoveryJitter = config.DiscoveryJitter
	}
	if config.DiscoveryMaxStale != 0 {
		p.DiscoveryMaxStale = config.DiscoveryMaxStale
	}
	if config.AuthStyle != "" {
		p.AuthStyle = config.AuthStyle
	}
	if config.PrivateKey != "" {
		p.PrivateKey = config.PrivateKey
	}
	if config.HTTPClient != nil {
		p.HTTPClient = config.HTTPClient
	}
	mergeExtra(p, config.Extra)
	if len(config.AuthParams) > 0 {
		if p.AuthParams == nil {
			p.AuthParams = make(map[string]string)
		}
		for key, value := range config.AuthParams {
			p.AuthParams[key] = value
		}
	}
	if len(config.TokenParams) > 0 {
		if p.TokenParams == nil {
			p.TokenParams = make(map[string]string)
		}
		for key, value := range config.TokenParams {
			p.TokenParams[key] = value
		}
	}
	if len(config.UserInfoHeaders) > 0 {
		if p.UserInfoHeaders == nil {
			p.UserInfoHeaders = make(map[string]string)
		}
		for key, value := range config.UserInfoHeaders {
			p.UserInfoHeaders[key] = value
		}
	}
	applyOptions(p, options)
	return p
}

// Google returns a Google OpenID Connect provider preset. | Google 返回 Google OpenID Connect 提供方预设。
func Google(config ProviderConfig, options ...ProviderOption) *Provider {
	return applyPreset("google", "Google", KindOIDC, Provider{
		Scopes:      []string{"openid", "email", "profile"},
		AuthURL:     "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:    "https://oauth2.googleapis.com/token",
		UserInfoURL: "https://openidconnect.googleapis.com/v1/userinfo",
		JWKSURL:     "https://www.googleapis.com/oauth2/v3/certs",
		Issuer:      "https://accounts.google.com",
		UseOIDC:     true,
		PKCE:        true,
		Nonce:       true,
	}, config, options)
}

// Microsoft returns a Microsoft Entra ID v2 provider preset. Set
// ExtraMicrosoftTenant to a tenant ID for single-tenant applications; the default
// is common. | Microsoft 返回 Microsoft Entra ID v2 提供方预设。单租户应用应把
// ExtraMicrosoftTenant 设为租户标识，默认值为 common。
func Microsoft(config ProviderConfig, options ...ProviderOption) *Provider {
	tenant := "common"
	if value := strings.TrimSpace(config.Extra[ExtraMicrosoftTenant]); value != "" {
		tenant = value
	}
	base := "https://login.microsoftonline.com/" + tenant
	return applyPreset("microsoft", "Microsoft Entra ID", KindOIDC, Provider{
		Scopes:      []string{"openid", "profile", "email"},
		AuthURL:     base + "/oauth2/v2.0/authorize",
		TokenURL:    base + "/oauth2/v2.0/token",
		UserInfoURL: "https://graph.microsoft.com/oidc/userinfo",
		JWKSURL:     base + "/discovery/v2.0/keys",
		Issuer:      base + "/v2.0",
		UseOIDC:     true,
		PKCE:        true,
		Nonce:       true,
		AuthParams:  map[string]string{"prompt": "select_account"},
		Extra:       map[string]string{ExtraMicrosoftTenant: tenant},
	}, config, options)
}

// GitHub returns a GitHub OAuth 2.0 provider preset. Email is linked only when the
// upstream response marks it verified; GitHub login names are mapped to Username. |
// GitHub 返回 GitHub OAuth 2.0 提供方预设。只有上游响应标记邮箱已验证时才可用于关联；
// GitHub 登录名映射到 Username。
func GitHub(config ProviderConfig, options ...ProviderOption) *Provider {
	return applyPreset("github", "GitHub", KindOAuth2, Provider{
		Scopes:      []string{"read:user", "user:email"},
		AuthURL:     "https://github.com/login/oauth/authorize",
		TokenURL:    "https://github.com/login/oauth/access_token",
		UserInfoURL: "https://api.github.com/user",
		UserInfoHeaders: map[string]string{
			"Accept": "application/vnd.github+json",
		},
		PKCE:      true,
		AuthStyle: AuthStylePost,
	}, config, options)
}

// Apple returns an Apple Sign in provider preset. ClientSecret must be the
// generated ES256 client-secret JWT. Apple returns no UserInfo endpoint, so the
// verified ID token claims are used. | Apple 返回 Apple 登录提供方预设。ClientSecret 必须是
// 生成的 ES256 客户端密钥 JWT。Apple 不提供 UserInfo 端点，因此使用已校验的 ID 令牌声明。
func Apple(config ProviderConfig, options ...ProviderOption) *Provider {
	return applyPreset("apple", "Apple", KindOIDC, Provider{
		Scopes:     []string{"name", "email"},
		AuthURL:    "https://appleid.apple.com/auth/authorize",
		TokenURL:   "https://appleid.apple.com/auth/token",
		JWKSURL:    "https://appleid.apple.com/auth/keys",
		Issuer:     "https://appleid.apple.com",
		UseOIDC:    true,
		PKCE:       true,
		Nonce:      true,
		AuthParams: map[string]string{"response_mode": "form_post"},
	}, config, options)
}

// Facebook returns a Facebook Login provider preset. | Facebook 返回 Facebook 登录提供方预设。
func Facebook(config ProviderConfig, options ...ProviderOption) *Provider {
	return applyPreset("facebook", "Facebook", KindOAuth2, Provider{
		Scopes:         []string{"email", "public_profile"},
		ScopeSeparator: ",",
		AuthURL:        "https://www.facebook.com/v19.0/dialog/oauth",
		TokenURL:       "https://graph.facebook.com/v19.0/oauth/access_token",
		UserInfoURL:    "https://graph.facebook.com/v19.0/me?fields=id,name,email,picture.type(large)",
		PKCE:           true,
		UserInfoHook:   facebookUserInfo,
	}, config, options)
}

// GitLab returns a GitLab OpenID Connect provider preset for gitlab.com. | GitLab
// 返回 gitlab.com 的 GitLab OpenID Connect 提供方预设。
func GitLab(config ProviderConfig, options ...ProviderOption) *Provider {
	return applyPreset("gitlab", "GitLab", KindOIDC, Provider{
		Scopes:      []string{"openid", "profile", "email"},
		AuthURL:     "https://gitlab.com/oauth/authorize",
		TokenURL:    "https://gitlab.com/oauth/token",
		UserInfoURL: "https://gitlab.com/oauth/userinfo",
		JWKSURL:     "https://gitlab.com/oauth/discovery/keys",
		Issuer:      "https://gitlab.com",
		UseOIDC:     true,
		PKCE:        true,
		Nonce:       true,
	}, config, options)
}

// Okta returns an Okta OpenID Connect preset for an issuer such as
// https://example.okta.com. | Okta 返回指定 issuer（例如 https://example.okta.com）的 Okta
// OpenID Connect 预设。
func Okta(issuer string, config ProviderConfig, options ...ProviderOption) *Provider {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	p := applyPreset("okta", "Okta", KindOIDC, Provider{
		Scopes:      []string{"openid", "profile", "email"},
		AuthURL:     issuer + "/v1/authorize",
		TokenURL:    issuer + "/v1/token",
		UserInfoURL: issuer + "/v1/userinfo",
		JWKSURL:     issuer + "/v1/keys",
		Issuer:      issuer,
		UseOIDC:     true,
		PKCE:        true,
		Nonce:       true,
	}, config, options)
	return p
}

// Auth0 returns an Auth0 OpenID Connect preset for a domain such as
// example.us.auth0.com or https://example.us.auth0.com. | Auth0 返回指定域（例如
// example.us.auth0.com 或 https://example.us.auth0.com）的 Auth0 OpenID Connect 预设。
func Auth0(domain string, config ProviderConfig, options ...ProviderOption) *Provider {
	domain = normalizeDomain(domain)
	return applyPreset("auth0", "Auth0", KindOIDC, Provider{
		Scopes:      []string{"openid", "profile", "email"},
		AuthURL:     domain + "/authorize",
		TokenURL:    domain + "/oauth/token",
		UserInfoURL: domain + "/userinfo",
		JWKSURL:     domain + "/.well-known/jwks.json",
		Issuer:      domain + "/",
		UseOIDC:     true,
		PKCE:        true,
		Nonce:       true,
		AuthParams:  map[string]string{"prompt": "login"},
	}, config, options)
}

// Keycloak returns a Keycloak OpenID Connect preset for a base URL and realm. | Keycloak
// 返回指定基础 URL 与 realm 的 Keycloak OpenID Connect 预设。
func Keycloak(baseURL, realm string, config ProviderConfig, options ...ProviderOption) *Provider {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	realm = strings.Trim(strings.TrimSpace(realm), "/")
	issuer := baseURL + "/realms/" + realm
	return applyPreset("keycloak", "Keycloak", KindOIDC, Provider{
		Scopes:      []string{"openid", "profile", "email"},
		AuthURL:     issuer + "/protocol/openid-connect/auth",
		TokenURL:    issuer + "/protocol/openid-connect/token",
		UserInfoURL: issuer + "/protocol/openid-connect/userinfo",
		JWKSURL:     issuer + "/protocol/openid-connect/certs",
		Issuer:      issuer,
		UseOIDC:     true,
		PKCE:        true,
		Nonce:       true,
	}, config, options)
}

// normalizeDomain adds an https scheme and removes a trailing slash. | normalizeDomain
// 添加 https 协议并移除末尾斜杠。
func normalizeDomain(domain string) string {
	domain = strings.TrimRight(strings.TrimSpace(domain), "/")
	if domain == "" {
		return ""
	}
	if !strings.HasPrefix(domain, "https://") && !strings.HasPrefix(domain, "http://") {
		domain = "https://" + domain
	}
	return domain
}
