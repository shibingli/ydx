package federation

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Extra keys and account types used by Chinese provider presets. | 中国提供方预设使用的扩展键与账号类型。
const (
	// ExtraWeChatAccountType selects WeChat Open Platform (open) or Official Account (mp).
	// ExtraWeChatAccountType 选择微信开放平台（open）或公众号（mp）。
	ExtraWeChatAccountType = "wechat_account_type"
	// WeChatAccountOpenPlatform is the WeChat website application (qrconnect) flow.
	// WeChatAccountOpenPlatform 是微信网站应用（qrconnect）流程。
	WeChatAccountOpenPlatform = "open"
	// WeChatAccountOfficialAccount is the WeChat Official Account (oauth2/authorize) flow.
	// WeChatAccountOfficialAccount 是微信公众号（oauth2/authorize）流程。
	WeChatAccountOfficialAccount = "mp"
	// ExtraWeChatLang selects the WeChat UserInfo language, for example zh_CN.
	// ExtraWeChatLang 选择微信 UserInfo 语言，例如 zh_CN。
	ExtraWeChatLang = "wechat_lang"
	// ExtraQQOpenIDURL overrides the QQ OpenID endpoint derived from TokenURL.
	// ExtraQQOpenIDURL 覆盖由 TokenURL 推导的 QQ OpenID 端点。
	ExtraQQOpenIDURL = "qq_openid_url"
	// ExtraWeComAuthUserInfoURL overrides the WeCom code-to-user endpoint.
	// ExtraWeComAuthUserInfoURL 覆盖企业微信 code 换用户端点。
	ExtraWeComAuthUserInfoURL = "wecom_auth_userinfo_url"
	// ExtraAlipayPrivateKey supplies the Alipay RSA2 private key when Provider.PrivateKey is empty.
	// ExtraAlipayPrivateKey 在 Provider.PrivateKey 为空时提供支付宝 RSA2 私钥。
	ExtraAlipayPrivateKey = "alipay_private_key"
)

// Default Chinese provider endpoints. | 中国提供方默认端点。
const (
	defaultWeChatOpenAuthURL     = "https://open.weixin.qq.com/connect/qrconnect"
	defaultWeChatOfficialAuthURL = "https://open.weixin.qq.com/connect/oauth2/authorize"
	defaultWeChatTokenURL        = "https://api.weixin.qq.com/sns/oauth2/access_token"
	defaultWeChatUserInfoURL     = "https://api.weixin.qq.com/sns/userinfo"
	defaultAlipayAuthURL         = "https://openauth.alipay.com/oauth2/publicAppAuthorize.htm"
	defaultAlipayGatewayURL      = "https://openapi.alipay.com/gateway.do"
	defaultDingTalkAuthURL       = "https://login.dingtalk.com/oauth2/auth"
	defaultDingTalkTokenURL      = "https://api.dingtalk.com/v1.0/oauth2/userAccessToken"
	defaultDingTalkUserInfoURL   = "https://api.dingtalk.com/v1.0/contact/users/me"
	defaultFeishuAuthURL         = "https://open.feishu.cn/open-apis/authen/v1/authorize"
	defaultFeishuTokenURL        = "https://open.feishu.cn/open-apis/authen/v1/oidc/access_token"
	defaultFeishuUserInfoURL     = "https://open.feishu.cn/open-apis/authen/v1/user_info"
	defaultWeComAuthURL          = "https://open.weixin.qq.com/connect/oauth2/authorize"
	defaultWeComTokenURL         = "https://qyapi.weixin.qq.com/cgi-bin/gettoken"
	defaultWeComAuthUserInfoURL  = "https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo"
	defaultWeComUserInfoURL      = "https://qyapi.weixin.qq.com/cgi-bin/user/get"
	defaultQQAuthURL             = "https://graph.qq.com/oauth2.0/authorize"
	defaultQQTokenURL            = "https://graph.qq.com/oauth2.0/token"
	defaultQQOpenIDURL           = "https://graph.qq.com/oauth2.0/me"
	defaultQQUserInfoURL         = "https://graph.qq.com/user/get_user_info"
	defaultWeiboAuthURL          = "https://api.weibo.com/oauth2/authorize"
	defaultWeiboTokenURL         = "https://api.weibo.com/oauth2/access_token"
	defaultWeiboUserInfoURL      = "https://api.weibo.com/2/users/show.json"
	defaultBaiduAuthURL          = "https://openapi.baidu.com/oauth/2.0/authorize"
	defaultBaiduTokenURL         = "https://openapi.baidu.com/oauth/2.0/token"
	defaultBaiduUserInfoURL      = "https://openapi.baidu.com/rest/2.0/passport/users/getInfo"
	defaultGiteeAuthURL          = "https://gitee.com/oauth/authorize"
	defaultGiteeTokenURL         = "https://gitee.com/oauth/token"
	defaultGiteeUserInfoURL      = "https://gitee.com/api/v5/user"
)

// WeChat returns a WeChat provider preset. The default is the Open Platform
// qrconnect flow with snsapi_login; set ExtraWeChatAccountType to
// WeChatAccountOfficialAccount for the Official Account oauth2 flow with
// snsapi_userinfo. Subject prefers unionid over openid. | WeChat 返回微信提供方预设。默认使用
// 开放平台 qrconnect 流程与 snsapi_login；把 ExtraWeChatAccountType 设为
// WeChatAccountOfficialAccount 可切换为公众号 oauth2 流程与 snsapi_userinfo。Subject 优先 unionid，
// 其次 openid。
func WeChat(config ProviderConfig, options ...ProviderOption) *Provider {
	account := strings.ToLower(strings.TrimSpace(config.Extra[ExtraWeChatAccountType]))
	official := account == WeChatAccountOfficialAccount || account == "official" || account == "official_account" || account == "public"
	authURL := defaultWeChatOpenAuthURL
	scope := "snsapi_login"
	accountType := WeChatAccountOpenPlatform
	if official {
		authURL = defaultWeChatOfficialAuthURL
		scope = "snsapi_userinfo"
		accountType = WeChatAccountOfficialAccount
	}
	return applyPreset("wechat", "WeChat", KindWeChat, Provider{
		Scopes:       []string{scope},
		AuthURL:      authURL,
		TokenURL:     defaultWeChatTokenURL,
		UserInfoURL:  defaultWeChatUserInfoURL,
		AuthURLHook:  wechatAuthURL,
		ExchangeHook: wechatExchange,
		UserInfoHook: wechatUserInfo,
		Extra:        map[string]string{ExtraWeChatAccountType: accountType},
	}, config, options)
}

// Alipay returns an Alipay provider preset. It signs alipay.system.oauth.token and
// alipay.user.info.share with RSA2 (SHA256withRSA). Provider.PrivateKey or
// ExtraAlipayPrivateKey must contain the application private key. | Alipay 返回支付宝提供方预设。
// 它使用 RSA2（SHA256withRSA）为 alipay.system.oauth.token 与 alipay.user.info.share 签名。
// Provider.PrivateKey 或 ExtraAlipayPrivateKey 必须包含应用私钥。
func Alipay(config ProviderConfig, options ...ProviderOption) *Provider {
	return applyPreset("alipay", "Alipay", KindAlipay, Provider{
		Scopes:       []string{"auth_user"},
		AuthURL:      defaultAlipayAuthURL,
		TokenURL:     defaultAlipayGatewayURL,
		UserInfoURL:  defaultAlipayGatewayURL,
		AuthURLHook:  alipayAuthURL,
		ExchangeHook: alipayExchange,
		UserInfoHook: alipayUserInfo,
	}, config, options)
}

// DingTalk returns a DingTalk provider preset. Its token and UserInfo endpoints
// use the JSON v1.0 APIs and the x-acs-dingtalk-access-token header. | DingTalk 返回钉钉提供方
// 预设。其令牌与 UserInfo 端点使用 JSON v1.0 API 与 x-acs-dingtalk-access-token 请求头。
func DingTalk(config ProviderConfig, options ...ProviderOption) *Provider {
	return applyPreset("dingtalk", "DingTalk", KindDingTalk, Provider{
		Scopes:       []string{"openid"},
		AuthURL:      defaultDingTalkAuthURL,
		TokenURL:     defaultDingTalkTokenURL,
		UserInfoURL:  defaultDingTalkUserInfoURL,
		AuthParams:   map[string]string{"prompt": "consent"},
		ExchangeHook: dingTalkExchange,
		UserInfoHook: dingTalkUserInfo,
	}, config, options)
}

// Feishu returns a Feishu / Lark provider preset. Token exchange uses the OIDC
// access_token endpoint with client_id and client_secret in a JSON body. | Feishu 返回飞书 / Lark
// 提供方预设。令牌兑换使用 OIDC access_token 端点，并以 JSON 体发送 client_id 与 client_secret。
func Feishu(config ProviderConfig, options ...ProviderOption) *Provider {
	return applyPreset("feishu", "Feishu / Lark", KindFeishu, Provider{
		Scopes:       []string{"contact:user.base:readonly"},
		AuthURL:      defaultFeishuAuthURL,
		TokenURL:     defaultFeishuTokenURL,
		UserInfoURL:  defaultFeishuUserInfoURL,
		AuthURLHook:  feishuAuthURL,
		ExchangeHook: feishuExchange,
		UserInfoHook: feishuUserInfo,
	}, config, options)
}

// WeCom returns a WeCom (WeChat Work) provider preset. It exchanges the code at
// cgi-bin/auth/getuserinfo and, for internal users, enriches the identity from
// cgi-bin/user/get. | WeCom 返回企业微信提供方预设。它在 cgi-bin/auth/getuserinfo 兑换 code，
// 并对内部用户从 cgi-bin/user/get 补充身份信息。
func WeCom(config ProviderConfig, options ...ProviderOption) *Provider {
	return applyPreset("wecom", "WeCom", KindWeCom, Provider{
		Scopes:       []string{"snsapi_base"},
		AuthURL:      defaultWeComAuthURL,
		TokenURL:     defaultWeComTokenURL,
		UserInfoURL:  defaultWeComUserInfoURL,
		AuthURLHook:  wecomAuthURL,
		ExchangeHook: wecomExchange,
		UserInfoHook: wecomUserInfo,
	}, config, options)
}

// QQ returns a QQ Connect provider preset. The OpenID is fetched from the
// oauth2.0/me endpoint during token exchange. | QQ 返回 QQ 互联提供方预设。OpenID 在令牌兑换
// 期间从 oauth2.0/me 端点获取。
func QQ(config ProviderConfig, options ...ProviderOption) *Provider {
	return applyPreset("qq", "QQ", KindQQ, Provider{
		Scopes:       []string{"get_user_info"},
		AuthURL:      defaultQQAuthURL,
		TokenURL:     defaultQQTokenURL,
		UserInfoURL:  defaultQQUserInfoURL,
		ExchangeHook: qqExchange,
		UserInfoHook: qqUserInfo,
	}, config, options)
}

// Weibo returns a Sina Weibo provider preset. | Weibo 返回新浪微博提供方预设。
func Weibo(config ProviderConfig, options ...ProviderOption) *Provider {
	return applyPreset("weibo", "Weibo", KindWeibo, Provider{
		Scopes:       []string{"email"},
		AuthURL:      defaultWeiboAuthURL,
		TokenURL:     defaultWeiboTokenURL,
		UserInfoURL:  defaultWeiboUserInfoURL,
		UserInfoHook: weiboUserInfo,
	}, config, options)
}

// Baidu returns a Baidu Passport provider preset. | Baidu 返回百度账号提供方预设。
func Baidu(config ProviderConfig, options ...ProviderOption) *Provider {
	return applyPreset("baidu", "Baidu", KindBaidu, Provider{
		Scopes:       []string{"basic"},
		AuthURL:      defaultBaiduAuthURL,
		TokenURL:     defaultBaiduTokenURL,
		UserInfoURL:  defaultBaiduUserInfoURL,
		UserInfoHook: baiduUserInfo,
	}, config, options)
}

// Gitee returns a Gitee provider preset. | Gitee 返回 Gitee 提供方预设。
func Gitee(config ProviderConfig, options ...ProviderOption) *Provider {
	return applyPreset("gitee", "Gitee", KindGitee, Provider{
		Scopes:       []string{"user_info"},
		AuthURL:      defaultGiteeAuthURL,
		TokenURL:     defaultGiteeTokenURL,
		UserInfoURL:  defaultGiteeUserInfoURL,
		AuthStyle:    AuthStylePost,
		UserInfoHook: giteeUserInfo,
	}, config, options)
}

// wechatAuthURL builds the WeChat QR or Official Account authorization URL. | wechatAuthURL
// 构建微信扫码或公众号授权 URL。
func wechatAuthURL(p *Provider, state, _, _ string) (string, error) {
	params := map[string]string{
		"appid":         p.ClientID,
		"redirect_uri":  p.RedirectURL,
		"response_type": "code",
		"scope":         scopeValue(p),
		"state":         state,
	}
	for key, value := range p.AuthParams {
		params[key] = value
	}
	endpoint, err := setQueryParams(p.AuthURL, params)
	if err != nil {
		return "", err
	}
	return setURLFragment(endpoint, "wechat_redirect")
}

// wechatExchange redeems a WeChat code with the sns/oauth2 access_token API. | wechatExchange
// 使用 sns/oauth2 access_token API 兑换微信 code。
func wechatExchange(ctx context.Context, p *Provider, client *http.Client, code, _ string) (*Token, error) {
	endpoint, err := appendQuery(p.TokenURL, map[string]string{
		"appid":      p.ClientID,
		"secret":     p.ClientSecret,
		"code":       code,
		"grant_type": "authorization_code",
	})
	if err != nil {
		return nil, errs.Wrap(err, ErrTokenExchange)
	}
	status, body, err := getProvider(ctx, client, endpoint, nil)
	if err != nil {
		return nil, errs.Wrap(err, ErrTokenExchange)
	}
	if status != http.StatusOK {
		return nil, tokenHTTPError(status, body)
	}
	token, err := tokenFromBody(body, time.Now())
	if err != nil {
		return nil, errs.Wrap(err, ErrTokenExchange)
	}
	if token.OpenID == "" {
		token.OpenID = token.Raw["openid"]
	}
	if token.UnionID == "" {
		token.UnionID = token.Raw["unionid"]
	}
	return token, nil
}

// wechatUserInfo calls sns/userinfo and prefers unionid as the subject. | wechatUserInfo
// 调用 sns/userinfo 并优先使用 unionid 作为主体。
func wechatUserInfo(ctx context.Context, p *Provider, client *http.Client, token *Token) (*Identity, error) {
	openID := firstNonEmpty(token.OpenID, token.Raw["openid"])
	if openID == "" {
		return nil, errs.Detail(ErrUserInfo, "wechat token has no openid | 微信令牌缺少 openid")
	}
	language := firstNonEmpty(p.Extra[ExtraWeChatLang], "zh_CN")
	endpoint, err := appendQuery(p.UserInfoURL, map[string]string{
		"access_token": token.AccessToken,
		"openid":       openID,
		"lang":         language,
	})
	if err != nil {
		return nil, errs.Wrap(err, ErrUserInfo)
	}
	status, body, err := getProvider(ctx, client, endpoint, nil)
	if err != nil {
		return nil, errs.Wrap(err, ErrUserInfo)
	}
	if status != http.StatusOK {
		return nil, providerStatusError(ErrUserInfo, p.Name, "UserInfo", status)
	}
	raw, err := parseJSONObject(body)
	if err != nil {
		return nil, errs.Detail(ErrUserInfo, "wechat UserInfo is invalid | 微信 UserInfo 非法")
	}
	if code := providerErrorCode(raw); code != "" {
		return nil, errs.Detail(ErrUserInfo, "wechat UserInfo returned %s | 微信 UserInfo 返回 %s", code, code)
	}
	identity := identityFromMap(p.Name, raw)
	identity.Subject = firstNonEmpty(stringValue(raw["unionid"]), stringValue(raw["openid"]), openID)
	if identity.Subject == "" {
		return nil, errs.Detail(ErrUserInfo, "wechat UserInfo has no openid or unionid | 微信 UserInfo 缺少 openid 或 unionid")
	}
	identity.Email = ""
	identity.EmailVerified = false
	identity.Username = ""
	identity.Name = firstNonEmpty(stringValue(raw["nickname"]), identity.Name)
	identity.AvatarURL = firstNonEmpty(stringValue(raw["headimgurl"]), identity.AvatarURL)
	return identity, nil
}

// alipayAuthURL builds the Alipay public application authorization URL. | alipayAuthURL
// 构建支付宝公众应用授权 URL。
func alipayAuthURL(p *Provider, state, _, _ string) (string, error) {
	params := map[string]string{
		"app_id":       p.ClientID,
		"scope":        scopeValue(p),
		"redirect_uri": p.RedirectURL,
		"state":        state,
	}
	for key, value := range p.AuthParams {
		params[key] = value
	}
	return setQueryParams(p.AuthURL, params)
}

// alipayExchange calls alipay.system.oauth.token with an RSA2 signature. | alipayExchange
// 使用 RSA2 签名调用 alipay.system.oauth.token。
func alipayExchange(ctx context.Context, p *Provider, client *http.Client, code, _ string) (*Token, error) {
	params := alipayBaseParams(p, "alipay.system.oauth.token")
	params["grant_type"] = "authorization_code"
	params["code"] = code
	for key, value := range p.TokenParams {
		if value == "" {
			delete(params, key)
		} else {
			params[key] = value
		}
	}
	if err := signAlipayRequest(params, privateKeyFor(p)); err != nil {
		return nil, errs.Wrap(err, ErrTokenExchange)
	}
	status, body, err := postForm(ctx, client, p.TokenURL, mapValues(params), nil)
	if err != nil {
		return nil, errs.Wrap(err, ErrTokenExchange)
	}
	if status != http.StatusOK {
		return nil, tokenHTTPError(status, body)
	}
	raw, err := parseJSONObject(body)
	if err != nil {
		return nil, errs.Detail(ErrTokenExchange, "alipay token response is invalid | 支付宝令牌响应非法")
	}
	response, err := alipayResponse(p, raw, "alipay_system_oauth_token_response", ErrTokenExchange)
	if err != nil {
		return nil, err
	}
	token, err := tokenFromMap(response, time.Now())
	if err != nil {
		return nil, errs.Wrap(err, ErrTokenExchange)
	}
	if token.OpenID == "" {
		token.OpenID = token.Raw["open_id"]
	}
	return token, nil
}

// alipayUserInfo calls alipay.user.info.share with an RSA2 signature. | alipayUserInfo
// 使用 RSA2 签名调用 alipay.user.info.share。
func alipayUserInfo(ctx context.Context, p *Provider, client *http.Client, token *Token) (*Identity, error) {
	if token == nil || token.AccessToken == "" {
		return nil, errs.Detail(ErrUserInfo, "alipay token has no access token | 支付宝令牌缺少访问令牌")
	}
	params := alipayBaseParams(p, "alipay.user.info.share")
	params["auth_token"] = token.AccessToken
	if err := signAlipayRequest(params, privateKeyFor(p)); err != nil {
		return nil, errs.Wrap(err, ErrUserInfo)
	}
	status, body, err := postForm(ctx, client, p.UserInfoURL, mapValues(params), nil)
	if err != nil {
		return nil, errs.Wrap(err, ErrUserInfo)
	}
	if status != http.StatusOK {
		return nil, providerStatusError(ErrUserInfo, p.Name, "UserInfo", status)
	}
	raw, err := parseJSONObject(body)
	if err != nil {
		return nil, errs.Detail(ErrUserInfo, "alipay UserInfo is invalid | 支付宝 UserInfo 非法")
	}
	response, err := alipayResponse(p, raw, "alipay_user_info_share_response", ErrUserInfo)
	if err != nil {
		return nil, err
	}
	identity := identityFromMap(p.Name, response)
	identity.Subject = firstNonEmpty(stringValue(response["user_id"]), stringValue(response["open_id"]), token.Raw["user_id"], token.OpenID)
	if identity.Subject == "" {
		return nil, errs.Detail(ErrUserInfo, "alipay UserInfo has no user_id or open_id | 支付宝 UserInfo 缺少 user_id 或 open_id")
	}
	identity.EmailVerified = false
	identity.Username = ""
	identity.Name = firstNonEmpty(stringValue(response["nick_name"]), identity.Name)
	identity.AvatarURL = firstNonEmpty(stringValue(response["avatar"]), identity.AvatarURL)
	return identity, nil
}

// dingTalkExchange uses the JSON v1.0 userAccessToken API. | dingTalkExchange 使用 JSON v1.0
// userAccessToken API。
func dingTalkExchange(ctx context.Context, p *Provider, client *http.Client, code, _ string) (*Token, error) {
	payload := map[string]string{
		"clientId":     p.ClientID,
		"clientSecret": p.ClientSecret,
		"code":         code,
		"grantType":    "authorization_code",
	}
	status, body, err := postJSON(ctx, client, p.TokenURL, payload, nil)
	if err != nil {
		return nil, errs.Wrap(err, ErrTokenExchange)
	}
	if status != http.StatusOK {
		return nil, tokenHTTPError(status, body)
	}
	token, err := tokenFromBody(body, time.Now())
	if err != nil {
		return nil, errs.Wrap(err, ErrTokenExchange)
	}
	return token, nil
}

// dingTalkUserInfo calls contact/users/me with the DingTalk access token header. | dingTalkUserInfo
// 使用钉钉访问令牌请求头调用 contact/users/me。
func dingTalkUserInfo(ctx context.Context, p *Provider, client *http.Client, token *Token) (*Identity, error) {
	status, body, err := getProvider(ctx, client, p.UserInfoURL, map[string]string{
		"x-acs-dingtalk-access-token": token.AccessToken,
	})
	if err != nil {
		return nil, errs.Wrap(err, ErrUserInfo)
	}
	if status != http.StatusOK {
		return nil, providerStatusError(ErrUserInfo, p.Name, "UserInfo", status)
	}
	raw, err := parseJSONObject(body)
	if err != nil {
		return nil, errs.Detail(ErrUserInfo, "dingtalk UserInfo is invalid | 钉钉 UserInfo 非法")
	}
	if code := firstNonEmpty(providerErrorCode(raw), providerCodeZeroAware(raw["code"])); code != "" {
		return nil, errs.Detail(ErrUserInfo, "dingtalk UserInfo returned %s | 钉钉 UserInfo 返回 %s", sanitizeProviderCode(code), sanitizeProviderCode(code))
	}
	identity := identityFromMap(p.Name, raw)
	identity.Subject = firstNonEmpty(stringValue(raw["unionId"]), stringValue(raw["openId"]), identity.Subject)
	if identity.Subject == "" {
		return nil, errs.Detail(ErrUserInfo, "dingtalk UserInfo has no unionId or openId | 钉钉 UserInfo 缺少 unionId 或 openId")
	}
	identity.EmailVerified = false
	identity.Username = ""
	identity.Name = firstNonEmpty(stringValue(raw["nick"]), identity.Name)
	identity.AvatarURL = firstNonEmpty(stringValue(raw["avatarUrl"]), identity.AvatarURL)
	return identity, nil
}

// feishuAuthURL builds the Feishu authen authorize URL with app_id. | feishuAuthURL 使用 app_id
// 构建飞书 authen 授权 URL。
func feishuAuthURL(p *Provider, state, _, _ string) (string, error) {
	params := map[string]string{
		"app_id":        p.ClientID,
		"redirect_uri":  p.RedirectURL,
		"response_type": "code",
		"state":         state,
		"scope":         scopeValue(p),
	}
	for key, value := range p.AuthParams {
		params[key] = value
	}
	return setQueryParams(p.AuthURL, params)
}

// feishuExchange posts a client_id/client_secret JSON body to the OIDC access_token API.
// feishuExchange 把 client_id/client_secret JSON 体提交到 OIDC access_token API。
func feishuExchange(ctx context.Context, p *Provider, client *http.Client, code, _ string) (*Token, error) {
	payload := map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"client_id":     p.ClientID,
		"client_secret": p.ClientSecret,
		"redirect_uri":  p.RedirectURL,
	}
	status, body, err := postJSON(ctx, client, p.TokenURL, payload, nil)
	if err != nil {
		return nil, errs.Wrap(err, ErrTokenExchange)
	}
	if status != http.StatusOK {
		return nil, tokenHTTPError(status, body)
	}
	raw, err := parseJSONObject(body)
	if err != nil {
		return nil, errs.Detail(ErrTokenExchange, "feishu token response is invalid | 飞书令牌响应非法")
	}
	data, err := feishuData(p, raw, ErrTokenExchange)
	if err != nil {
		return nil, err
	}
	token, err := tokenFromMap(data, time.Now())
	if err != nil {
		return nil, errs.Wrap(err, ErrTokenExchange)
	}
	return token, nil
}

// feishuUserInfo calls authen/v1/user_info and maps open_id/union_id. | feishuUserInfo
// 调用 authen/v1/user_info 并映射 open_id/union_id。
func feishuUserInfo(ctx context.Context, p *Provider, client *http.Client, token *Token) (*Identity, error) {
	status, body, err := getProvider(ctx, client, p.UserInfoURL, map[string]string{
		"Authorization": "Bearer " + token.AccessToken,
	})
	if err != nil {
		return nil, errs.Wrap(err, ErrUserInfo)
	}
	if status != http.StatusOK {
		return nil, providerStatusError(ErrUserInfo, p.Name, "UserInfo", status)
	}
	raw, err := parseJSONObject(body)
	if err != nil {
		return nil, errs.Detail(ErrUserInfo, "feishu UserInfo is invalid | 飞书 UserInfo 非法")
	}
	data, err := feishuData(p, raw, ErrUserInfo)
	if err != nil {
		return nil, err
	}
	identity := identityFromMap(p.Name, data)
	identity.Subject = firstNonEmpty(stringValue(data["union_id"]), stringValue(data["open_id"]), stringValue(data["user_id"]), identity.Subject)
	if identity.Subject == "" {
		return nil, errs.Detail(ErrUserInfo, "feishu UserInfo has no open_id or union_id | 飞书 UserInfo 缺少 open_id 或 union_id")
	}
	identity.EmailVerified = false
	identity.Username = ""
	identity.Name = firstNonEmpty(stringValue(data["name"]), stringValue(data["en_name"]), identity.Name)
	identity.AvatarURL = firstNonEmpty(stringValue(data["avatar_url"]), stringValue(data["avatar_big"]), identity.AvatarURL)
	return identity, nil
}

// wecomAuthURL builds the WeCom OAuth authorization URL with appid and #wechat_redirect.
// wecomAuthURL 使用 appid 与 #wechat_redirect 构建企业微信 OAuth 授权 URL。
func wecomAuthURL(p *Provider, state, _, _ string) (string, error) {
	params := map[string]string{
		"appid":         p.ClientID,
		"redirect_uri":  p.RedirectURL,
		"response_type": "code",
		"scope":         scopeValue(p),
		"state":         state,
		"agentid":       p.Extra["agentid"],
	}
	for key, value := range p.AuthParams {
		params[key] = value
	}
	endpoint, err := setQueryParams(p.AuthURL, params)
	if err != nil {
		return "", err
	}
	return setURLFragment(endpoint, "wechat_redirect")
}

// wecomExchange gets the corp access token and resolves the code at getuserinfo. | wecomExchange
// 获取企业访问令牌并在 getuserinfo 解析 code。
func wecomExchange(ctx context.Context, p *Provider, client *http.Client, code, _ string) (*Token, error) {
	tokenEndpoint, err := appendQuery(p.TokenURL, map[string]string{
		"corpid":     p.ClientID,
		"corpsecret": p.ClientSecret,
	})
	if err != nil {
		return nil, errs.Wrap(err, ErrTokenExchange)
	}
	status, body, err := getProvider(ctx, client, tokenEndpoint, nil)
	if err != nil {
		return nil, errs.Wrap(err, ErrTokenExchange)
	}
	if status != http.StatusOK {
		return nil, tokenHTTPError(status, body)
	}
	tokenRaw, err := parseJSONObject(body)
	if err != nil {
		return nil, errs.Detail(ErrTokenExchange, "wecom token response is invalid | 企业微信令牌响应非法")
	}
	if code := providerErrorCode(tokenRaw); code != "" {
		return nil, errs.Detail(ErrTokenExchange, "wecom token endpoint returned %s | 企业微信令牌端点返回 %s", code, code)
	}
	corpToken := stringValue(tokenRaw["access_token"])
	if corpToken == "" {
		return nil, errs.Detail(ErrTokenExchange, "wecom token response has no access token | 企业微信令牌响应缺少访问令牌")
	}
	userEndpoint, err := appendQuery(wecomCodeUserInfoURL(p), map[string]string{
		"access_token": corpToken,
		"code":         code,
	})
	if err != nil {
		return nil, errs.Wrap(err, ErrTokenExchange)
	}
	status, body, err = getProvider(ctx, client, userEndpoint, nil)
	if err != nil {
		return nil, errs.Wrap(err, ErrTokenExchange)
	}
	if status != http.StatusOK {
		return nil, tokenHTTPError(status, body)
	}
	authRaw, err := parseJSONObject(body)
	if err != nil {
		return nil, errs.Detail(ErrTokenExchange, "wecom user response is invalid | 企业微信用户响应非法")
	}
	if code := providerErrorCode(authRaw); code != "" {
		return nil, errs.Detail(ErrTokenExchange, "wecom user endpoint returned %s | 企业微信用户端点返回 %s", code, code)
	}
	userID := firstStringValue(authRaw, "userid", "user_id", "UserId")
	openID := firstStringValue(authRaw, "openid", "open_id", "OpenId")
	externalID := firstStringValue(authRaw, "external_userid", "externalUserId")
	if firstNonEmpty(userID, openID, externalID) == "" {
		return nil, errs.Detail(ErrTokenExchange, "wecom response has no user identifier | 企业微信响应缺少用户标识")
	}
	return &Token{
		AccessToken: corpToken,
		TokenType:   "Bearer",
		OpenID:      firstNonEmpty(openID, externalID),
		Raw:         stringMap(authRaw),
	}, nil
}

// wecomUserInfo enriches an internal WeCom user with cgi-bin/user/get. | wecomUserInfo
// 使用 cgi-bin/user/get 补充企业微信内部用户信息。
func wecomUserInfo(ctx context.Context, p *Provider, client *http.Client, token *Token) (*Identity, error) {
	rawValues := cloneMap(token.Raw)
	userID := firstNonEmpty(rawValues["userid"], rawValues["user_id"], rawValues["UserId"])
	openID := firstNonEmpty(rawValues["openid"], rawValues["open_id"], rawValues["external_userid"])
	identity := &Identity{Provider: p.Name, Subject: firstNonEmpty(userID, openID), Raw: rawValues}
	if userID != "" && p.UserInfoURL != "" {
		endpoint, err := appendQuery(p.UserInfoURL, map[string]string{
			"access_token": token.AccessToken,
			"userid":       userID,
		})
		if err != nil {
			return nil, errs.Wrap(err, ErrUserInfo)
		}
		status, body, err := getProvider(ctx, client, endpoint, nil)
		if err != nil {
			return nil, errs.Wrap(err, ErrUserInfo)
		}
		if status != http.StatusOK {
			return nil, providerStatusError(ErrUserInfo, p.Name, "UserInfo", status)
		}
		raw, err := parseJSONObject(body)
		if err != nil {
			return nil, errs.Detail(ErrUserInfo, "wecom UserInfo is invalid | 企业微信 UserInfo 非法")
		}
		if code := providerErrorCode(raw); code != "" {
			return nil, errs.Detail(ErrUserInfo, "wecom UserInfo returned %s | 企业微信 UserInfo 返回 %s", code, code)
		}
		detailed := identityFromMap(p.Name, raw)
		identity.Name = detailed.Name
		identity.AvatarURL = detailed.AvatarURL
		identity.Email = detailed.Email
		identity.Username = ""
		identity.EmailVerified = false
		identity.Raw = mergeRawMaps(identity.Raw, detailed.Raw)
	}
	if identity.Subject == "" {
		return nil, errs.Detail(ErrUserInfo, "wecom identity has no user identifier | 企业微信身份缺少用户标识")
	}
	return identity, nil
}

// qqExchange fetches the QQ OpenID after the token exchange. | qqExchange 在令牌兑换后获取 QQ OpenID。
func qqExchange(ctx context.Context, p *Provider, client *http.Client, code, _ string) (*Token, error) {
	endpoint, err := appendQuery(p.TokenURL, map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     p.ClientID,
		"client_secret": p.ClientSecret,
		"code":          code,
		"redirect_uri":  p.RedirectURL,
		"fmt":           "json",
	})
	if err != nil {
		return nil, errs.Wrap(err, ErrTokenExchange)
	}
	status, body, err := getProvider(ctx, client, endpoint, nil)
	if err != nil {
		return nil, errs.Wrap(err, ErrTokenExchange)
	}
	if status != http.StatusOK {
		return nil, tokenHTTPError(status, body)
	}
	token, err := tokenFromBody(body, time.Now())
	if err != nil {
		return nil, errs.Wrap(err, ErrTokenExchange)
	}
	openIDEndpoint, err := appendQuery(qqOpenIDURL(p), map[string]string{
		"access_token": token.AccessToken,
		"fmt":          "json",
	})
	if err != nil {
		return nil, errs.Wrap(err, ErrTokenExchange)
	}
	status, body, err = getProvider(ctx, client, openIDEndpoint, nil)
	if err != nil {
		return nil, errs.Wrap(err, ErrTokenExchange)
	}
	if status != http.StatusOK {
		return nil, tokenHTTPError(status, body)
	}
	raw, err := parseJSONObject(body)
	if err != nil {
		return nil, errs.Detail(ErrTokenExchange, "qq openid response is invalid | QQ openid 响应非法")
	}
	if code := providerErrorCode(raw); code != "" {
		return nil, errs.Detail(ErrTokenExchange, "qq openid endpoint returned %s | QQ openid 端点返回 %s", code, code)
	}
	openID := firstStringValue(raw, "openid", "open_id", "openId")
	if openID == "" {
		return nil, errs.Detail(ErrTokenExchange, "qq openid response has no openid | QQ openid 响应缺少 openid")
	}
	token.OpenID = openID
	token.Raw = mergeRawMaps(token.Raw, map[string]string{"openid": openID})
	return token, nil
}

// qqUserInfo calls user/get_user_info with the QQ OpenID. | qqUserInfo 使用 QQ OpenID 调用
// user/get_user_info。
func qqUserInfo(ctx context.Context, p *Provider, client *http.Client, token *Token) (*Identity, error) {
	openID := firstNonEmpty(token.OpenID, token.Raw["openid"])
	if openID == "" {
		return nil, errs.Detail(ErrUserInfo, "qq token has no openid | QQ 令牌缺少 openid")
	}
	endpoint, err := appendQuery(p.UserInfoURL, map[string]string{
		"access_token":       token.AccessToken,
		"oauth_consumer_key": p.ClientID,
		"openid":             openID,
		"fmt":                "json",
	})
	if err != nil {
		return nil, errs.Wrap(err, ErrUserInfo)
	}
	status, body, err := getProvider(ctx, client, endpoint, nil)
	if err != nil {
		return nil, errs.Wrap(err, ErrUserInfo)
	}
	if status != http.StatusOK {
		return nil, providerStatusError(ErrUserInfo, p.Name, "UserInfo", status)
	}
	raw, err := parseJSONObject(body)
	if err != nil {
		return nil, errs.Detail(ErrUserInfo, "qq UserInfo is invalid | QQ UserInfo 非法")
	}
	if ret := int64Value(raw["ret"]); ret != 0 {
		return nil, errs.Detail(ErrUserInfo, "qq UserInfo returned %d | QQ UserInfo 返回 %d", ret, ret)
	}
	if code := providerErrorCode(raw); code != "" {
		return nil, errs.Detail(ErrUserInfo, "qq UserInfo returned %s | QQ UserInfo 返回 %s", code, code)
	}
	identity := identityFromMap(p.Name, raw)
	identity.Subject = openID
	identity.EmailVerified = false
	identity.Username = ""
	identity.Name = firstNonEmpty(stringValue(raw["nickname"]), identity.Name)
	identity.AvatarURL = firstNonEmpty(stringValue(raw["figureurl_qq_2"]), stringValue(raw["figureurl_2"]), identity.AvatarURL)
	identity.Raw = mergeRawMaps(identity.Raw, map[string]string{"openid": openID})
	return identity, nil
}

// weiboUserInfo calls users/show.json with the Weibo uid. | weiboUserInfo 使用微博 uid 调用
// users/show.json。
func weiboUserInfo(ctx context.Context, p *Provider, client *http.Client, token *Token) (*Identity, error) {
	uid := firstNonEmpty(token.Raw["uid"], token.OpenID)
	if uid == "" {
		return nil, errs.Detail(ErrUserInfo, "weibo token has no uid | 微博令牌缺少 uid")
	}
	endpoint, err := appendQuery(p.UserInfoURL, map[string]string{
		"access_token": token.AccessToken,
		"uid":          uid,
	})
	if err != nil {
		return nil, errs.Wrap(err, ErrUserInfo)
	}
	status, body, err := getProvider(ctx, client, endpoint, nil)
	if err != nil {
		return nil, errs.Wrap(err, ErrUserInfo)
	}
	if status != http.StatusOK {
		return nil, providerStatusError(ErrUserInfo, p.Name, "UserInfo", status)
	}
	raw, err := parseJSONObject(body)
	if err != nil {
		return nil, errs.Detail(ErrUserInfo, "weibo UserInfo is invalid | 微博 UserInfo 非法")
	}
	if code := providerErrorCode(raw); code != "" {
		return nil, errs.Detail(ErrUserInfo, "weibo UserInfo returned %s | 微博 UserInfo 返回 %s", code, code)
	}
	identity := identityFromMap(p.Name, raw)
	identity.Subject = firstNonEmpty(identity.Subject, uid)
	if identity.Subject == "" {
		return nil, errs.Detail(ErrUserInfo, "weibo UserInfo has no uid | 微博 UserInfo 缺少 uid")
	}
	identity.EmailVerified = false
	identity.Username = ""
	identity.Name = firstNonEmpty(stringValue(raw["screen_name"]), identity.Name)
	identity.AvatarURL = firstNonEmpty(stringValue(raw["avatar_large"]), identity.AvatarURL)
	identity.Raw = mergeRawMaps(identity.Raw, map[string]string{"uid": uid})
	return identity, nil
}

// baiduUserInfo calls users/getInfo with access_token in the query. | baiduUserInfo
// 在查询参数中携带 access_token 调用 users/getInfo。
func baiduUserInfo(ctx context.Context, p *Provider, client *http.Client, token *Token) (*Identity, error) {
	endpoint, err := appendQuery(p.UserInfoURL, map[string]string{"access_token": token.AccessToken})
	if err != nil {
		return nil, errs.Wrap(err, ErrUserInfo)
	}
	status, body, err := getProvider(ctx, client, endpoint, nil)
	if err != nil {
		return nil, errs.Wrap(err, ErrUserInfo)
	}
	if status != http.StatusOK {
		return nil, providerStatusError(ErrUserInfo, p.Name, "UserInfo", status)
	}
	raw, err := parseJSONObject(body)
	if err != nil {
		return nil, errs.Detail(ErrUserInfo, "baidu UserInfo is invalid | 百度 UserInfo 非法")
	}
	if code := providerErrorCode(raw); code != "" {
		return nil, errs.Detail(ErrUserInfo, "baidu UserInfo returned %s | 百度 UserInfo 返回 %s", code, code)
	}
	identity := identityFromMap(p.Name, raw)
	identity.Subject = firstNonEmpty(stringValue(raw["userid"]), stringValue(raw["user_id"]), identity.Subject)
	if identity.Subject == "" {
		return nil, errs.Detail(ErrUserInfo, "baidu UserInfo has no userid | 百度 UserInfo 缺少 userid")
	}
	identity.EmailVerified = false
	identity.Username = firstNonEmpty(stringValue(raw["username"]), identity.Username)
	identity.Name = firstNonEmpty(stringValue(raw["realname"]), stringValue(raw["username"]), identity.Name)
	identity.AvatarURL = firstNonEmpty(stringValue(raw["portrait"]), identity.AvatarURL)
	return identity, nil
}

// giteeUserInfo calls api/v5/user with access_token in the query. | giteeUserInfo
// 在查询参数中携带 access_token 调用 api/v5/user。
func giteeUserInfo(ctx context.Context, p *Provider, client *http.Client, token *Token) (*Identity, error) {
	endpoint, err := appendQuery(p.UserInfoURL, map[string]string{"access_token": token.AccessToken})
	if err != nil {
		return nil, errs.Wrap(err, ErrUserInfo)
	}
	status, body, err := getProvider(ctx, client, endpoint, nil)
	if err != nil {
		return nil, errs.Wrap(err, ErrUserInfo)
	}
	if status != http.StatusOK {
		return nil, providerStatusError(ErrUserInfo, p.Name, "UserInfo", status)
	}
	raw, err := parseJSONObject(body)
	if err != nil {
		return nil, errs.Detail(ErrUserInfo, "gitee UserInfo is invalid | Gitee UserInfo 非法")
	}
	identity := identityFromMap(p.Name, raw)
	identity.Subject = firstNonEmpty(stringValue(raw["id"]), stringValue(raw["login"]), identity.Subject)
	if identity.Subject == "" {
		return nil, errs.Detail(ErrUserInfo, "gitee UserInfo has no id | Gitee UserInfo 缺少 id")
	}
	identity.EmailVerified = false
	identity.Username = firstNonEmpty(stringValue(raw["login"]), identity.Username)
	identity.Name = firstNonEmpty(stringValue(raw["name"]), stringValue(raw["login"]), identity.Name)
	identity.AvatarURL = firstNonEmpty(stringValue(raw["avatar_url"]), identity.AvatarURL)
	return identity, nil
}

// feishuData extracts the data object and rejects a non-zero business code. | feishuData
// 提取 data 对象并拒绝非零业务码。
func feishuData(p *Provider, raw map[string]any, sentinel error) (map[string]any, error) {
	if code := int64Value(raw["code"]); code != 0 {
		return nil, errs.Detail(sentinel, "feishu returned code %d | 飞书返回 code %d", code, code)
	}
	if code := stringValue(raw["error"]); code != "" {
		return nil, errs.Detail(sentinel, "feishu returned %s | 飞书返回 %s", sanitizeProviderCode(code), sanitizeProviderCode(code))
	}
	data := nestedMap(raw, "data")
	if data == nil {
		return nil, errs.Detail(sentinel, "feishu response has no data | 飞书响应缺少 data")
	}
	return data, nil
}

// alipayBaseParams returns common Alipay OpenAPI parameters. | alipayBaseParams 返回支付宝 OpenAPI 公共参数。
func alipayBaseParams(p *Provider, method string) map[string]string {
	return map[string]string{
		"app_id":    p.ClientID,
		"method":    method,
		"format":    "json",
		"charset":   "utf-8",
		"sign_type": "RSA2",
		"version":   "1.0",
		"timestamp": time.Now().Format("2006-01-02 15:04:05"),
	}
}

// alipayResponse extracts a business response and rejects Alipay error responses. | alipayResponse
// 提取业务响应并拒绝支付宝错误响应。
func alipayResponse(p *Provider, raw map[string]any, key string, sentinel error) (map[string]any, error) {
	if failure := nestedMap(raw, "error_response"); failure != nil {
		code := firstNonEmpty(stringValue(failure["sub_code"]), stringValue(failure["code"]), "error")
		code = sanitizeProviderCode(code)
		return nil, errs.Detail(sentinel, "alipay returned %s | 支付宝返回 %s", code, code)
	}
	response := nestedMap(raw, key)
	if response == nil {
		return nil, errs.Detail(sentinel, "alipay response has no %s object | 支付宝响应缺少 %s 对象", key, key)
	}
	if code := stringValue(response["code"]); code != "" && code != "10000" {
		code = sanitizeProviderCode(code)
		return nil, errs.Detail(sentinel, "alipay returned %s | 支付宝返回 %s", code, code)
	}
	return response, nil
}

// privateKeyFor returns the configured Alipay private key. | privateKeyFor 返回已配置的支付宝私钥。
func privateKeyFor(p *Provider) string {
	if p == nil {
		return ""
	}
	return firstNonEmpty(p.PrivateKey, p.Extra[ExtraAlipayPrivateKey])
}

// wecomCodeUserInfoURL returns the WeCom code-to-user endpoint. | wecomCodeUserInfoURL
// 返回企业微信 code 换用户端点。
func wecomCodeUserInfoURL(p *Provider) string {
	if value := p.Extra[ExtraWeComAuthUserInfoURL]; value != "" {
		return value
	}
	if p.TokenURL != "" && p.TokenURL != defaultWeComTokenURL {
		return replaceURLPath(p.TokenURL, "/cgi-bin/auth/getuserinfo")
	}
	return defaultWeComAuthUserInfoURL
}

// qqOpenIDURL returns the QQ OpenID endpoint. | qqOpenIDURL 返回 QQ OpenID 端点。
func qqOpenIDURL(p *Provider) string {
	if value := p.Extra[ExtraQQOpenIDURL]; value != "" {
		return value
	}
	if p.TokenURL != "" && p.TokenURL != defaultQQTokenURL {
		return replaceURLPath(p.TokenURL, "/oauth2.0/me")
	}
	return defaultQQOpenIDURL
}

// mapValues converts a string map to url.Values. | mapValues 把字符串映射转换为 url.Values。
func mapValues(values map[string]string) url.Values {
	out := make(url.Values, len(values))
	for key, value := range values {
		out.Set(key, value)
	}
	return out
}
