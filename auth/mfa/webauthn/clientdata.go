package webauthn

import (
	"net/url"
	"strings"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// Client data type values defined by WebAuthn. | WebAuthn 定义的客户端数据类型值。
const (
	// ClientDataTypeCreate is the type of a registration ceremony. | ClientDataTypeCreate 是注册流程的类型。
	ClientDataTypeCreate = "webauthn.create"
	// ClientDataTypeGet is the type of an authentication ceremony. | ClientDataTypeGet 是认证流程的类型。
	ClientDataTypeGet = "webauthn.get"
	// maxClientDataBytes bounds client data JSON before decoding. | maxClientDataBytes 限制解码前的客户端数据 JSON 大小。
	maxClientDataBytes = 64 << 10
)

// TokenBinding is the client data token binding member. | TokenBinding 是客户端数据的令牌绑定成员。
type TokenBinding struct {
	// Status is "present", "supported" or "not-supported". | Status 取值为 "present"、"supported" 或 "not-supported"。
	Status string `json:"status"`
	// ID is the base64url token binding identifier when Status is "present". | 当 Status 为 "present" 时，ID 是 base64url 令牌绑定标识。
	ID string `json:"id,omitempty"`
}

// AppleClientData marks the presence of the Apple client data extension. | AppleClientData 标记 Apple 客户端数据扩展的存在。
//
// Its contents are intentionally opaque: this package cannot validate an extension whose schema is
// not defined by WebAuthn Level 2/3, so the origin and challenge checks remain the only authority.
// Decoding accepts any JSON object and rejects non-object values. | 其内容刻意保持不透明：对于
// WebAuthn Level 2/3 未定义结构的扩展，本包无法校验，因此来源与挑战检查仍是唯一依据。解码接受
// 任意 JSON 对象，并拒绝非对象值。
type AppleClientData struct{}

// ClientData is the JSON structure signed by an authenticator. | ClientData 是认证器签名的 JSON 结构。
type ClientData struct {
	// Type is ClientDataTypeCreate or ClientDataTypeGet. | Type 取值为 ClientDataTypeCreate 或 ClientDataTypeGet。
	Type string `json:"type"`
	// Challenge is the unpadded base64url challenge. | Challenge 是无填充 base64url 挑战。
	Challenge string `json:"challenge"`
	// Origin is the serialized origin of the requesting context. | Origin 是请求上下文的序列化来源。
	Origin string `json:"origin"`
	// CrossOrigin reports a cross-origin request context. | CrossOrigin 表示跨来源请求上下文。
	CrossOrigin bool `json:"crossOrigin,omitempty"`
	// TopOrigin is the top-level origin of a cross-origin iframe. | TopOrigin 是跨来源 iframe 的顶层来源。
	TopOrigin string `json:"topOrigin,omitempty"`
	// TokenBinding carries the legacy token binding result. | TokenBinding 携带旧版令牌绑定结果。
	TokenBinding *TokenBinding `json:"tokenBinding,omitempty"`
	// AndroidPackageName is the APK package name for Android origin client data. | AndroidPackageName 是 Android 来源客户端数据的 APK 包名。
	AndroidPackageName string `json:"androidPackageName,omitempty"`
	// AndroidInstant reports an Android Instant App. | AndroidInstant 表示 Android Instant App。
	AndroidInstant bool `json:"androidInstant,omitempty"`
	// Apple marks the Apple extension when present. | Apple 在 Apple 扩展存在时非空。
	Apple *AppleClientData `json:"apple,omitempty"`
	// Raw is the exact signed JSON. | Raw 是签名的原始 JSON。
	Raw []byte `json:"-"`
}

// ClientDataVerifyOptions are the expected values for client data verification. | ClientDataVerifyOptions 是客户端数据校验的期望值。
type ClientDataVerifyOptions struct {
	// Type is the required ceremony type. | Type 是要求的流程类型。
	Type string
	// Challenge is the expected raw challenge. | Challenge 是期望的原始挑战。
	Challenge []byte
	// Origins lists the accepted origins. | Origins 列出可接受的来源。
	Origins []string
	// RPID is the effective relying party identifier, used for origin compatibility when non-empty. | RPID 是生效的依赖方标识；非空时用于检查来源兼容性。
	RPID string
	// AllowCrossOrigin permits client data with crossOrigin true. | AllowCrossOrigin 允许 crossOrigin 为 true 的客户端数据。
	AllowCrossOrigin bool
	// AllowedTopOrigins lists the accepted top-level origins for cross-origin requests. | AllowedTopOrigins 列出跨来源请求可接受的顶层来源。
	AllowedTopOrigins []string
	// TokenBindingID is the expected token binding identifier when token binding is present. | 令牌绑定存在时，TokenBindingID 是期望的令牌绑定标识。
	TokenBindingID string
	// RequireTokenBinding requires the tokenBinding member to be present. | RequireTokenBinding 要求存在 tokenBinding 成员。
	RequireTokenBinding bool
}

// ParseClientData decodes client data JSON without checking expected values. | ParseClientData 解码客户端数据 JSON，但不校验期望值。
func ParseClientData(raw []byte) (*ClientData, error) {
	if len(raw) == 0 {
		return nil, errs.Detail(ErrInvalidClientData, "empty client data | 客户端数据为空")
	}
	if len(raw) > maxClientDataBytes {
		return nil, errs.Detail(ErrInvalidClientData, "client data is %d bytes, limit is %d | 客户端数据 %d 字节，限制 %d",
			len(raw), maxClientDataBytes, len(raw), maxClientDataBytes)
	}
	var cd ClientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidClientData, "client data is not valid JSON | 客户端数据不是合法 JSON")
	}
	cd.Raw = append([]byte(nil), raw...)
	if cd.Type == "" {
		return nil, errs.Detail(ErrInvalidClientData, "client data type is empty | 客户端数据类型为空")
	}
	if cd.Challenge == "" {
		return nil, errs.Detail(ErrInvalidClientData, "client data challenge is empty | 客户端数据挑战为空")
	}
	if cd.Origin == "" {
		return nil, errs.Detail(ErrInvalidClientData, "client data origin is empty | 客户端数据来源为空")
	}
	return &cd, nil
}

// VerifyClientData parses client data and checks every expected value. | VerifyClientData 解析客户端数据并校验全部期望值。
func VerifyClientData(raw []byte, opts ClientDataVerifyOptions) (*ClientData, error) {
	cd, err := ParseClientData(raw)
	if err != nil {
		return nil, err
	}
	if cd.Type != opts.Type {
		return nil, errs.Detail(ErrInvalidClientData, "client data type %q, want %q | 客户端数据类型 %q，期望 %q", cd.Type, opts.Type, cd.Type, opts.Type)
	}
	challenge, err := base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidClientData, "challenge is not unpadded base64url | 挑战不是无填充 base64url")
	}
	if !constantTimeEqual(challenge, opts.Challenge) {
		return nil, errs.Detail(ErrChallengeMismatch, "client data challenge does not match the ceremony | 客户端数据挑战与流程不匹配")
	}
	origin, err := normalizeOrigin(cd.Origin)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrOriginMismatch, "client data origin is invalid | 客户端数据来源非法")
	}
	if !secureOrigin(origin) {
		return nil, errs.Detail(ErrOriginMismatch, "origin %q is not a secure context | 来源 %q 不是安全上下文", cd.Origin, cd.Origin)
	}
	matched := ""
	for _, allowed := range opts.Origins {
		normalized, err := normalizeOrigin(allowed)
		if err != nil {
			continue
		}
		if normalized == origin {
			matched = normalized
			break
		}
	}
	if matched == "" {
		return nil, errs.Detail(ErrOriginMismatch, "origin %q is not configured | 来源 %q 未配置", cd.Origin, cd.Origin)
	}
	if opts.RPID != "" && !originMatchesRPID(matched, opts.RPID) {
		return nil, errs.Detail(ErrRPIDMismatch, "origin %q is outside RP ID %q | 来源 %q 不在 RP ID %q 内", matched, opts.RPID, matched, opts.RPID)
	}
	if err := verifyCrossOrigin(cd, opts); err != nil {
		return nil, err
	}
	if err := verifyAndroidClientData(cd); err != nil {
		return nil, err
	}
	if err := verifyTokenBinding(cd, opts); err != nil {
		return nil, err
	}
	return cd, nil
}

func verifyCrossOrigin(cd *ClientData, opts ClientDataVerifyOptions) error {
	if !cd.CrossOrigin {
		if cd.TopOrigin != "" {
			return errs.Detail(ErrInvalidClientData, "topOrigin is present without crossOrigin | crossOrigin 为 false 时出现 topOrigin")
		}
		return nil
	}
	if !opts.AllowCrossOrigin {
		return errs.Detail(ErrOriginMismatch, "cross-origin ceremonies are disabled | 跨来源流程已禁用")
	}
	top, err := normalizeOrigin(cd.TopOrigin)
	if err != nil {
		return errs.WrapDetail(err, ErrOriginMismatch, "topOrigin is invalid | topOrigin 非法")
	}
	for _, allowed := range opts.AllowedTopOrigins {
		normalized, err := normalizeOrigin(allowed)
		if err == nil && normalized == top {
			return nil
		}
	}
	return errs.Detail(ErrOriginMismatch, "topOrigin %q is not allowed | topOrigin %q 不被允许", cd.TopOrigin, cd.TopOrigin)
}

func verifyAndroidClientData(cd *ClientData) error {
	isAndroid := strings.HasPrefix(strings.ToLower(cd.Origin), "android:")
	if cd.AndroidInstant && cd.AndroidPackageName == "" {
		return errs.Detail(ErrInvalidClientData, "androidInstant is set without androidPackageName | 设置 androidInstant 但缺少 androidPackageName")
	}
	if cd.AndroidPackageName != "" && !isAndroid {
		return errs.Detail(ErrInvalidClientData, "androidPackageName is set for a non-Android origin | 非 Android 来源却设置 androidPackageName")
	}
	if isAndroid && cd.AndroidPackageName == "" {
		return errs.Detail(ErrInvalidClientData, "Android origin lacks androidPackageName | Android 来源缺少 androidPackageName")
	}
	return nil
}

func verifyTokenBinding(cd *ClientData, opts ClientDataVerifyOptions) error {
	if cd.TokenBinding == nil {
		if opts.RequireTokenBinding {
			return errs.Detail(ErrTokenBindingMismatch, "token binding is required but absent | 要求令牌绑定但缺失")
		}
		return nil
	}
	switch cd.TokenBinding.Status {
	case "not-supported", "supported":
		if cd.TokenBinding.ID != "" {
			return errs.Detail(ErrTokenBindingMismatch, "token binding ID is present for status %q | 状态 %q 却包含令牌绑定 ID", cd.TokenBinding.Status, cd.TokenBinding.Status)
		}
		return nil
	case "present":
		if opts.TokenBindingID == "" {
			return errs.Detail(ErrTokenBindingMismatch, "token binding is present but no identifier is configured | 令牌绑定存在但未配置标识")
		}
		if !constantTimeEqual([]byte(cd.TokenBinding.ID), []byte(opts.TokenBindingID)) {
			return errs.Detail(ErrTokenBindingMismatch, "token binding identifier mismatch | 令牌绑定标识不匹配")
		}
		return nil
	default:
		return errs.Detail(ErrTokenBindingMismatch, "unknown token binding status %q | 未知的令牌绑定状态 %q", cd.TokenBinding.Status, cd.TokenBinding.Status)
	}
}

// normalizeOrigin canonicalizes an http, https or android origin. | normalizeOrigin 规范化 http、https 或 android 来源。
func normalizeOrigin(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errs.Detail(ErrOriginMismatch, "empty origin | 来源为空")
	}
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "android:") {
		if len(s) <= len("android:") {
			return "", errs.Detail(ErrOriginMismatch, "empty android origin | Android 来源为空")
		}
		return "android:" + s[len("android:"):], nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", errs.Wrap(err, ErrOriginMismatch)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errs.Detail(ErrOriginMismatch, "unsupported origin scheme %q | 不支持的来源协议 %q", u.Scheme, u.Scheme)
	}
	if u.User != nil {
		return "", errs.Detail(ErrOriginMismatch, "origin must not contain user info | 来源不得包含用户信息")
	}
	if u.Path != "" && u.Path != "/" {
		return "", errs.Detail(ErrOriginMismatch, "origin must not contain a path | 来源不得包含路径")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", errs.Detail(ErrOriginMismatch, "origin must not contain a query or fragment | 来源不得包含查询或片段")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", errs.Detail(ErrOriginMismatch, "origin host is empty | 来源主机为空")
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host, nil
}

// secureOrigin reports whether a normalized origin satisfies the WebAuthn secure-context rule:
// https, an Android app origin, or http restricted to localhost/loopback. | secureOrigin 报告规范化
// 来源是否满足 WebAuthn 安全上下文规则：https、Android 应用来源，或仅限 localhost/环回地址的 http。
func secureOrigin(origin string) bool {
	if strings.HasPrefix(origin, "android:") {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return true
	case "http":
		host := strings.ToLower(u.Hostname())
		return host == "localhost" || host == "127.0.0.1" || host == "::1" || strings.HasSuffix(host, ".localhost")
	default:
		return false
	}
}

// originMatchesRPID reports whether an origin host is the RP ID or a subdomain of it. | originMatchesRPID 报告来源主机是否等于 RP ID 或是其子域。
func originMatchesRPID(origin, rpID string) bool {
	if strings.HasPrefix(origin, "android:") {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	rp := strings.ToLower(strings.TrimSpace(rpID))
	if host == rp {
		return true
	}
	if rp == "" || strings.ContainsAny(rp, ":/") {
		return false
	}
	return strings.HasSuffix(host, "."+rp)
}

// normalizeRPID validates and canonicalizes a relying party identifier. | normalizeRPID 校验并规范化依赖方标识。
func normalizeRPID(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errs.Detail(ErrInvalidConfig, "RP ID is empty | RP ID 为空")
	}
	if s != raw {
		return "", errs.Detail(ErrInvalidConfig, "RP ID contains surrounding whitespace | RP ID 包含首尾空白")
	}
	if strings.ContainsAny(s, "/:@ \t\r\n?#") {
		return "", errs.Detail(ErrInvalidConfig, "RP ID must be a bare domain without scheme, port or path | RP ID 必须是不含协议、端口与路径的裸域名")
	}
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") || strings.Contains(s, "..") {
		return "", errs.Detail(ErrInvalidConfig, "RP ID has an empty label | RP ID 包含空标签")
	}
	return strings.ToLower(s), nil
}
