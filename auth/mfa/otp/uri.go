package otp

import (
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Kind is the credential type carried by an otpauth:// URI. | Kind 是 otpauth:// URI 携带的凭据类型。
type Kind string

// The supported otpauth:// credential types. | 受支持的 otpauth:// 凭据类型。
const (
	// KindTOTP is a time-based credential. | KindTOTP 是基于时间的凭据。
	KindTOTP Kind = "totp"
	// KindHOTP is a counter-based credential. | KindHOTP 是基于计数器的凭据。
	KindHOTP Kind = "hotp"
)

// URI is the decoded form of an otpauth:// enrollment URI. | URI 是 otpauth:// 登记 URI 的解码形式。
type URI struct {
	// Type is the credential type. | Type 是凭据类型。
	Type Kind
	// Issuer is the service name shown by authenticator applications. | Issuer 是认证器应用展示的服务名。
	Issuer string
	// AccountName is the account label. | AccountName 是账号标签。
	AccountName string
	// Secret is the canonical uppercase base32 shared secret without padding. | Secret 是规范的大写无填充 base32 共享密钥。
	Secret string
	// Algorithm is the HMAC hash. | Algorithm 是 HMAC 哈希。
	Algorithm Algorithm
	// Digits is the code length. | Digits 是口令长度。
	Digits int
	// Period is the TOTP time step. It is always set, even for HOTP URIs. | Period 是 TOTP 时间步。即使对 HOTP URI 也会设置。
	Period time.Duration
	// Counter is the HOTP initial counter. | Counter 是 HOTP 初始计数器。
	Counter uint64
}

// GenerateURI returns an otpauth://totp enrollment URI. Empty issuer or account arguments fall
// back to cfg.Issuer and cfg.AccountName. Invalid cfg values are replaced by defaults because the
// signature has no error channel; use Config.Normalize before calling when validation matters.
// | GenerateURI 返回 otpauth://totp 登记 URI。issuer 或 account 参数为空时回退到 cfg.Issuer 与
// cfg.AccountName。由于签名没有错误通道，非法的 cfg 值会被替换为默认值；需要校验时请先调用
// Config.Normalize。
func GenerateURI(issuer, account, secret string, cfg Config) string {
	c := cfg.lenient()
	if issuer == "" {
		issuer = c.Issuer
	}
	if account == "" {
		account = c.AccountName
	}
	return URI{
		Type:        KindTOTP,
		Issuer:      strings.TrimSpace(issuer),
		AccountName: strings.TrimSpace(account),
		Secret:      canonicalSecret(secret),
		Algorithm:   c.Algorithm,
		Digits:      c.Digits,
		Period:      c.Period,
	}.String()
}

// GenerateHOTPURI returns an otpauth://hotp enrollment URI with counter. Empty issuer or account
// arguments fall back to cfg.Issuer and cfg.AccountName. | GenerateHOTPURI 返回携带 counter 的
// otpauth://hotp 登记 URI。issuer 或 account 参数为空时回退到 cfg.Issuer 与 cfg.AccountName。
func GenerateHOTPURI(issuer, account, secret string, counter uint64, cfg Config) string {
	c := cfg.lenient()
	if issuer == "" {
		issuer = c.Issuer
	}
	if account == "" {
		account = c.AccountName
	}
	return URI{
		Type:        KindHOTP,
		Issuer:      strings.TrimSpace(issuer),
		AccountName: strings.TrimSpace(account),
		Secret:      canonicalSecret(secret),
		Algorithm:   c.Algorithm,
		Digits:      c.Digits,
		Period:      c.Period,
		Counter:     counter,
	}.String()
}

// ParseURI decodes an otpauth://totp or otpauth://hotp URI. Parameter names are matched
// case-insensitively, the issuer may come from the label prefix and/or the issuer query parameter,
// and the secret may carry whitespace, hyphens or padding. When the label contains a colon, the
// text after the first colon is the account and the query issuer, if present, wins over the label
// prefix. Missing optional parameters select the package defaults. | ParseURI 解码 otpauth://totp
// 或 otpauth://hotp URI。参数名大小写不敏感，issuer 可以来自标签前缀和/或 issuer 查询参数，密钥
// 可以包含空白、连字符或填充。标签包含冒号时，第一个冒号之后的文本是账号；若存在查询参数 issuer，
// 它优先于标签前缀。缺失的可选参数使用包默认值。
func ParseURI(raw string) (URI, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return URI{}, uriError("URI is empty | URI 为空")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return URI{}, errs.WrapDetail(err, ErrInvalidURI, "cannot parse URI | 无法解析 URI")
	}
	if !strings.EqualFold(parsed.Scheme, "otpauth") {
		return URI{}, uriError("scheme %q is not otpauth | 协议 %q 不是 otpauth", parsed.Scheme, parsed.Scheme)
	}
	if parsed.Opaque != "" {
		return URI{}, uriError("opaque URIs are not supported | 不支持不透明 URI")
	}
	if parsed.User != nil || parsed.Port() != "" || parsed.Fragment != "" {
		return URI{}, uriError("user info, port and fragment are not allowed | 不允许用户信息、端口与片段")
	}
	kind := Kind(strings.ToLower(parsed.Hostname()))
	if kind != KindTOTP && kind != KindHOTP {
		return URI{}, uriError("credential type %q is not totp or hotp | 凭据类型 %q 不是 totp 或 hotp", parsed.Hostname(), parsed.Hostname())
	}
	values, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return URI{}, errs.WrapDetail(err, ErrInvalidURI, "cannot parse query | 无法解析查询串")
	}
	params := normalizeParams(values)

	label := strings.TrimPrefix(parsed.Path, "/")
	issuer := strings.TrimSpace(params["issuer"])
	account := label
	if i := strings.Index(label, ":"); i >= 0 {
		if issuer == "" {
			issuer = strings.TrimSpace(label[:i])
		}
		account = label[i+1:]
	}
	account = strings.TrimSpace(account)

	secret := canonicalSecret(params["secret"])
	if secret == "" {
		return URI{}, uriError("secret parameter is missing | 缺少 secret 参数")
	}
	if _, err := decodeSecret(secret); err != nil {
		return URI{}, errs.WrapDetail(err, ErrInvalidURI, "invalid secret | 密钥无效")
	}

	digits := DefaultDigits
	if value, ok := params["digits"]; ok && strings.TrimSpace(value) != "" {
		parsedDigits, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || parsedDigits < MinDigits || parsedDigits > MaxDigits {
			return URI{}, uriError("digits %q outside [%d,%d] | 位数 %q 超出 [%d,%d]",
				value, MinDigits, MaxDigits, value, MinDigits, MaxDigits)
		}
		digits = parsedDigits
	}

	algorithm := DefaultAlgorithm
	if value, ok := params["algorithm"]; ok && strings.TrimSpace(value) != "" {
		algorithm = Algorithm(value).canonical()
		if !algorithm.valid() {
			return URI{}, uriError("unsupported algorithm %q | 不支持的算法 %q", value, value)
		}
	}

	period := DefaultPeriod
	if value, ok := params["period"]; ok && strings.TrimSpace(value) != "" {
		parsedPeriod, err := parsePeriodValue(value)
		if err != nil {
			return URI{}, err
		}
		period = parsedPeriod
	}

	var counter uint64
	if value, ok := params["counter"]; ok && strings.TrimSpace(value) != "" {
		parsedCounter, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return URI{}, uriError("counter %q is not an unsigned integer | 计数器 %q 不是无符号整数", value, value)
		}
		counter = parsedCounter
	}

	normalized, err := Config{Digits: digits, Period: period, Algorithm: algorithm}.Normalize()
	if err != nil {
		return URI{}, errs.Wrap(err, ErrInvalidURI)
	}
	return URI{
		Type:        kind,
		Issuer:      issuer,
		AccountName: account,
		Secret:      secret,
		Algorithm:   normalized.Algorithm,
		Digits:      normalized.Digits,
		Period:      normalized.Period,
		Counter:     counter,
	}, nil
}

// String renders u as an otpauth:// URI. Unknown Type values render as totp, and invalid digit,
// period or algorithm values are replaced by defaults so String never fails. | String 把 u 渲染为
// otpauth:// URI。未知 Type 按 totp 渲染，非法的位数、时间步或算法值会被替换为默认值，因此 String
// 永不失败。
func (u URI) String() string {
	kind := u.Type
	if kind != KindHOTP {
		kind = KindTOTP
	}
	digits := u.Digits
	if digits < MinDigits || digits > MaxDigits {
		digits = DefaultDigits
	}
	algorithm := u.Algorithm.canonical()
	if !algorithm.valid() {
		algorithm = DefaultAlgorithm
	}
	period := u.Period
	if period < time.Second {
		period = DefaultPeriod
	}
	issuer := strings.TrimSpace(u.Issuer)
	label := strings.TrimSpace(u.AccountName)
	if issuer != "" {
		if label != "" {
			label = issuer + ":" + label
		} else {
			label = issuer
		}
	}

	values := url.Values{}
	values.Set("secret", canonicalSecret(u.Secret))
	if issuer != "" {
		values.Set("issuer", issuer)
	}
	values.Set("algorithm", string(algorithm))
	values.Set("digits", strconv.Itoa(digits))
	if kind == KindHOTP {
		values.Set("counter", strconv.FormatUint(u.Counter, 10))
	} else {
		values.Set("period", strconv.FormatInt(int64(period/time.Second), 10))
	}
	target := &url.URL{
		Scheme:   "otpauth",
		Host:     string(kind),
		Path:     "/" + label,
		RawQuery: values.Encode(),
	}
	return target.String()
}

// Config returns a Config carrying the URI's issuer, account, algorithm, digits and period.
// | Config 返回携带 URI 的签发方、账号、算法、位数与时间步的 Config。
func (u URI) Config() Config {
	return Config{
		Digits:      u.Digits,
		Period:      u.Period,
		Algorithm:   u.Algorithm,
		Issuer:      u.Issuer,
		AccountName: u.AccountName,
	}
}

// normalizeParams lowercases parameter names and resolves duplicate spellings deterministically:
// the lexicographically first key wins. | normalizeParams 把参数名转为小写，并以确定方式解决重复
// 拼写：字典序最小的键优先。
func normalizeParams(values url.Values) map[string]string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make(map[string]string, len(values))
	for _, key := range keys {
		lower := strings.ToLower(key)
		if _, exists := out[lower]; exists {
			continue
		}
		out[lower] = values.Get(key)
	}
	return out
}

// parsePeriodValue parses either an integer number of seconds or a Go duration string and wraps
// failures as ErrInvalidURI. | parsePeriodValue 解析整数秒或 Go 时长字符串，并把失败包装为
// ErrInvalidURI。
func parsePeriodValue(value string) (time.Duration, error) {
	period, ok := parseDurationSetting(value)
	if !ok {
		return 0, uriError("period %q is not a positive duration of at least one second | 时间步 %q 不是至少一秒的正时长", value, value)
	}
	return period, nil
}

// parseDurationSetting parses an integer number of seconds or a Go duration string of at least
// one second. | parseDurationSetting 解析整数秒或至少一秒的 Go 时长字符串。
func parseDurationSetting(value string) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		const maxSeconds = int64(^uint64(0)>>1) / int64(time.Second)
		if seconds < 1 || seconds > maxSeconds {
			return 0, false
		}
		return time.Duration(seconds) * time.Second, true
	}
	period, err := time.ParseDuration(value)
	if err != nil || period < time.Second {
		return 0, false
	}
	return period, true
}

// uriError attaches context to ErrInvalidURI. | uriError 为 ErrInvalidURI 附加上下文。
func uriError(format string, args ...any) error {
	return errs.Detail(ErrInvalidURI, format, args...)
}
