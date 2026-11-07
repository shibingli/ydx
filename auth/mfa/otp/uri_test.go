package otp

import (
	"encoding/base32"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestGenerateURITOTPRoundTrip checks TOTP URI generation, percent encoding and parsing.
// | TestGenerateURITOTPRoundTrip 检查 TOTP URI 生成、百分号编码与解析。
func TestGenerateURITOTPRoundTrip(t *testing.T) {
	t.Parallel()
	secret, err := GenerateSecret(0)
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	cfg := Config{Digits: 8, Period: 45 * time.Second, Algorithm: SHA256}
	raw := GenerateURI("Example Co", "alice@example.com", secret, cfg)
	if !strings.HasPrefix(raw, "otpauth://totp/") {
		t.Fatalf("URI = %q, want otpauth://totp/ prefix | URI 前缀不正确", raw)
	}
	if strings.Contains(raw, "Example Co") {
		t.Errorf("URI contains an unencoded space: %q | URI 含未编码空格", raw)
	}
	if !strings.Contains(raw, "issuer=Example+Co") {
		t.Errorf("URI issuer parameter is not encoded as expected: %q | issuer 参数编码不符预期", raw)
	}
	parsed, err := ParseURI(raw)
	if err != nil {
		t.Fatalf("ParseURI: %v | 解析失败", err)
	}
	if parsed.Type != KindTOTP {
		t.Errorf("Type = %q, want totp | 类型不匹配", parsed.Type)
	}
	if parsed.Issuer != "Example Co" {
		t.Errorf("Issuer = %q, want %q | 签发方不匹配", parsed.Issuer, "Example Co")
	}
	if parsed.AccountName != "alice@example.com" {
		t.Errorf("AccountName = %q, want %q | 账号不匹配", parsed.AccountName, "alice@example.com")
	}
	if parsed.Secret != secret {
		t.Errorf("Secret = %q, want %q | 密钥不匹配", parsed.Secret, secret)
	}
	if parsed.Algorithm != SHA256 {
		t.Errorf("Algorithm = %q, want SHA256 | 算法不匹配", parsed.Algorithm)
	}
	if parsed.Digits != 8 {
		t.Errorf("Digits = %d, want 8 | 位数不匹配", parsed.Digits)
	}
	if parsed.Period != 45*time.Second {
		t.Errorf("Period = %s, want 45s | 时间步不匹配", parsed.Period)
	}
	if parsed.Counter != 0 {
		t.Errorf("Counter = %d, want 0 | 计数器不匹配", parsed.Counter)
	}
	if reparsed := parsed.String(); reparsed != raw {
		t.Errorf("String round trip = %q, want %q | URI 往返不一致", reparsed, raw)
	}
}

// TestGenerateURIHOTPRoundTrip checks HOTP URI generation and parsing. | TestGenerateURIHOTPRoundTrip 检查 HOTP URI 生成与解析。
func TestGenerateURIHOTPRoundTrip(t *testing.T) {
	t.Parallel()
	secret := testSecret("12345678901234567890")
	raw := GenerateHOTPURI("Example", "alice", secret, 42, Config{Digits: 7})
	if !strings.HasPrefix(raw, "otpauth://hotp/") {
		t.Fatalf("URI = %q, want otpauth://hotp/ prefix | URI 前缀不正确", raw)
	}
	if strings.Contains(raw, "period=") {
		t.Errorf("HOTP URI contains a period parameter: %q | HOTP URI 含 period 参数", raw)
	}
	parsed, err := ParseURI(raw)
	if err != nil {
		t.Fatalf("ParseURI: %v | 解析失败", err)
	}
	if parsed.Type != KindHOTP {
		t.Errorf("Type = %q, want hotp | 类型不匹配", parsed.Type)
	}
	if parsed.Counter != 42 {
		t.Errorf("Counter = %d, want 42 | 计数器不匹配", parsed.Counter)
	}
	if parsed.Digits != 7 {
		t.Errorf("Digits = %d, want 7 | 位数不匹配", parsed.Digits)
	}
	if parsed.Period != DefaultPeriod {
		t.Errorf("Period = %s, want %s | 时间步不匹配", parsed.Period, DefaultPeriod)
	}
}

// TestParseURICaseInsensitive checks case-insensitive parameter names and algorithm aliases.
// | TestParseURICaseInsensitive 检查参数名大小写不敏感与算法别名。
func TestParseURICaseInsensitive(t *testing.T) {
	t.Parallel()
	secret := testSecret("12345678901234567890")
	raw := "otpauth://TOTP/Example:alice%40example.com?SECRET=" + secret +
		"&ALGORITHM=sha-256&DIGITS=8&PERIOD=45&ISSUER=Example"
	parsed, err := ParseURI(raw)
	if err != nil {
		t.Fatalf("ParseURI: %v | 解析失败", err)
	}
	if parsed.Type != KindTOTP {
		t.Errorf("Type = %q, want totp | 类型不匹配", parsed.Type)
	}
	if parsed.Issuer != "Example" {
		t.Errorf("Issuer = %q, want Example | 签发方不匹配", parsed.Issuer)
	}
	if parsed.AccountName != "alice@example.com" {
		t.Errorf("AccountName = %q, want alice@example.com | 账号不匹配", parsed.AccountName)
	}
	if parsed.Algorithm != SHA256 {
		t.Errorf("Algorithm = %q, want SHA256 | 算法不匹配", parsed.Algorithm)
	}
	if parsed.Digits != 8 || parsed.Period != 45*time.Second {
		t.Errorf("digits/period = %d/%s, want 8/45s | 位数或时间步不匹配", parsed.Digits, parsed.Period)
	}
}

// TestParseURIIssuerPlacement checks issuer discovery from the label, the query, or both.
// | TestParseURIIssuerPlacement 检查从标签、查询串或两者发现 issuer。
func TestParseURIIssuerPlacement(t *testing.T) {
	t.Parallel()
	secret := testSecret("12345678901234567890")
	tests := []struct {
		name        string
		raw         string
		wantIssuer  string
		wantAccount string
	}{
		{
			name:        "label encoded colon",
			raw:         "otpauth://totp/Example%3Aalice?secret=" + secret,
			wantIssuer:  "Example",
			wantAccount: "alice",
		},
		{
			name:        "query only",
			raw:         "otpauth://totp/alice?secret=" + secret + "&issuer=Example",
			wantIssuer:  "Example",
			wantAccount: "alice",
		},
		{
			name:        "label and query",
			raw:         "otpauth://totp/Example:alice?secret=" + secret + "&issuer=Example",
			wantIssuer:  "Example",
			wantAccount: "alice",
		},
		{
			name:        "account colon with mismatched issuer",
			raw:         "otpauth://totp/alice:work?secret=" + secret + "&issuer=Example",
			wantIssuer:  "Example",
			wantAccount: "work",
		},
		{
			name:        "no issuer",
			raw:         "otpauth://totp/alice?secret=" + secret,
			wantIssuer:  "",
			wantAccount: "alice",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			parsed, err := ParseURI(tt.raw)
			if err != nil {
				t.Fatalf("ParseURI: %v | 解析失败", err)
			}
			if parsed.Issuer != tt.wantIssuer {
				t.Errorf("Issuer = %q, want %q | 签发方不匹配", parsed.Issuer, tt.wantIssuer)
			}
			if parsed.AccountName != tt.wantAccount {
				t.Errorf("AccountName = %q, want %q | 账号不匹配", parsed.AccountName, tt.wantAccount)
			}
		})
	}
}

// TestParseURIDefaults checks default parameters. | TestParseURIDefaults 检查默认参数。
func TestParseURIDefaults(t *testing.T) {
	t.Parallel()
	secret := testSecret("12345678901234567890")
	parsed, err := ParseURI("otpauth://totp/alice?secret=" + secret)
	if err != nil {
		t.Fatalf("ParseURI: %v | 解析失败", err)
	}
	if parsed.Algorithm != SHA1 || parsed.Digits != DefaultDigits || parsed.Period != DefaultPeriod {
		t.Errorf("defaults = %q/%d/%s, want SHA1/%d/%s | 默认值不匹配",
			parsed.Algorithm, parsed.Digits, parsed.Period, DefaultDigits, DefaultPeriod)
	}
}

// TestParseURISecretCanonicalization checks that the parsed secret is canonical. | TestParseURISecretCanonicalization 检查解析后的密钥已规范化。
func TestParseURISecretCanonicalization(t *testing.T) {
	t.Parallel()
	padded := base32Padded("12345678901234567890")
	messy := " " + strings.ToLower(padded)
	parsed, err := ParseURI("otpauth://totp/alice?secret=" + urlQueryEscape(messy))
	if err != nil {
		t.Fatalf("ParseURI: %v | 解析失败", err)
	}
	if want := testSecret("12345678901234567890"); parsed.Secret != want {
		t.Errorf("Secret = %q, want %q | 密钥未规范化", parsed.Secret, want)
	}
}

// TestParseURIInvalid checks malformed URI handling. | TestParseURIInvalid 检查非法 URI 处理。
func TestParseURIInvalid(t *testing.T) {
	t.Parallel()
	secret := testSecret("12345678901234567890")
	tests := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"wrong scheme", "https://totp/alice?secret=" + secret},
		{"unknown type", "otpauth://webauthn/alice?secret=" + secret},
		{"missing secret", "otpauth://totp/alice"},
		{"empty secret", "otpauth://totp/alice?secret="},
		{"bad secret", "otpauth://totp/alice?secret=!!!!"},
		{"digits too small", "otpauth://totp/alice?secret=" + secret + "&digits=5"},
		{"digits too large", "otpauth://totp/alice?secret=" + secret + "&digits=11"},
		{"digits not a number", "otpauth://totp/alice?secret=" + secret + "&digits=abc"},
		{"zero period", "otpauth://totp/alice?secret=" + secret + "&period=0"},
		{"negative period", "otpauth://totp/alice?secret=" + secret + "&period=-5"},
		{"period not a duration", "otpauth://totp/alice?secret=" + secret + "&period=abc"},
		{"sub-second period", "otpauth://totp/alice?secret=" + secret + "&period=500ms"},
		{"negative counter", "otpauth://hotp/alice?secret=" + secret + "&counter=-1"},
		{"counter not a number", "otpauth://hotp/alice?secret=" + secret + "&counter=abc"},
		{"bad query escape", "otpauth://totp/alice?secret=" + secret + "&%zz=1"},
		{"user info", "otpauth://user@totp/alice?secret=" + secret},
		{"port", "otpauth://totp:80/alice?secret=" + secret},
		{"fragment", "otpauth://totp/alice?secret=" + secret + "#fragment"},
		{"bad path escape", "otpauth://totp/%zz?secret=" + secret},
		{"unsupported algorithm", "otpauth://totp/alice?secret=" + secret + "&algorithm=MD5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseURI(tt.raw); !errors.Is(err, ErrInvalidURI) {
				t.Errorf("ParseURI error = %v, want ErrInvalidURI | ParseURI 错误应为 ErrInvalidURI", err)
			}
		})
	}
}

// TestParseURIIssuerMismatchPrefersQuery checks that the query issuer wins when it disagrees with
// the label prefix. | TestParseURIIssuerMismatchPrefersQuery 检查查询串 issuer 与标签前缀不一致时
// 以查询串为准。
func TestParseURIIssuerMismatchPrefersQuery(t *testing.T) {
	t.Parallel()
	secret := testSecret("12345678901234567890")
	parsed, err := ParseURI("otpauth://totp/Old:alice?secret=" + secret + "&issuer=New")
	if err != nil {
		t.Fatalf("ParseURI: %v | 解析失败", err)
	}
	if parsed.Issuer != "New" {
		t.Errorf("Issuer = %q, want New | 应以查询串 issuer 为准", parsed.Issuer)
	}
	if parsed.AccountName != "alice" {
		t.Errorf("AccountName = %q, want alice | 账号不匹配", parsed.AccountName)
	}
}

// TestURIString checks rendering from a struct and unknown type fallback. | TestURIString 检查从结构体渲染与未知类型回退。
func TestURIString(t *testing.T) {
	t.Parallel()
	secret := testSecret("12345678901234567890")
	uri := URI{
		Type:        KindTOTP,
		Issuer:      "Example",
		AccountName: "alice",
		Secret:      secret,
		Algorithm:   SHA256,
		Digits:      8,
		Period:      60 * time.Second,
	}
	parsed, err := ParseURI(uri.String())
	if err != nil {
		t.Fatalf("ParseURI: %v | 解析失败", err)
	}
	if parsed.Issuer != "Example" || parsed.AccountName != "alice" || parsed.Digits != 8 ||
		parsed.Algorithm != SHA256 || parsed.Period != time.Minute {
		t.Errorf("parsed URI = %+v | 解析结果不匹配", parsed)
	}
	unknown := uri
	unknown.Type = Kind("unknown")
	if !strings.HasPrefix(unknown.String(), "otpauth://totp/") {
		t.Errorf("unknown type did not fall back to totp: %q | 未知类型未回退到 totp", unknown.String())
	}
	invalid := URI{Type: KindHOTP, AccountName: "alice", Secret: secret, Digits: 99, Algorithm: "MD5", Period: 0}
	parsedInvalid, err := ParseURI(invalid.String())
	if err != nil {
		t.Fatalf("ParseURI(invalid normalized): %v | 非法值未回退", err)
	}
	if parsedInvalid.Digits != DefaultDigits || parsedInvalid.Algorithm != SHA1 {
		t.Errorf("invalid values did not fall back: %+v | 非法值未回退", parsedInvalid)
	}
}

// TestURIConfig checks the Config projection. | TestURIConfig 检查 Config 投影。
func TestURIConfig(t *testing.T) {
	t.Parallel()
	uri := URI{
		Type:        KindTOTP,
		Issuer:      "Example",
		AccountName: "alice",
		Algorithm:   SHA512,
		Digits:      7,
		Period:      15 * time.Second,
	}
	cfg := uri.Config()
	if cfg.Issuer != "Example" || cfg.AccountName != "alice" || cfg.Algorithm != SHA512 ||
		cfg.Digits != 7 || cfg.Period != 15*time.Second {
		t.Errorf("Config() = %+v | Config 投影不匹配", cfg)
	}
}

// base32Padded encodes raw with base32 padding. | base32Padded 使用 base32 填充编码 raw。
func base32Padded(raw string) string {
	return base32.StdEncoding.EncodeToString([]byte(raw))
}

// urlQueryEscape escapes a query value with the standard library. | urlQueryEscape 使用标准库转义查询值。
func urlQueryEscape(value string) string {
	return url.QueryEscape(value)
}
