package cn

import (
	"strings"
	"unicode"

	"github.com/shibingli/ydx/errs"
)

// Name sentinels. | 姓名哨兵错误。
var (
	// ErrInvalidName reports an empty, over-long or control-character-bearing name. | ErrInvalidName 表示姓名为空、过长或包含控制字符。
	ErrInvalidName = errs.New("cn: invalid name | cn：姓名非法")
	// ErrPlaceholderName reports an obvious placeholder such as "test" or "匿名". | ErrPlaceholderName 表示 "test"、"匿名" 等明显的占位姓名。
	ErrPlaceholderName = errs.New("cn: placeholder name | cn：姓名为占位值")
)

// maxNameRunes bounds accepted name length. | maxNameRunes 限定可接受的姓名长度。
const maxNameRunes = 64

// MaskName masks a personal name while preserving its first and last rune. | MaskName 掩码个人姓名，保留首尾字符。
//
// Names of three or more runes keep the first and last rune and mask the middle, so "张小明" becomes
// "张*明" and "欧阳娜娜" becomes "欧**娜". Two-rune names become "张*" and a single rune becomes "*".
// The function is rune-aware and works for Chinese and non-Chinese names alike. | 三个及以上字符的姓名
// 保留首尾字符并掩码中间部分，因此 "张小明" 变为 "张*明"，"欧阳娜娜" 变为 "欧**娜"。两字姓名变为
// "张*"，单字变为 "*"。函数按 Unicode 字符处理，对中英文姓名同样适用。
func MaskName(name string) string {
	return MaskGeneric(strings.TrimSpace(name))
}

// MaskEmail masks the local part of an email address while keeping the domain. | MaskEmail 掩码邮箱地址的本地部分，保留域名。
//
// "alice@example.com" becomes "a***e@example.com"; two-character local parts keep the first
// character and one-character local parts become "*". Values without a valid local part and domain
// fall back to MaskGeneric. | "alice@example.com" 变为 "a***e@example.com"；两字符本地部分保留
// 首字符，单字符本地部分变为 "*"。缺少有效本地部分或域名的值回退到 MaskGeneric。
func MaskEmail(email string) string {
	s := strings.TrimSpace(email)
	at := strings.LastIndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return MaskGeneric(s)
	}
	local := []rune(s[:at])
	domain := s[at:]
	switch len(local) {
	case 0:
		return MaskGeneric(s)
	case 1:
		return "*" + domain
	case 2:
		return string(local[0]) + "*" + domain
	default:
		return string(local[0]) + "***" + string(local[len(local)-1]) + domain
	}
}

// MaskGeneric masks a value while preserving its first and last rune. | MaskGeneric 掩码任意值，保留首尾字符。
//
// Values of three or more runes keep the first and last rune; two-rune values become "x*";
// one-rune values become "*". The empty string stays empty. | 三个及以上字符保留首尾字符；两字符变为
// "x*"；单字符变为 "*"；空串保持为空。
func MaskGeneric(value string) string {
	runes := []rune(value)
	switch len(runes) {
	case 0:
		return ""
	case 1:
		return "*"
	case 2:
		return string(runes[0]) + "*"
	default:
		return string(runes[0]) + strings.Repeat("*", len(runes)-2) + string(runes[len(runes)-1])
	}
}

// NormalizeChineseName trims surrounding whitespace from a Chinese name and rejects placeholders. | NormalizeChineseName 去除中文姓名首尾空白并拒绝占位值。
//
// It trims ASCII whitespace, the ideographic space U+3000, the zero-width space U+200B and the byte
// order mark U+FEFF. Internal spaces are preserved so names such as "阿依古丽·买买提" and
// "Mary Jane" survive unchanged. The result must contain 1 to 64 runes, must not contain control
// characters, and must not be an obvious placeholder such as "test", "null", "匿名" or "暂无".
// Empty or malformed names return ErrInvalidName; placeholders return ErrPlaceholderName. | 去除
// ASCII 空白、全角空格 U+3000、零宽空格 U+200B 与字节序标记 U+FEFF。保留内部空格，因此
// "阿依古丽·买买提" 与 "Mary Jane" 原样保留。结果必须包含 1 至 64 个字符、不含控制字符，且不能是
// "test"、"null"、"匿名"、"暂无" 等明显占位值。空或格式非法返回 ErrInvalidName；占位值返回
// ErrPlaceholderName。
func NormalizeChineseName(name string) (string, error) {
	trimmed := strings.TrimFunc(name, func(r rune) bool {
		return unicode.IsSpace(r) || r == rune(0x200B) || r == rune(0xFEFF)
	})
	if trimmed == "" {
		return "", errs.Detail(ErrInvalidName, "name is empty | 姓名为空")
	}
	runes := []rune(trimmed)
	if len(runes) > maxNameRunes {
		return "", errs.Detail(ErrInvalidName, "name exceeds %d runes | 姓名超过 %d 个字符", maxNameRunes, maxNameRunes)
	}
	for _, r := range runes {
		if unicode.IsControl(r) {
			return "", errs.Detail(ErrInvalidName, "name contains control characters | 姓名包含控制字符")
		}
	}
	if isPlaceholderName(trimmed) {
		return "", errs.Detail(ErrPlaceholderName, "name is an obvious placeholder | 姓名是明显的占位值")
	}
	return trimmed, nil
}

// isPlaceholderName reports whether s is a well-known placeholder value. | isPlaceholderName 报告 s 是否为常见占位值。
func isPlaceholderName(s string) bool {
	switch strings.ToLower(s) {
	case "test", "testing", "null", "nil", "undefined", "none", "anonymous", "unknown", "n/a", "na",
		"姓名", "名字", "测试", "测试用户", "匿名", "匿名用户", "未知", "暂无", "无":
		return true
	}
	// A value made only of mask or filler punctuation is never a real name. | 只由掩码或填充标点组成的值不可能是真实姓名。
	for _, r := range s {
		switch r {
		case '*', '?', '.', '_', '-', '#':
			continue
		default:
			return false
		}
	}
	return true
}
