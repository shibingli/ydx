package cn

import (
	"strings"

	"github.com/shibingli/ydx/errs"
)

// ErrInvalidBankCard reports a malformed or checksum-invalid bank card number. | ErrInvalidBankCard 表示银行卡号格式非法或校验码不匹配。
var ErrInvalidBankCard = errs.New("cn: invalid bank card number | cn：银行卡号非法")

// ValidateBankCard reports whether raw is a plausible bank card number. | ValidateBankCard 报告 raw 是否为合理的银行卡号。
//
// Accepted input contains 12 to 19 digits, optionally separated by ASCII spaces, tabs, hyphens or
// the ideographic space. The Luhn (MOD 10) check must pass. The check is structural: it does not
// prove that the card exists or is active. | 接受 12 至 19 位数字，可用 ASCII 空格、制表符、连字符或
// 全角空格分隔。必须通过 Luhn（MOD 10）校验。该校验是结构性的，不能证明卡片真实存在或处于可用状态。
func ValidateBankCard(raw string) bool {
	digits, ok := bankCardDigits(raw)
	if !ok || len(digits) < 12 || len(digits) > 19 {
		return false
	}
	return luhnValid(digits)
}

// MaskBankCard masks a bank card number, keeping the first four and last four digits. | MaskBankCard 掩码银行卡号，保留前四位与后四位。
//
// "6222021234567890123" becomes "6222***********0123". Numbers shorter than eight digits keep only
// the last four digits; input containing non-digit characters falls back to MaskGeneric. |
// "6222021234567890123" 变为 "6222***********0123"。少于八位的号码只保留后四位；含非数字字符的
// 输入回退到 MaskGeneric。
func MaskBankCard(raw string) string {
	digits, ok := bankCardDigits(raw)
	if !ok {
		return MaskGeneric(raw)
	}
	n := len(digits)
	switch {
	case n == 0:
		return ""
	case n <= 4:
		return strings.Repeat("*", n)
	case n < 8:
		return strings.Repeat("*", n-4) + digits[n-4:]
	default:
		return digits[:4] + strings.Repeat("*", n-8) + digits[n-4:]
	}
}

// bankCardDigits extracts digits from an accepted bank-card form. | bankCardDigits 从接受的银行卡号形式中提取数字。
func bankCardDigits(raw string) (string, bool) {
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '\t' || r == '\r' || r == '\n' || r == '-' || r == '　':
			continue
		default:
			return "", false
		}
	}
	return b.String(), true
}

// luhnValid reports whether digits passes the Luhn (MOD 10) check. | luhnValid 报告 digits 是否通过 Luhn（MOD 10）校验。
func luhnValid(digits string) bool {
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}
