package redis

import (
	"strconv"
	"strings"
)

// parseInt parses a decimal integer stored in a hash field. | parseInt 解析哈希字段中的十进制整数。
func parseInt(value string) (int64, error) {
	return strconv.ParseInt(value, 10, 64)
}

// normalizePhone mirrors the auth in-memory store's phone normalization: digits only, one
// leading '+', common separators ignored, a leading 00 and a Chinese 86 country code removed.
// | normalizePhone 与 auth 内存存储的手机号规范化保持一致：仅保留数字、允许一个前导 '+'、
// 忽略常见分隔符，并去掉前导 00 与中国区号 86。
func normalizePhone(phone string) (string, bool) {
	var b strings.Builder
	b.Grow(len(phone))
	for _, r := range phone {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '+' && b.Len() == 0:
		case r == ' ' || r == '\t' || r == '\r' || r == '\n' || r == '-' ||
			r == '(' || r == ')' || r == '　':
		default:
			return "", false
		}
	}
	digits := b.String()
	digits = strings.TrimPrefix(digits, "00")
	if len(digits) == 13 && strings.HasPrefix(digits, "86") && digits[2] == '1' {
		digits = digits[2:]
	}
	if len(digits) < 5 {
		return "", false
	}
	return digits, true
}

// flag returns "1" for true and "0" for false, the encoding Lua scripts expect.
// | flag 对 true 返回 "1"，对 false 返回 "0"，即 Lua 脚本期望的编码。
func flag(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

// stringValue converts one Redis multi-bulk element to a string.
// | stringValue 把单个 Redis 多批量元素转换为字符串。
func stringValue(v any) string {
	switch value := v.(type) {
	case nil:
		return ""
	case string:
		return value
	case []byte:
		return string(value)
	default:
		return ""
	}
}

// pageBounds applies a zero-based offset and a positive limit to total.
// | pageBounds 把从零开始的偏移与正数上限应用到 total。
func pageBounds(offset, limit, total int) (int, int) {
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		offset = total
	}
	if limit <= 0 {
		return offset, total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return offset, end
}
