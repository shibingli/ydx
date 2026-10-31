package waf

import (
	"strconv"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// byteRanges is a compiled @validateByteRange allow list. | byteRanges 是编译后的
// @validateByteRange 允许列表。
type byteRanges struct {
	allowed [256]bool
}

// parseByteRanges parses a SecLang byte range list such as "9,10,13,32-126". | parseByteRanges
// 解析 "9,10,13,32-126" 这类 SecLang 字节范围列表。
func parseByteRanges(value string) (byteRanges, error) {
	var ranges byteRanges
	parts := strings.Split(value, ",")
	seen := false
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		low, high, err := parseByteRange(part)
		if err != nil {
			return byteRanges{}, err
		}
		for b := low; b <= high; b++ {
			ranges.allowed[b] = true
		}
		seen = true
	}
	if !seen {
		return byteRanges{}, errs.Detail(ErrParse, "empty byte range | 空的字节范围")
	}
	return ranges, nil
}

// parseByteRange parses one "N" or "N-M" range. | parseByteRange 解析一个 "N" 或 "N-M" 范围。
func parseByteRange(value string) (int, int, error) {
	if lowText, highText, ok := strings.Cut(value, "-"); ok {
		low, err := strconv.Atoi(strings.TrimSpace(lowText))
		if err != nil {
			return 0, 0, errs.Detail(ErrParse, "invalid byte range %q | 非法的字节范围 %q", value, value)
		}
		high, err := strconv.Atoi(strings.TrimSpace(highText))
		if err != nil {
			return 0, 0, errs.Detail(ErrParse, "invalid byte range %q | 非法的字节范围 %q", value, value)
		}
		if low < 0 || high > 255 || low > high {
			return 0, 0, errs.Detail(ErrParse, "byte range out of bounds %q | 字节范围越界 %q", value, value)
		}
		return low, high, nil
	}
	value = strings.TrimSpace(value)
	number, err := strconv.Atoi(value)
	if err != nil || number < 0 || number > 255 {
		return 0, 0, errs.Detail(ErrParse, "invalid byte value %q | 非法的字节值 %q", value, value)
	}
	return number, number, nil
}

// valid reports whether every byte of s is allowed. | valid 报告 s 的每个字节是否都被允许。
func (r byteRanges) valid(s string) bool {
	for i := 0; i < len(s); i++ {
		if !r.allowed[s[i]] {
			return false
		}
	}
	return true
}
