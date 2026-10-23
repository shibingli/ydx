//go:build !jsonx_std

package json

// skipSpaceRun returns the first position at or after pos that is not JSON whitespace. |
// skipSpaceRun 返回 pos 之后第一个不是 JSON 空白的位置。
func skipSpaceRun(data []byte, pos int) int {
	for pos < len(data) {
		switch data[pos] {
		case ' ', '\t', '\n', '\r':
			pos++
		default:
			return pos
		}
	}
	return pos
}

// scanDigits returns the first position at or after pos that is not an ASCII digit. |
// scanDigits 返回 pos 之后第一个不是 ASCII 数字的位置。
func scanDigits(data []byte, pos int) int {
	for pos < len(data) && data[pos] >= '0' && data[pos] <= '9' {
		pos++
	}
	return pos
}
