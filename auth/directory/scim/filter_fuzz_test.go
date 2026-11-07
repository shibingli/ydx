package scim

import "testing"

// FuzzParseFilter verifies hostile filter text never panics and parsed filters stay
// renderable and evaluable. | FuzzParseFilter 校验恶意过滤器文本不会 panic，且已解析过滤器可
// 渲染与求值。
func FuzzParseFilter(f *testing.F) {
	f.Add(`userName eq "alice"`)
	f.Add(`emails[type eq "work"].value co "@example.com"`)
	f.Add(`(userName eq "a")`)
	f.Add(`userName eq "` + "\x00" + `"`)
	f.Fuzz(func(t *testing.T, input string) {
		filter, err := ParseFilter(input)
		if err != nil {
			return
		}
		_ = filter.String()
		_ = filter.Match(map[string]any{"userName": "alice", "active": true})
	})
}
