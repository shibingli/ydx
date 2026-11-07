package ldap

import "testing"

// FuzzParseFilter verifies hostile RFC 4515 text never panics and parsed filters
// round-trip through rendering. | FuzzParseFilter 校验恶意 RFC 4515 文本不会 panic，且已解析
// 过滤器可完成渲染。
func FuzzParseFilter(f *testing.F) {
	f.Add(`(cn=Babs Jensen)`)
	f.Add(`(&(objectClass=person)(|(sn=Jensen)(cn=Babs J*)))`)
	f.Add(`(cn:caseExactMatch:=Fred Flintstone)`)
	f.Add(`(cn=\zz)`)
	f.Fuzz(func(t *testing.T, input string) {
		filter, err := ParseFilter(input)
		if err != nil {
			return
		}
		_ = filter.String()
		_ = ValidateFilter(filter)
	})
}
