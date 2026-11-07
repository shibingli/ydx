package auth

import (
	"testing"

	goldap "github.com/go-ldap/ldap/v3"
	ydldap "github.com/shibingli/ydx/auth/directory/ldap"
)

// testFilter is a representative AND filter with equality, substring and presence components. |
// testFilter 是包含相等、子串与存在组件的代表性 AND 过滤器。
const testFilter = `(&(uid=alice)(cn=ali*ce)(mail=*))`

// BenchmarkLDAPFilterParse compares RFC 4515 filter parsing. The go-ldap path also produces its
// BER encoding, so it does more work than a pure parse. | BenchmarkLDAPFilterParse 对比 RFC 4515
// 过滤器解析。go-ldap 路径同时生成 BER 编码，因此比纯解析做的工作更多。
func BenchmarkLDAPFilterParse(b *testing.B) {
	b.Run("ydx", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := ydldap.ParseFilter(testFilter); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("go-ldap", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := goldap.CompileFilter(testFilter); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkLDAPFilterRender compares rendering a parsed filter back to RFC 4515 form. |
// BenchmarkLDAPFilterRender 对比把已解析过滤器渲染回 RFC 4515 形式。
func BenchmarkLDAPFilterRender(b *testing.B) {
	filter, err := ydldap.ParseFilter(testFilter)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = filter.String()
	}
}

// TestLDAPFilterInteropWithGoLDAP checks that both parsers accept ydx-rendered filters. |
// TestLDAPFilterInteropWithGoLDAP 检查两个解析器都接受 ydx 渲染的过滤器。
func TestLDAPFilterInteropWithGoLDAP(t *testing.T) {
	for _, input := range []string{
		testFilter,
		`(uid=alice)`,
		`(|(uid=alice)(uid=bob))`,
		`(&(objectClass=person)(!(disabled=TRUE)))`,
		`(cn=*alice*)`,
		`(uid=alice\2abob)`,
		`(age>=18)`,
		`(age<=65)`,
		`(cn~=alice)`,
	} {
		parsed, err := ydldap.ParseFilter(input)
		if err != nil {
			t.Fatalf("ydx ParseFilter(%q): %v", input, err)
		}
		if _, err := goldap.CompileFilter(parsed.String()); err != nil {
			t.Fatalf("go-ldap rejected ydx rendering %q: %v | go-ldap 拒绝 ydx 渲染", parsed.String(), err)
		}
		if _, err := goldap.CompileFilter(input); err != nil {
			t.Fatalf("go-ldap rejected input %q: %v", input, err)
		}
	}
}
