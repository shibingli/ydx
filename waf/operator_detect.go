package waf

import libinjection "github.com/corazawaf/libinjection-go"

// detectSQLi reports whether value contains a SQL injection payload and returns the libinjection
// fingerprint. | detectSQLi 报告 value 是否包含 SQL 注入载荷，并返回 libinjection 指纹。
func detectSQLi(value string) (bool, string) {
	return libinjection.IsSQLi(value)
}

// detectXSS reports whether value contains a cross-site scripting payload. | detectXSS 报告
// value 是否包含跨站脚本载荷。
func detectXSS(value string) bool {
	return libinjection.IsXSS(value)
}
