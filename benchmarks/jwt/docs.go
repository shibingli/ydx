// Package jwt contains the JWT benchmarks that live outside the component module, so
// github.com/shibingli/ydx/jwt never depends on benchmark-only code or comparison
// libraries. | Package jwt 保存位于组件模块之外的 JWT 基准，使
// github.com/shibingli/ydx/jwt 不依赖基准专用代码或对比库。
//
// Compared with golang-jwt/jwt/v5, lestrrat-go/jwx/v4 and go-jose/v4; see README.md for
// the measured tables. | 对比 golang-jwt/jwt/v5、lestrrat-go/jwx/v4 与 go-jose/v4；实测表见
// README.md。
//
// Run with | 运行方式：
//
//	cd benchmarks/jwt
//	GOWORK=off go test -run '^$' -bench . -benchmem
package jwt
