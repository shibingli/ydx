// Package waf contains the net/http performance and compatibility benchmarks for
// github.com/shibingli/ydx/waf against Coraza v3. The component module stays free of Coraza and
// benchmark-only dependencies. | Package waf 保存 github.com/shibingli/ydx/waf 对 Coraza v3 的
// net/http 性能与兼容性基准，使组件模块不依赖 Coraza 或基准专用代码。
//
// Both engines receive the same requests through their net/http middleware. ydx/waf also exposes
// the same evaluation engine through its YD router middleware, so the HTTP path measured here is
// the shared hot path used by router and net/http integrations. | 两个引擎通过各自的 net/http
// 中间件处理同一批请求。ydx/waf 通过 YD 路由中间件暴露出同一套求值引擎，因此这里测量的 HTTP
// 路径就是 router 与 net/http 集成共享的热路径。
//
// Run with | 运行方式：
//
//	cd benchmarks/waf
//	GOWORK=off go test ./...
//	GOWORK=off go test -run '^$' -bench . -benchmem -count=5
//
// The embedded rules in testdata/rules.conf are used by default so the benchmarks run without
// external data. Set YDX_WAF_CRS_DIR to an OWASP CRS directory containing crs-setup.conf and
// rules/*.conf to benchmark and test the full CRS set. | 默认使用 testdata/rules.conf 中的内嵌
// 规则，无需外部数据即可运行。把 YDX_WAF_CRS_DIR 指向包含 crs-setup.conf 与 rules/*.conf 的
// OWASP CRS 目录，即可对完整 CRS 规则集运行基准与兼容性测试。
//
//	YDX_WAF_CRS_DIR=/path/to/coreruleset GOWORK=off go test -run '^$' -bench . -benchmem -count=5
package waf
