// Package waf protects HTTP services with the OWASP Coraza engine. | Package waf 使用 OWASP
// Coraza 引擎保护 HTTP 服务。
//
// The middleware covers the complete request lifecycle: request line and headers (phase 1),
// request body (phase 2), response headers (phase 3), response body (phase 4), the logging phase
// (phase 5) and transaction cleanup. Rule files load first, a security baseline loads next, and
// inline directives load last: a third-party rule file cannot weaken the baseline, while explicit
// inline directives can still override it. The baseline is blocking mode, request body access, an
// 8 MiB request limit with 128 KiB kept in memory, response body access disabled, and audit
// logging disabled (blocks and detections go through ydx/log and Observer). | 中间件覆盖完整请求
// 生命周期：请求行与请求头（阶段 1）、请求正文（阶段 2）、响应头（阶段 3）、响应正文（阶段 4）、
// 日志阶段（阶段 5）与事务清理。规则文件最先加载，安全基线其次，内联指令最后：第三方规则文件
// 无法削弱基线，而显式内联指令仍可覆盖它。基线为拦截模式、开启请求正文访问、请求上限 8 MiB
// （其中 128 KiB 驻留内存）、关闭响应正文访问、关闭审计日志（拦截与检测通过 ydx/log 与
// Observer 输出）。
//
// Rules come from Directives, RuleFiles or an embedded filesystem (RootFS). Full OWASP CRS is
// intentionally not bundled: load only the rule files your threat model needs, start in
// ModeDetection, then switch to ModeBlock after tuning. | 规则来自 Directives、RuleFiles 或嵌入式
// 文件系统（RootFS）。本包刻意不捆绑完整 OWASP CRS：只加载威胁模型所需的规则文件，先以
// ModeDetection 上线，调优后再切换 ModeBlock。
//
// CONNECT tunnels (WebSocket over HTTP/2 or HTTP/3, WebTransport, raw TCP) are inspected at the
// request line and headers only; the response phase is skipped so transport-specific writer
// interfaces stay available. | CONNECT 隧道（HTTP/2 或 HTTP/3 WebSocket、WebTransport、原始 TCP）
// 只检测请求行与请求头；响应阶段会被跳过，以保留传输层专用的写入器接口。
//
// YD router | YD 路由：
//
//	engine, err := waf.New(waf.Options{
//		Directives: []string{
//			`SecRule REQUEST_URI "@contains /etc/passwd" "id:9001,phase:1,deny,status:403"`,
//			`SecRule ARGS "@detectSQLi" "id:9002,phase:2,deny,status:403"`,
//		},
//		Exclude: func(r *http.Request) bool { return r.URL.Path == "/healthz" },
//	})
//	if err != nil {
//		return err
//	}
//	defer engine.Close()
//	r.Use(engine.Middleware())
//
// Native net/http | 原生 net/http：
//
//	handler := engine.HTTPMiddleware(mux)
//	_ = http.ListenAndServe(":8080", handler)
//
// Rules can be reloaded atomically with Reload or ReloadWith, and graceful shutdown drains
// in-flight transactions with Shutdown. | 规则可通过 Reload 或 ReloadWith 原子重载；优雅关闭可用
// Shutdown 排空在途事务。
package waf
