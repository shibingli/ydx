// Package client provides a policy-driven HTTP client, streaming forwarder and
// request orchestrator built on net/http. | Package client 提供基于 net/http 的
// 策略化 HTTP 客户端、流式转发与请求编排能力。
//
// The core engine implements http.RoundTripper, so it can be used directly by a
// standard http.Client or as the transport of an existing client. | 核心引擎实现
// http.RoundTripper，可直接交给标准 http.Client 使用，也可替换已有客户端的 Transport。
// The default client carries an in-memory cookie jar, so Set-Cookie responses
// survive 301/302/303/307/308 redirects; use WithoutCookieJar to disable it. |
// 默认客户端带内存 Cookie Jar，301/302/303/307/308 跳转会自动带入 Set-Cookie；
// 可用 WithoutCookieJar 关闭。
//
// Multipart request bodies buffer known payloads up to 1 MiB and stream larger
// bodies through a pipe. | Multipart 请求正文对已知且不超过 1 MiB 的载荷缓冲，
// 更大的载荷通过管道流式发送。
//
// # Basic usage | 基本用法
//
//	c, err := client.New(client.WithBaseURL("https://api.example.com"))
//	if err != nil {
//		log.Fatal("create client", log.Err(err))
//	}
//	defer c.Close()
//
//	resp, err := c.Get(context.Background(), "/api/user/42")
//	if err != nil {
//		log.Fatal("request failed", log.Err(err))
//	}
//	defer resp.Body.Close()
//
// # Rules, hosts and cache | 规则、Host 与缓存
//
//	c, err := client.New(
//		client.WithHosts("https://api-a.example.com", "https://api-b.example.com"),
//		client.WithRule(client.Rule{
//			Name:    "user",
//			Pattern: "/api/user/{id}",
//			Cache:   &client.CachePolicy{TTL: 30 * time.Second},
//		}),
//	)
//
// # SSE forwarding | SSE 转发
//
// Mount the reverse proxy on a YD route or on net/http: | 把反向代理挂到 YD 路由或 net/http：
//
//	r.HandleRaw(http.MethodGet, "/gateway", c.Handler().ServeHTTP)
//	http.Handle("/gateway/", http.StripPrefix("/gateway", c.Handler()))
//
// The handler detects text/event-stream and streams it chunk by chunk with a
// Flush; cache and coalescing are bypassed for streams. | Handler 会识别
// text/event-stream 并逐块 Flush；流式响应绕过缓存与合并。
//
// # Pipeline orchestration | Pipeline 编排
//
//	plan := client.NewPipeline(client.PipelineOptions{Timeout: 10 * time.Second},
//		client.Step("login").POST("/auth/login").JSON(credentials).
//			ExtractJSON("token", "token"),
//		client.Parallel(
//			client.Step("profile").GET("/api/me").
//				HeaderFunc("Authorization", func(v *client.Vars) string {
//					return "Bearer " + v.String("token")
//				}),
//			client.Step("orders").GET("/api/orders").
//				HeaderFunc("Authorization", func(v *client.Vars) string {
//					return "Bearer " + v.String("token")
//				}),
//		),
//	)
//	result, err := plan.Run(ctx, c)
//
// # Rule-level UA and tracing | 规则级 UA 与追踪
//
//	c, err := client.New(
//		client.WithTrace(true),
//		client.WithRule(client.Rule{
//			Name:    "mobile",
//			Pattern: "/m/{path:*}",
//			UA:      &client.UAPolicy{Mode: client.UAFixed, List: []string{"custom-ua"}, Force: true},
//		}),
//	)
//
// Absolute URLs connect directly by default; use WithRewriteAll(true) to route
// them through the default host pool. | 绝对 URL 默认直连；用 WithRewriteAll(true)
// 可强制走默认 Host 池。
//
// # TLS | TLS
//
//	c, err := client.New(
//		client.WithHosts("https://mts.example.com"),
//		client.WithTLS(client.TLSConfig{
//			RootCAFiles: []string{"/etc/ydx/ca.pem"},
//			CertFile:    "/etc/ydx/client.pem",
//			KeyFile:     "/etc/ydx/client-key.pem",
//		}),
//	)
//	err = c.ReloadTLS() // re-read files and swap new connections
package client
