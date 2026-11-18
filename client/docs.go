// Package client provides a policy-driven HTTP client, streaming forwarder and
// request orchestrator built on net/http. | Package client 提供基于 net/http 的
// 策略化 HTTP 客户端、流式转发与请求编排能力。
//
// The core engine implements http.RoundTripper, so it can be used directly by a
// standard http.Client or as the transport of an existing client. | 核心引擎实现
// http.RoundTripper，可直接交给标准 http.Client 使用，也可替换已有客户端的 Transport。
//
// Basic usage with net/http semantics: | 使用 net/http 语义的基本用法：
//
//	c, err := client.New(
//		client.WithBaseURL("https://api.example.com"),
//	)
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
// The same engine can be mounted as a reverse proxy handler: | 同一引擎也可以挂成反向代理：
//
//	http.Handle("/gateway/", http.StripPrefix("/gateway", c.Handler()))
package client
