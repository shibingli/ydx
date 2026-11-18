# ydx/client

基于 `net/http` 的策略化 HTTP 客户端与转发引擎，正在实现中。

计划能力：

- 完整 HTTP 方法（含 CONNECT 隧道流）
- 路径规则匹配：`:id`、`{id}`、参数正则、段内通配、末段捕获
- 多 Host 负载、健康检查、故障剔除与换 Host 重试
- 可选缓存、并发请求合并、A/B 流量镜像
- SSE 出站消费、流式转发、影子上游重放与 tee 扇出
- 反向代理 `Forward`/`Handler`
- WAF/黑白名单/SSRF 防护
- UA 模拟与随机、Hooks、统计
- TLS 私有 CA、mTLS、证书固定、热更新
- Pipeline/Group 请求编排

设计稿：`../docs/superpowers/specs/2026-11-18-http-client-design.md`