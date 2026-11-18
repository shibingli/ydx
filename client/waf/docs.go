// Package waf adapts ydx/waf into a client.Guard so outbound requests can be
// inspected before cache, coalescing or host selection. | Package waf 把 ydx/waf 适配为
// client.Guard，使出站请求在缓存、合并或 Host 选择前被检查。
//
// The adapter calls waf.WAF.Evaluate, which runs request phases 1 and 2 without
// writing a response. | 适配器调用 waf.WAF.Evaluate，只执行请求阶段 1 与 2，不写响应。
package waf
