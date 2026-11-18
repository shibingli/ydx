# ydx/client/waf

把 `ydx/waf` 的请求级 `Evaluate` 适配为 `ydx/client` 的 `Guard`，用于出站请求的 SecLang 检查。

```go
engine, err := ydxwaf.New(ydxwaf.Options{
    Directives: []string{
        `SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny,status:403"`,
    },
})
guard, err := clientwaf.New(clientwaf.Options{Engine: engine, InspectBody: true})
c, err := client.New(
    client.WithHosts("https://api.example.com"),
    client.WithGuard(guard),
)
```

`InspectBody=false`（默认）不读取正文；`FailOpen=true` 在 WAF 求值失败时放行。