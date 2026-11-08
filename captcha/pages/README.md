# captcha/pages — 示例页与嵌入资源

本目录提供可直接托管的浏览器示例，以及 Go 模块通过 `go:embed` 发布的同源资源。

## 目录

- `assets/yd-captcha.js`、`assets/yd-captcha.css`：浏览器 SDK 构建产物。由
  `sdk/browser/scripts/build.mjs` 从 `sdk/browser/src/` 同步生成，**不要手工编辑**。
- `example/index.html`：独立示例页，支持语言与明暗主题切换、`?endpoint=`、
  `?type=` 与 `?fallback=` 参数。

## 使用

先启动一个挂载了验证码处理器的服务，使示例页通过相对路径访问 `/captcha`：

```go
manager, _ := captcha.New(captcha.Options{Secret: []byte(os.Getenv("CAPTCHA_SECRET"))})
http.Handle("/captcha/", manager.Handler(captcha.HandlerOptions{}))
http.Handle("/captcha-example/", http.StripPrefix("/captcha-example/", http.FileServer(http.Dir("captcha/pages"))))
```

然后访问 `/captcha-example/example/index.html`。若验证码端点位于其它路径，可追加
`?endpoint=https://app.example.com/captcha`。

## 构建与校验

修改 `sdk/browser/src/` 后运行：

```bash
node sdk/browser/scripts/build.mjs
```

脚本会把同一份产物写入 `sdk/browser/dist/`、`transport/assets/` 与
`captcha/pages/assets/`；`transport/assets_test.go` 会校验嵌入资源与源码一致。
