// Package captcha provides human-verification challenges, risk control and
// host-recordable audit events for YD and plain net/http applications.
// | Package captcha 为 YD 与原生 net/http 应用提供人机验证挑战、风险控制与可回写宿主的审计事件。
//
// # Challenge families | 验证码类型
//
// Built-in providers cover distorted text (Chinese, English and digits), ordered
// character selection, ordered icon selection, semantic category selection,
// two-axis slide puzzles, scratch cards and orientation rotation. SMS and email
// challenges share one delivery abstraction. Custom visual families can be
// registered through Manager.RegisterProvider. | 内置生成器覆盖扭曲文本（中英文与数字）、
// 有序文字点选、有序图标点选、语义分类选择、双轴滑动拼图、刮刮卡与方向旋转。短信与邮件
// 挑战共用一套下发抽象。自定义视觉类型可通过 Manager.RegisterProvider 注册。
//
// # Security model | 安全模型
//
// The expected answer, target coordinates and one-time code hashes stay on the
// server. A challenge is consumed atomically before validation, has a short TTL,
// a bounded attempt budget, an optional SHA-256 proof of work, and may be bound
// to the client's short-term geolocation. Successful verification issues an
// HMAC-SHA256 token bound to the host action; ConsumeToken enforces one-time use
// through the same Store. Client signals and pointer tracks are risk inputs,
// never authorization decisions. | 预期答案、目标坐标与一次性验证码散列只留在服务端。
// 挑战在校验前原子消费，具有短 TTL、有界尝试次数、可选 SHA-256 工作量证明，并可绑定客户端
// 短期地理位置。验证成功后签发绑定宿主动作的 HMAC-SHA256 令牌；ConsumeToken 通过同一
// Store 强制一次性使用。客户端信号与指针轨迹只是风险输入，绝不是授权依据。
//
// The browser SDK deters screen capture by blocking getDisplayMedia, screenshot
// shortcuts, printing and copy gestures, and by reporting focus/visibility
// changes as Signals. Those signals are client-reported and forgeable; the OS
// screenshot itself cannot be prevented. | 浏览器 SDK 通过阻止 getDisplayMedia、截屏快捷键、
// 打印与复制手势，并把失焦/页面可见性变化上报为 Signals 来威慑录屏与截屏。这些信号由
// 客户端上报且可伪造；操作系统级截屏本身无法被阻止。
//
// Hosts may enable FallbackOptions to switch a detected capture attempt to an
// SMS or email code; the browser SDK mirrors that choice with its fallback
// option and renders a localized Notice element. SendCode returns the same
// notice in Challenge.Notice so server-rendered clients can display it. | 宿主可启用
// FallbackOptions，把检测到的录屏/截屏尝试降级为短信或邮箱验证码；浏览器 SDK 通过
// fallback 选项与之一致，并显示本地化提示条。SendCode 在 Challenge.Notice 中返回同一
// 提示，便于服务端渲染的客户端展示。
//
// # Internationalization | 国际化
//
// Built-in catalogs cover zh-CN, zh-TW, en, ja, ko, fr, de and es. Prompts,
// icon labels, category names and HTTP error messages follow the request body
// locale, then the lang query parameter, X-Lang header and Accept-Language.
// Options.DefaultLocale selects the fallback; Options.Messages extends or
// overrides catalogs; Options.Translate bridges an existing ydx/i18n bundle.
// The browser SDK reads the same captcha/core/langs files at build time and exposes
// setLocale plus YdCaptcha.locales. | 内置目录覆盖 zh-CN、zh-TW、en、ja、ko、fr、de、es。
// 提示、图标名称、分类名与 HTTP 错误文案依次跟随请求体 locale、lang 查询参数、X-Lang
// 头与 Accept-Language。Options.DefaultLocale 选择回退语言；Options.Messages 扩展或
// 覆盖目录；Options.Translate 可桥接既有 ydx/i18n Bundle。浏览器 SDK 构建时读取同一份
// captcha/core/langs 文件，并暴露 setLocale 与 YdCaptcha.locales。
//
// # YD usage | YD 用法
//
//	manager, _ := captcha.New(captcha.Options{Secret: []byte(os.Getenv("CAPTCHA_SECRET"))})
//	handler := manager.Handler(captcha.HandlerOptions{})
//	r := router.New()
//	handler.Bind(r)
//	r.POST("/login", login, manager.Protect("login"))
//
// # net/http usage | 原生 net/http 用法
//
//	mux := http.NewServeMux()
//	mux.Handle("/captcha/", manager.Handler(captcha.HandlerOptions{}))
//	mux.Handle("/login", manager.HTTPMiddleware("login")(http.HandlerFunc(login)))
//
// # SMS and email | 短信与邮件
//
// Plugins live under captcha/plugins; import the matching package, for example
// github.com/shibingli/ydx/captcha/plugins/aliyun. | 插件位于 captcha/plugins；
// 按通道导入对应包，例如 github.com/shibingli/ydx/captcha/plugins/aliyun。
//
//	aliyunSender, _ := aliyun.New(aliyun.Options{...})
//	manager, _ := captcha.New(captcha.Options{
//		Secret:               []byte(secret),
//		SMSDefaultCountryCode: "86",
//		Senders: map[captcha.Channel]captcha.Sender{
//			captcha.ChannelSMS: aliyunSender,
//		},
//	})
//
// # Multi-instance state | 多机状态
//
// Redis state lives in github.com/shibingli/ydx/captcha/store/redisstore. | Redis
// 多机状态位于 github.com/shibingli/ydx/captcha/store/redisstore。
//
//	client, _ := redis.Open(redis.Options{...})
//	store, _ := redisstore.NewStore(redisstore.StoreOptions{Client: client})
//	images, _ := redisstore.NewImageStore(redisstore.ImageStoreOptions{Client: client})
//	limiter, _ := redisstore.NewRateLimitStore(client, "")
//	policy, _ := redisstore.NewPolicyProvider(client, "")
//	manager, _ := captcha.New(captcha.Options{
//		Secret:         secret,
//		Store:          store,
//		ImageStore:     images,
//		PolicyProvider: policy,
//		Limits:         captcha.Limits{Store: limiter},
//	})
//
// The browser SDK and Node client live under sdk/browser and sdk/node. The Go
// module embeds the browser build at /captcha/assets/yd-captcha.js and
// /captcha/assets/yd-captcha.css. The SDK supports auto, light and dark themes,
// follows prefers-color-scheme in auto mode, and exposes setTheme for runtime
// switching. | 浏览器 SDK 与 Node 客户端位于 sdk/browser 与 sdk/node。Go 模块在
// /captcha/assets/yd-captcha.js 与 /captcha/assets/yd-captcha.css 嵌入浏览器构建
// 产物。SDK 支持 auto、light、dark 主题，auto 模式跟随 prefers-color-scheme，并暴露
// setTheme 供运行时切换。
package captcha
