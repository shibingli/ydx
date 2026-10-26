# captcha — 多类型人机验证与风险控制

`github.com/shibingli/ydx/captcha` 是 ydx 的独立验证码模块，同时服务 YD 路由与原生
`net/http`，并附带独立打包的浏览器 JS SDK、Node SDK、短信/邮件插件与多机 Redis 存储。

设计目标不是“多画几种图片验证码”，而是把验证码放进一条可运营的防线：

```text
客户端信号 + 行为轨迹
        │
        ▼
动态黑白名单 ──► 令牌桶限流 ──► 短期地理绑定 ──► 风险评分
                                                    │
                                    ┌───────────────┴───────────────┐
                                    ▼                               ▼
                              低风险：直接出题                 高风险：升级题型 / PoW
                                    │                               │
                                    └───────────────┬───────────────┘
                                                    ▼
                                     服务端一次性挑战 + 答案校验
                                                    │
                                                    ▼
                                   HMAC 令牌（绑定 action、短 TTL、可一次性消费）
                                                    │
                                                    ▼
                                     JSON 审计事件回写宿主平台
```

## 1. 方案调研结论

主流方案已经形成三类能力，单独使用都有明显边界：

| 方案 | 代表 | 优点 | 主要问题 |
|---|---|---|---|
| 托管风险评分/无感验证 | reCAPTCHA v3、Cloudflare Turnstile | 无感、部署快、持续更新 | 依赖第三方、隐私与跨境合规、误杀不可控、Token 需服务端二次校验 |
| 行为/图形题 | GeeTest、hCaptcha、tianai-captcha、GoCaptcha | 自托管、题型丰富、可解释 | 视觉模型与打码平台可批量破解，必须配合轨迹、限流与短时 Token |
| 工作量证明/隐私优先 | ALTCHA、mCaptcha、Cap | 无第三方、可无障碍、成本可调 | PoW 只能抬高成本，不能证明“人”；需要服务端签发与一次性消费 |

参考方案与行业观察：

- Zyte《State of Web Access 2026》CAPTCHA 章节：<https://dev.zyte.com/sowa/2026/barriers/captcha/>
- GeeTest CAPTCHA Options 2026：<https://www.geetest.com/en/article/captcha-options>
- ALTCHA 开源 PoW 方案：<https://altcha.org/open-source-captcha/>
- tianai-captcha 行为验证码：<https://atomgit.com/dromara/tianai-captcha/tree/master>
- Castle 风险分级挑战指南：<https://docs.castle.io/docs/challenging-users.md>
- Arcjet：CAPTCHA 是否仍然有效：<https://arcjet.com/learn/captcha-alternatives>

因此本模块采用组合策略：

- 服务端生成题目与答案，前端永远拿不到目标坐标或一次性验证码明文。
- 题目按风险自适应升级：文本 → 点选/滑动 → 高风险追加 PoW。
- 挑战 ID、图片 Key、验证码、PoW 种子全部使用密码学随机。
- 答案先原子取出再校验，失败重存并消耗尝试次数；成功即销毁图片。
- Token 使用 HMAC-SHA256 绑定 `action`，默认通过共享 Store 一次性消费。
- 限流、名单、地理、行为、审计都是可注入的，不把“验证码”当唯一防线。

## 2. 验证码类型

| Type | 说明 | 主要校验 |
|---|---|---|
| `text` | 中英文/数字混合扭曲文本 | 不区分大小写文本 + 轨迹 |
| `click_text` | 按顺序点击图片中的汉字/字母 | 点击顺序、命中半径、轨迹 |
| `click_icon` | 按顺序点击图标 | 图标顺序、命中半径、轨迹 |
| `semantic` | “点击所有水果/动物/交通工具” | 目标集合相等、轨迹 |
| `slide` | 双轴滑动拼图 | 拼图块目标 X/Y、轨迹 |
| `scratch` | 刮开涂层后输入字符 | 刮擦轨迹时长/采样、文本 |
| `rotate` | 旋转图片到正向 | 校正角误差、滑块轨迹 |
| `sms` / `email` | 一次性验证码 | 服务端散列、目标限流、冷却、尝试次数 |

`Provider` 接口允许宿主注册自定义视觉类型：

```go
type Provider interface {
    Type() Type
    Generate(ctx context.Context, req GenerateRequest) (*Generated, error)
    Verify(ctx context.Context, rec *Record, ans Answer) (CheckResult, error)
}
```

在 `Options.Providers` 中传入自定义生成器即可在启动期注册并自动启用其类型；也可以
启动后调用 `Manager.RegisterProvider` 覆盖同类型实现。若手动调用 `RegisterProvider`，
自定义类型还要加入 `Options.Types`（例如 `Types: []captcha.Type{captcha.TypeText, "my_type"}`），
否则 `Create` 会按未启用类型拒绝。

## 3. 目录结构

```
captcha/
  captcha.go        # 兼容门面：既有 import 与 Manager API 保持不变
  core/             # 类型、Options、Store、Token/Record、消息目录、策略/地理基础
  challenge/        # 文本/点选/滑动/刮刮卡/旋转生成器、渲染、字体与图标
  risk/             # 行为轨迹评分（风控编排位于 service/assessment.go）
  service/          # Manager 生命周期、Create/Verify/SendCode、Token、PoW
  transport/        # 原生 net/http、YD Bind、Protect、响应与嵌入资源
  plugins/          # aliyun/ smtp/ tencent/ webhook/
  store/redisstore/ # 多机 Redis 状态
  sdk/              # browser/ 与 node/
  pages/            # 示例页与示例静态资源
  core/langs/       # 前后端共用的语言目录
```

根包 `github.com/shibingli/ydx/captcha` 继续导出 `New`、`Options`、`Manager`、
`Provider` 等旧符号；插件与多机存储按新路径导入：
`github.com/shibingli/ydx/captcha/plugins/aliyun`、
`github.com/shibingli/ydx/captcha/store/redisstore`。

## 4. 快速开始

```bash
go get github.com/shibingli/ydx/captcha@v0.1.0
```

最小可用配置（单机内存状态）：

```go
manager, err := captcha.New(captcha.Options{
    Secret: []byte(os.Getenv("CAPTCHA_SECRET")), // 至少 16 字节；多机必须固定
})
if err != nil {
    return err
}
defer manager.Close()

handler := manager.Handler(captcha.HandlerOptions{})
```

### YD 路由

```go
r := router.New()
handler.Bind(r)                       // /captcha/challenge、/verify、/send、/assets、/image
r.POST("/login", login, manager.Protect("login"))
```

### 原生 net/http

```go
mux := http.NewServeMux()
mux.Handle("/captcha/", manager.Handler(captcha.HandlerOptions{}))
mux.Handle("/login", manager.HTTPMiddleware("login")(http.HandlerFunc(login)))
```

### 国际化（后端）

内置 `zh-CN`、`zh-TW`、`en`、`ja`、`ko`、`fr`、`de`、`es` 八种语言，提示语、点选
图标名称、分类名与 HTTP 错误文案都会跟随请求语言。语言来源优先级为请求体
`locale` > 查询参数 `lang` > `X-Lang` > `Accept-Language`，响应携带
`Content-Language`。默认语言由 `Options.DefaultLocale` 控制（默认 `zh-CN`）。

```go
manager, _ := captcha.New(captcha.Options{
    Secret:        secret,
    DefaultLocale: "en",
    Messages: map[string]map[string]string{
        "it": {
            "prompt.text": "Digita i caratteri nell'immagine",
            "hint.text":   "Maiuscole e minuscole non contano",
        },
    },
})
```

`Options.Messages` 可覆盖内置文案或新增语言；键名、图标名与错误码见
`core/langs/*.json`。已有 `ydx/i18n` 目录的宿主可通过 `Options.Translate`
桥接，返回空字符串或键名即回退内置目录：

```go
bundle, _ := i18n.New(afs.NewOS("configs/langs"), ".", "zh-CN")
manager, _ := captcha.New(captcha.Options{
    Translate: func(locale, key string, args ...string) string {
        values := make([]any, len(args))
        for i, arg := range args { values[i] = arg }
        return bundle.Translator(locale).T(key, values...)
    },
})
```

### 浏览器 SDK

```html
<link rel="stylesheet" href="/captcha/assets/yd-captcha.css">
<div id="captcha"></div>
<script src="/captcha/assets/yd-captcha.js"></script>
<script>
  YdCaptcha.mount('#captcha', {
    endpoint: '/captcha',
    action: 'login',
    locale: 'zh-CN',
    onSuccess(token) { login({ captchaToken: token }); }
  });
</script>
```

浏览器 SDK 支持全部视觉类型与短信/邮件表单，自动求解服务端下发的 PoW，采集指针
轨迹、Canvas/WebGL 指纹与浏览器信号。源码在 `sdk/browser/src`，`npm run build`
会把同一份产物同步到 `dist/`、`transport/assets/` 与 `pages/assets/`，Go 端通过 `go:embed` 随模块发布。

前端语言与主题可以运行时切换：

```js
const widget = YdCaptcha.mount('#captcha', {
  endpoint: '/captcha',
  action: 'login',
  locale: navigator.language,   // 也接受 ja-JP、zh-HK 等区域标签
  theme: 'auto',                 // auto | light | dark
  onThemeChange(theme) { console.log('resolved theme:', theme); }
});
YdCaptcha.locales;              // 内置语言列表
YdCaptcha.labels('ja');         // 读取某语言的 UI 文案
widget.setLocale('ja');         // 切换语言并重新拉取挑战
widget.setTheme('dark');        // 即时切换主题
widget.resolvedTheme();         // auto 时返回实际 light/dark
widget.options.labels = { submit: 'Go' }; // 也可用 labels 选项覆盖单条文案
```

`theme: 'auto'` 跟随 `prefers-color-scheme`，页面系统主题变化会即时生效；
`light`/`dark` 显式锁定。CSS 同时设置 `color-scheme`，使输入框、滚动条等原生控件
与暗色主题一致。内置语言目录位于 `core/langs/*.json`；构建脚本把 `sdk.*`
文案注入 `dist/`，后端用同一份文件生成提示与错误文案，避免两端漂移。示例页
`pages/example/index.html` 提供语言与明暗主题切换。

### Node SDK

```js
import { createClient } from '@ydx/captcha-node';

const client = createClient({
  endpoint: 'https://app.example.com/captcha',
  locale: 'ja-JP',                  // 也可在单次调用中覆盖
  secret: process.env.CAPTCHA_SECRET
});
const challenge = await client.challenge({ action: 'login' });
const claims = await client.consume({ token, action: 'login' });
```

Node SDK 提供 `challenge`、`verify`、`send`、`consume`、本地 `verifyToken` 与
`solvePoW`，零运行时依赖，适用于 Node 18+。

## 5. 多机部署与状态同步

核心模块默认使用分片内存存储，适合单机；多机部署必须让所有实例共享以下状态：

| 状态 | 单机默认 | 多机组件 |
|---|---|---|
| 挑战记录、一次性 Token 标记、冷却 | `MemoryStore` | `redisstore.NewStore`（`captcha/store/redisstore`） |
| 题目图片 | `MemoryImageStore` | `redisstore.NewImageStore` |
| 限流桶 | `ratelimit.MemoryStore` | `redisstore.NewRateLimitStore` |
| 动态策略 | `SetPolicy` | `redisstore.PolicyProvider` 或 `PolicyBus` |

```go
// import "github.com/shibingli/ydx/captcha/store/redisstore"
client, err := redis.Open(redis.Options{ /* ... */ })
store, err := redisstore.NewStore(redisstore.StoreOptions{Client: client})
images, err := redisstore.NewImageStore(redisstore.ImageStoreOptions{Client: client})
limiter, err := redisstore.NewRateLimitStore(client, "")
policy, err := redisstore.NewPolicyProvider(client, "")

manager, err := captcha.New(captcha.Options{
    Secret:         secret,
    Store:          store,
    ImageStore:     images,
    PolicyProvider: policy,
    Limits:         captcha.Limits{Store: limiter, FailClosed: true},
})
```

`PolicyBus` 通过 Redis Pub/Sub 立即广播策略变更，并先把快照写入
`DefaultPolicyKey`，避免 `PolicyProvider` 刷新时用旧值覆盖新策略：

```go
bus, _ := redisstore.NewPolicyBus(client, "")
go func() { _ = bus.Watch(ctx, manager) }()
_ = bus.Publish(ctx, &captcha.Policy{Deny: []captcha.Rule{{IP: "203.0.113.0/24"}}})
```

自定义 `NewPolicyProvider` 键时，用 `NewPolicyBusWithKey(client, "", policyKey)`
传入同一个键。

关键点：

- `Take` 在 Redis 中由 Lua 脚本原子执行，同一挑战只有一个实例能成功消费。
- 一次性 Token 标记与挑战记录使用同一个共享 Store，跨实例有效。
- 限流使用 `ydx/middleware/ratelimit` 的 Redis Lua 令牌桶，跨实例精确。
- 图片 Key 是随机不可枚举值，图片本身也走共享 ImageStore。
- `Options.KeyPrefix` 用于隔离共享 Redis 中的不同应用。
- 轮换 Token 密钥时用 `Options.Keys` + `Options.KeyID`；目标/冷却/验证码摘要使用稳定的
  `Options.DigestKey`（未配置时从 `Secret` 或完整密钥集派生），因此旧密钥仍保留时在途
  验证码与冷却不会失效。
- `PolicyProvider` 首次加载失败（包括 Redis 策略键不存在）会使 `New` 返回错误（失败关闭）；
  首次部署先用 `PolicyBus.Publish` 或 `StorePolicy` 写入 `{}`；运行期刷新失败保留上一版策略并记录告警。
- `PolicyBus.Publish` 先持久化再广播；只广播不落盘的旧行为已移除。

## 6. 短信与邮件插件

统一接口：

```go
type Sender interface {
    Channel() Channel
    Send(ctx context.Context, msg Message) error
}
```

内置插件：

- `captcha/plugins/smtp`：自研 SMTP，支持隐式 TLS、STARTTLS、明文显式开关与超时。
- `captcha/plugins/webhook`：HMAC-SHA256 签名的通用云短信网关。
- `captcha/plugins/aliyun`：阿里云 Dysmsapi `SendSms` RPC 签名。
- `captcha/plugins/tencent`：腾讯云 SMS TC3-HMAC-SHA256。

```go
// import "github.com/shibingli/ydx/captcha/plugins/aliyun"
sms, err := aliyun.New(aliyun.Options{
    AccessKeyID:     os.Getenv("ALIYUN_ACCESS_KEY_ID"),
    AccessKeySecret: os.Getenv("ALIYUN_ACCESS_KEY_SECRET"),
    SignName:        "你的签名",
    TemplateCode:    "SMS_000000",
})
manager, err := captcha.New(captcha.Options{
    Secret: secret,
    Senders: map[captcha.Channel]captcha.Sender{captcha.ChannelSMS: sms},
})
```

`SendCode` 负责目标规范化、按目标和 IP 双桶限流、重发冷却、6 位密码学验证码、
HMAC 散列存储、发送失败回滚与审计；插件只负责投递。手机号会统一规范为 E.164：
`13800138000`、`+86 138-0013-8000`、`0086138000138000` 会映射到同一目标，国内号码
默认补 `86`，可用 `Options.SMSDefaultCountryCode` 修改默认国家码。冷却预占用
`Store.PutIfAbsent` 原子完成，发送失败时通过 `Store.DeleteIf` 仅释放本次预占，
不会覆盖并发请求；自定义 Store 必须实现这三个原子方法。

云厂商与 webhook 插件默认强制 HTTPS 并拒绝重定向；本地联调可显式设置
`AllowInsecureHTTP: true`，不要在生产开启。

## 7. 风险层

### 动态黑白名单

`Policy` 支持 IP/CIDR、国家、action、type 组合规则。拒绝规则优先于允许规则；
允许规则跳过风险检查（仍做答案校验）。策略可调用 `Manager.SetPolicy` 热更新，
也可通过 `PolicyProvider` 定时从 Redis/DB 加载，或用 `PolicyBus` 立即广播。

```go
_ = manager.SetPolicy(&captcha.Policy{
    Deny: []captcha.Rule{
        {IP: "198.51.100.0/24"},
        {Country: "CN", Action: "withdraw"},
    },
    Allow: []captcha.Rule{
        {IP: "10.0.0.0/8", Action: "internal_login"},
    },
})
```

国家规则要求配置 `GeoResolver`；未配置时启动或 `SetPolicy` 会拒绝策略，避免
“看起来有国别封禁、实际永不生效”。

### 智能限流

`Options.Limits` 分别限制创建、验证、发送与按目标发送；默认值：

- 创建：2 token/s，突发 20；
- 验证：5 token/s，突发 40；
- 发送：0.02 token/s，突发 3；
- 按目标发送：约 3 次/15 分钟；
- 验证码重发冷却 60 秒。

限流存储故障默认失败开放并记录风险原因；设置 `FailClosed: true` 可改为失败关闭。

### 短期地理校验

`GeoResolver` 把 IP 映射到 `Geo{Country, Region, City, Latitude, Longitude}`。
`GeoBind` 开启后，验证时要求：

- 国家一致；
- 若双方都有坐标，位移不超过 `max(GeoMaxDistanceKM, GeoMaxSpeedKMH × elapsed)`。

```go
manager, _ := captcha.New(captcha.Options{
    GeoResolver:      myGeoResolver, // 可接 CDN 头、MaxMind、自建 IP 库
    GeoBind:          true,
    GeoTTL:           2 * time.Minute,
    GeoMaxDistanceKM: 100,
    GeoMaxSpeedKMH:   900,
})
```

`captcha.NewCIDRGeoResolver` 适合内网、办公出口与测试；公网库由宿主注入。

### 行为与机器人信号

`scoreSignals` 对 `navigator.webdriver`、无头 UA、UA 不一致、移动端无触摸、缺失
屏幕/时区/平台、隐藏页面等加分；`scoreTrack` 对轨迹过短、静止、过快、时间倒序、
采样不足等加分。分数与风险阈值组合使用：

- `PoW.Mode=adaptive`：分数 ≥ `PoW.Threshold` 时追加 PoW；
- `RiskRejectScore`：达到该分数时，即使答案正确也拒绝；
- 风险升高时题型自动升级（文本 → 点选/滑动）。

## 8. 防录屏与截屏

浏览器无法阻止操作系统级截屏、屏幕录制或另一台设备拍摄；本模块提供的是
**检测、阻断当前交互、失效当前挑战、风险评分与审计**，不是绝对防复制。
部分系统级快捷键可能不会传给浏览器，检测结果不能视为可靠证据。

### 浏览器端

检测默认开启：

- 包装 `navigator.mediaDevices.getDisplayMedia`：检测到页面尝试屏幕捕获时直接阻止
  （`blockDisplayCapture: false` 可改为只上报）。
- 监听 `PrintScreen`、`Cmd/Ctrl+Shift+3/4/5`、`Ctrl+Shift+S`、`beforeprint`。
- 监听窗口失焦次数、页面隐藏；禁止右键菜单、复制、剪切、拖拽与选择。
- 打印样式直接隐藏验证码组件。
- 检测后默认阻断当前组件；`captureAction: 'refresh'` 会自动换题，
  `'ignore'` 只上报。

```js
YdCaptcha.mount('#captcha', {
  endpoint: '/captcha',
  action: 'login',
  captureGuard: true,          // 默认 true
  captureAction: 'block',      // block | refresh | ignore
  blockDisplayCapture: true,   // 默认 true
  onCapture(detail) {
    // detail.kind: screen_capture | screenshot_key | print_attempt | focus_loss | page_hidden
    navigator.sendBeacon('/audit/capture', JSON.stringify(detail));
  }
});
```

### 检测后降级为手机号或邮箱验证

开发者可以显式开启降级，并指定唯一允许的通道；前后端都必须配置，服务端还会校验
发送器是否存在：

```go
sms, _ := aliyun.New(aliyun.Options{ /* ... */ })
manager, _ := captcha.New(captcha.Options{
    Secret: secret,
    Senders: map[captcha.Channel]captcha.Sender{captcha.ChannelSMS: sms},
    Fallback: captcha.FallbackOptions{
        Enabled: true,
        Channel: captcha.ChannelSMS, // 或 captcha.ChannelEmail
    },
})
```

```js
YdCaptcha.mount('#captcha', {
  endpoint: '/captcha',
  action: 'login',
  fallback: 'sms', // 'sms' | 'email'；不设置则按 captureAction 处理
  onFallback(detail) {
    // detail = {kind:'screen_capture', channel:'sms'}
  }
});
```

检测到录屏/截屏/打印时，SDK 立即切换到对应通道的验证码表单；用户填写手机号或邮箱
并点击发送。`/send` 请求携带 `fallback: true` 与 `capture_kind`，服务端在降级请求中
不把同一个录屏信号当作拒绝理由，但会保留 `capture_fallback` 与触发原因到审计事件。
未启用或通道不匹配时返回 403 `fallback_disabled`；启用降级但未配置对应发送器会在
`New` 时直接拒绝启动。

宿主也可以根据最终用户偏好动态决定：只在用户同意时传入 `fallback`，或调用
`widget.fallbackTo('sms', 'screenshot_key')` 主动切换。降级只是替代验证方式，
不能证明客户端真的检测到了录屏；请继续使用限流、冷却、一次性令牌和 PoW。

### 服务端

`Signals` 增加 `screen_capture`、`screenshot_key`、`print_attempt`、`page_hidden`
与 `focus_loss`。`Options.CaptureMode`：

| 取值 | 行为 |
|---|---|
| `off` | 忽略这些信号 |
| `risk`（默认） | 计入风险分：屏幕捕获 +100、打印 +80、截屏快捷键 +60、页面隐藏 +20、每次失焦 +5（最多 5 次） |
| `reject` | 出现 `screen_capture`/`screenshot_key`/`print_attempt` 时直接返回 403 `capture_detected` |

```go
manager, _ := captcha.New(captcha.Options{
    Secret:      secret,
    CaptureMode: captcha.CaptureReject, // 高安全流程可显式拒绝
})
```

浏览器信号由客户端上报，能被定制客户端伪造；它只能提高自动化成本。真正的高安全
场景应叠加短 TTL、一次性令牌、PoW、限流、地理绑定与设备/账号风控，并保留短信/邮件
或人工复核降级路径。

## 9. 审计 JSON

`Options.Audit` 接收结构化事件；`NewJSONAuditSink(io.Writer)` 按行写 JSON，便于
接入日志平台或宿主的审计表。

```go
audit, _ := os.OpenFile("captcha-audit.jsonl", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
manager, _ := captcha.New(captcha.Options{
    Secret: secret,
    Audit:  captcha.NewJSONAuditSink(audit),
})
```

字段包括 `ts`、`request_id`、`challenge_id`、`action`、`type`、`outcome`、`ip`、
`country`、脱敏后的 `target`、`risk`、`reasons`、`duration_ms`、`error_code`。
不会写入验证码、Token、原始邮箱/手机号、原始 UA 或完整请求体。

## 10. HTTP API

默认挂载 `/captcha`：

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/challenge` | `{type?, action, locale, signals}` → 视觉挑战 |
| POST | `/verify` | `{id, answer, signals, pow?}` → `{token, expires_in, action}` |
| POST | `/send` | `{channel, target, action, locale, signals}` → 短信/邮件挑战 |
| POST | `/token/consume` | `{token, action}` → 一次性消费并返回 claims |
| GET | `/image/{key}` | 短期挑战图片 |
| GET | `/assets/yd-captcha.js` | 嵌入式浏览器 SDK |
| GET | `/assets/yd-captcha.css` | 嵌入式样式 |

所有 JSON 响应携带 `Cache-Control: no-store` 与 `X-Content-Type-Options: nosniff`；
错误响应包含稳定 `code`、双语 `message` 与可选 `retry_after`。请求体默认上限
64 KiB（硬上限 1 MiB），所有 JSON 解析走 `ydx/json`。

Token 请求头默认 `X-Captcha-Token`，也接受 `Authorization: Bearer <token>`。
`Manager.Protect` 默认消费一次；若同一请求会被多个处理器检查，使用
`ProtectWith(action, ProtectOptions{Reusable: true})`。

## 11. 无障碍与降级

- 文本、旋转、短信、邮件类型可键盘操作；点选类需要指针。
- 组件使用 `aria-live` 播报状态，支持 `prefers-reduced-motion` 与深色模式。
- 高敏感流程应同时提供短信/邮件或文本验证入口；不要把单一图片题作为唯一防线。
- 对隐私敏感地区，可禁用 Canvas/WebGL 指纹，只保留行为与 PoW；服务端信号始终
  只作为风险输入。

## 12. 已知边界

- 视觉题目无法阻止有动机的攻击者使用视觉模型或人工打码；本模块通过短 TTL、
  一次性消费、行为、限流、地理、PoW 与审计抬高成本，而不是承诺“不可破解”。
- PoW 只能抬高自动化成本，不能证明操作者是人。
- 浏览器信号可伪造；不要把它们当作授权依据。
- 邮箱本地部分按大小写不敏感归一化，以稳定冷却与 Token 绑定；如需严格区分，
  可在 `Sender` 插件层保留原始地址。
- 手机号会规范化为 E.164 后再用于限流、冷却、审计脱敏和投递；未带 `+`/`00` 的号码按
  `SMSDefaultCountryCode` 解释，默认 `86`。跨境业务应显式配置正确的默认国家码。
- 默认内存存储不跨进程；多机必须按第 4 节接入 Redis 组件。
- 刮刮卡的文本位于“底层图片”，有能力的客户端仍可读取像素；安全性主要来自交互
  轨迹、行为评分、限流与一次性校验。不要把刮刮卡作为高价值流程的唯一防线，建议配合
  PoW、短信/邮件降级或人工复核。
- 配置国家规则后，`GeoResolver` 故障会按失败关闭处理（拒绝请求），避免未知地区绕过
  国家拒绝规则；对可用性敏感的部署应使用本地 MMDB/CIDR 解析器并做好健康检查。
- 防录屏/截屏只能检测客户端可观察的信号；操作系统级截屏、另一台设备拍摄和定制客户端
  绕过都无法被彻底阻止。高安全流程必须叠加限流、PoW、短时令牌、地理/设备绑定与人工复核。

## 13. 验证

```bash
cd captcha
GOWORK=off go build ./...
GOWORK=off go vet ./...
GOWORK=off CGO_ENABLED=1 CC=clang go test ./... -race

cd sdk/browser && npm test
cd sdk/node && npm test
```

仓库守卫：

```bash
cd repotest && GOWORK=off go test ./...
```

## 许可证

Apache-2.0。`challenge/fontdata/OFL.txt` 是 Noto Sans CJK SC 字形位图来源的 SIL Open Font
License 1.1 许可证文本。
