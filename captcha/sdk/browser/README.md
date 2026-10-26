# @ydx/captcha browser SDK | ydx 验证码浏览器 SDK

纯 JavaScript、零运行时依赖、无 CDN。Go 模块把构建产物嵌入为
`/captcha/assets/yd-captcha.js` 与 `/captcha/assets/yd-captcha.css`。

## 构建 | Build

```bash
cd captcha/sdk/browser
npm run build
```

构建脚本会把 `src/` 与 `captcha/core/langs/*.json` 的 `sdk.*` 文案合并后写入 `dist/`，
并同步到 `captcha/transport/assets/` 与 `captcha/pages/assets/`。Go 侧通过 `go:embed` 随模块发布同一份产物。

## 使用 | Usage

```html
<link rel="stylesheet" href="/captcha/assets/yd-captcha.css">
<div id="captcha"></div>
<script src="/captcha/assets/yd-captcha.js"></script>
<script>
  const widget = YdCaptcha.mount('#captcha', {
    endpoint: '/captcha',
    action: 'login',
    locale: 'zh-CN',
    onSuccess(token) {
      // 把 token 放进登录请求，服务端用 Manager.ConsumeToken 再次校验。 | Send the token with the login request.
    },
    onError(error) {
      console.warn(error.code, error.message);
    }
  });
</script>
```

短信/邮件：

```js
const widget = YdCaptcha.mount('#captcha', {
  endpoint: '/captcha',
  action: 'login',
  type: 'sms',
  target: '13800138000'
});
```

纯 JS 环境也可以直接使用 `YdCaptcha.solvePoW(challenge.pow)`；浏览器在
缺少 `crypto.subtle` 时使用内置 SHA-256 实现。

## 国际化与主题 | i18n and themes

内置 `zh-CN`、`zh-TW`、`en`、`ja`、`ko`、`fr`、`de`、`es` 文案；区域标签会按主语言
回退（`ja-JP` → `ja`，`zh-HK` → `zh-TW`）。服务端挑战提示使用同一份语言目录。

```js
const widget = YdCaptcha.mount('#captcha', {
  action: 'login',
  locale: navigator.language,
  theme: 'auto', // auto | light | dark；'system' 等价于 auto
  labels: { submit: '继续' }, // 可选：覆盖单条 UI 文案
  onThemeChange(theme) { document.documentElement.dataset.theme = theme; }
});

YdCaptcha.locales;        // ['de', 'en', ...]
YdCaptcha.labels('ja');   // 读取某语言全部文案
widget.setLocale('ja');   // 切换语言并重新拉取挑战
widget.setTheme('dark');  // 运行时切换主题
widget.resolvedTheme();   // auto 时返回实际 light/dark
```

`theme: 'auto'` 跟随系统 `prefers-color-scheme`，系统切换会即时生效；显式
`light`/`dark` 会覆盖系统。CSS 使用 `color-scheme` 与 CSS 变量，输入框、滚动条等
原生控件同步适配。示例 `pages/example/index.html` 演示语言与主题切换。

## 支持的类型 | Supported types

`text`、`click_text`、`click_icon`、`slide`、`scratch`、`semantic`、`rotate`，
以及 `sms`、`email` 验证码表单。服务端决定具体类型时不要传 `type`。

## 无障碍 | Accessibility

文本、旋转、短信与邮件类型可用键盘操作；点选类需要指针。请为高敏感流程提供
短信/邮件或文本降级入口。组件使用 `aria-live` 播报状态，样式支持明暗主题、
`prefers-color-scheme`、`prefers-reduced-motion`，并适配原生控件的 `color-scheme`。


跨域部署必须把前端 Origin 加入 Go 的 `AllowedOrigins`；刮刮卡/旋转等 Canvas 功能还要求图片响应带 CORS 头。

## 防录屏/截屏 | Capture deterrence

SDK 默认启用 `captureGuard`：检测 `getDisplayMedia`、截屏快捷键、打印、失焦和页面隐藏；
检测到后默认阻断当前组件。可配置：

```js
YdCaptcha.mount('#captcha', {
  action: 'login',
  captureGuard: true,
  captureAction: 'block',      // block | refresh | ignore
  blockDisplayCapture: true,
  onCapture(detail) { /* screen_capture | screenshot_key | print_attempt | focus_loss | page_hidden */ }
});
```

浏览器无法阻止操作系统级截屏/录屏或另一台设备拍摄；这些信号是可伪造的客户端提示，
服务端应结合 `Options.CaptureMode`、限流、PoW 与短时令牌使用，并保留文字/短信/邮件降级。

检测到录屏/截屏后可以自动降级为短信或邮箱验证，需要 Go 侧同时启用
`FallbackOptions{Enabled:true, Channel:...}` 并配置对应 `Sender`：

```js
YdCaptcha.mount('#captcha', {
  action: 'login',
  fallback: 'sms', // 'sms' | 'email'
  fallbackNotice: '检测到截屏，已切换为短信验证', // 字符串，或 function({channel, kind, locale})
  onFallback(detail) { /* {kind, channel, notice} */ }
});
```

降级后组件显示独立提示条 `.yd-captcha__notice`（`role="status"`），默认使用当前
语言的 `fallbackSMS`/`fallbackEmail`；`/send` 返回的服务端 `challenge.notice` 会覆盖
本地提示，确保前后端文案一致。`fallback` 优先于 `captureAction`；服务端未启用或
通道不匹配时 `/send` 返回 `fallback_disabled`。降级表单提供“返回图形验证”按钮，宿主也可以调用
`widget.fallbackTo('sms', 'screenshot_key')` 按用户偏好主动切换。

## 安全边界 | Security boundary

浏览器端的信号、轨迹和 PoW 都是提高自动化成本的输入，不是授权依据。答案、目标
坐标、一次性令牌均只在服务端校验。不要在客户端读取或持久化验证码令牌。
