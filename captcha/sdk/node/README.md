# @ydx/captcha-node

零依赖 Node.js 18+ 客户端，用于服务端调用 ydx captcha HTTP API、求解 PoW，
以及在 Node 侧校验 HMAC 验证令牌。

```js
import { createClient } from '@ydx/captcha-node';

const captcha = createClient({
  endpoint: 'https://app.example.com/captcha',
  locale: 'ja-JP', // 可选默认语言；单次调用可覆盖 | optional default locale
  timeout: 15000,
  secret: process.env.CAPTCHA_SECRET // 与 Go Options.Secret 相同 | same as Go
});

const challenge = await captcha.challenge({
  action: 'login'
});
// 返回给浏览器渲染；不要在服务端日志记录 challenge 图片之外的敏感状态。 | Return to the browser.
```

校验一次性令牌：

```js
const claims = await captcha.consume({ token, action: 'login' });
// 或仅本地验签，不消费： | Or verify locally without consuming:
const claims = captcha.verifyToken(token, 'login');
```

`consume` 会调用 Go 服务端的一次性标记存储，适合多机部署；`verifyToken` 只做
无状态 HMAC 校验，重复调用不会失败，适用于本身已有幂等控制的动作。

PoW：

```js
import { solvePoW } from '@ydx/captcha-node';
const proof = await solvePoW(challenge.pow);
await captcha.verify({ id: challenge.id, pow: proof, answer: { text: 'AB12' } });
```

## 安全 | Security

- 不要把 `CAPTCHA_SECRET`、完整手机号/邮箱或验证码写入日志。
- 令牌与 action 绑定且默认一次性；跨机部署必须使用共享 Store。
- 所有错误都映射为 `CaptchaError`，其中 `code` 是稳定的公开错误码。
