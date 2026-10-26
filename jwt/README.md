# jwt — 免反射 JWT 签发、验签与中间件

`github.com/shibingli/ydx/jwt` 实现 JWT（RFC 7519）的签发、校验与 HTTP 中间件。校验路径
既不使用反射，也不构造声明 map：`Parse` 直接扫描被签名覆盖的载荷字节，因此 `exp` /
`nbf` / `iat` / `iss` / `aud` / `sub` 的判定落在签名所保护的原始字节上。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/jwt` |
| 包名 | `jwt` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |
| 默认 token 来源 | `header:Authorization:Bearer ` |

## 功能

- `Sign(claims, key, alg, SignOptions)`：签发 JWS。
- `SignJSON(payload, key, alg, SignOptions)`：直接对 JSON 载荷签名。
- `Parse(token, keyFn, ParseOptions)`：验签并校验声明。
- `Token.Release()`：把令牌归还内部池，实现零分配验签快路径。
- `Middleware`（YD 路由）与 `HTTPMiddleware`（原生 `net/http`）。
- `FromContext` / `FromRequest`：读取已验证令牌。
- `KeyFunc`：按 JOSE 头部选择密钥（支持 `kid` 轮换）。
- `ParseOptions`：`Issuer`、`Audience`、`ValidAlgs`、`Leeway`、`RequireExp`、`Now`。
- `Token.Claims`：`Subject`、`Issuer`、`Audience`、`ExpiresAt`、`NotBefore`、`IssuedAt`、
  `ID`、`Get`、`GetInt64`、`GetBool`、`GetFloat64`、`GetJSON`、`Has`、`Keys`、`Raw`。

## 特性

- **算法覆盖**：`HS256/384/512`、`RS256/384/512`、`PS256/384/512`、`ES256/384/512`、
  `EdDSA`（Ed25519）。
- **拒绝 `none`**：永不接受 `alg=none`。
- **封堵算法混淆**：密钥族不符一律以 `ErrSignatureInvalid` 拒绝。
- **免反射验签**：不把载荷解码成 `map[string]any`，不构造声明 map；数值/布尔访问器与
  `Has` 零分配。
- **签名字节优先**：声明校验直接读取签名覆盖的原始载荷字节。
- **零分配快路径**：`Parse` + `Release` 在高并发下可做到 0 allocs/op。
- **密钥轮换**：`KeyFunc` 接收完整 JOSE 头部，可按 `kid` 选择密钥。
- **时间容差**：`Leeway` 吸收时钟漂移；`Now` 便于确定性测试。

## 快速开始

```go
package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/shibingli/ydx/jwt"
)

type Claims struct {
	Sub string `json:"sub"`
	Iss string `json:"iss"`
	Exp int64  `json:"exp"`
}

func main() {
	key := []byte("test-key-do-not-use-in-production")
	claims := Claims{
		Sub: "user:42",
		Iss: "api",
		Exp: time.Now().Add(time.Hour).Unix(),
	}

	token, err := jwt.Sign(claims, key, jwt.HS256, jwt.SignOptions{Kid: "k1"})
	if err != nil {
		return
	}

	keyFn := func(h jwt.Header) (any, error) { return key, nil }
	tok, err := jwt.Parse(token, keyFn, jwt.ParseOptions{
		Issuer:     "api",
		ValidAlgs:  []jwt.Alg{jwt.HS256},
		RequireExp: true,
		Leeway:     30 * time.Second,
	})
	if err != nil {
		if errors.Is(err, jwt.ErrSignatureInvalid) {
			fmt.Println("bad signature")
		}
		return
	}
	defer tok.Release()

	exp, _ := tok.Claims.ExpiresAt()
	fmt.Println(tok.Claims.Subject(), exp)
}
```

### YD 路由中间件

```go
r.Use(jwt.Middleware(jwt.MiddlewareOptions{
	KeyFunc:      keyFn,
	ParseOptions: jwt.ParseOptions{ValidAlgs: []jwt.Alg{jwt.HS256}, RequireExp: true},
}))
```

### 原生 net/http

```go
handler := jwt.HTTPMiddleware(jwt.HTTPMiddlewareOptions{
	KeyFunc:      keyFn,
	ParseOptions: jwt.ParseOptions{ValidAlgs: []jwt.Alg{jwt.HS256}, RequireExp: true},
})(mux)
```

## 应用场景

- **登录态**：签发短时访问令牌与刷新令牌。
- **API 鉴权**：微服务之间传递用户/租户身份。
- **密钥轮换**：按 `kid` 选择多把密钥。
- **多算法部署**：HMAC、RSA、ECDSA、Ed25519 统一 API。
- **高并发网关**：`Release` 快路径降低验签分配。

## 性能指标

基准模块：[`benchmarks/jwt`](../benchmarks/jwt/README.md)。参考环境为 AMD Ryzen
AI MAX+ 395、Go 1.27.3、Linux，`-count=5`、`-benchtime=500ms` 中位数，所有解析器读取
同一份规范 token。

| 场景 | ydx/jwt | golang-jwt | jwx | go-jose |
|---|---:|---:|---:|---:|
| Sign HS256（map 声明） | **1.257 µs** | 2.544 µs | 2.237 µs | 2.961 µs |
| Sign HS256（类型化结构体） | **535.3 ns** | — | — | — |
| Sign ES256 | **19.81 µs** | 21.08 µs | 20.70 µs | 22.15 µs |
| Parse HS256 | **782.6 ns** | 3.170 µs | 4.726 µs | 5.846 µs |
| Parse ES256 | **41.13 µs** | 42.59 µs | 43.97 µs | 45.87 µs |
| 并发 Parse HS256 | **145.8 ns** | 1.117 µs | 1.973 µs | 3.279 µs |

- HS256 类型化签发出 535.3 ns，比 cristalhq 的同形态（1.061 µs）快约 2 倍。
- 验签比 golang-jwt 快约 4 倍、比 jwx 快约 6 倍；并发验签 145.8 ns。
- `Parse` 默认 2 allocs/op、289 B/op；`Release` 复用路径为 0 allocs：
  `ParseHS256Reuse` 576.5 ns、`ParseHS256ParallelReuse` 36.36 ns。
- ES256 由 ECDSA 标量乘主导，四个实现集中在 19.8–22.1 µs，差距接近噪声。

> 完整表格、轻量库对比与口径见基准 README；ES256 绝对值受 CPU 影响很大，不应外推。

## 第三方依赖与鸣谢

本模块没有第三方运行时依赖，只依赖 Go 标准库与 ydx 内部模块（`base64`、`errs`、
`json`、`router`）。

基准对比对象：[`golang-jwt/jwt`](https://github.com/golang-jwt/jwt)、
[`lestrrat-go/jwx`](https://github.com/lestrrat-go/jwx)、
[`go-jose/go-jose`](https://github.com/go-jose/go-jose)、
[`cristalhq/jwt`](https://github.com/cristalhq/jwt) 与
[`kataras/jwt`](https://github.com/kataras/jwt)，仅出现在 `benchmarks/jwt`。

## 相关模块

- [`router`](../router/README.md)：YD 路由中间件。
- [`middleware`](../middleware/README.md)：中间件组合。
- [`base64`](../base64/README.md)：JWS 的 Base64URL 编解码。
- [`json`](../json/README.md)：声明载荷序列化。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
