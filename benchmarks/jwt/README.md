# benchmarks/jwt — JWT 签发与验签对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/jwt` 提供免反射的 JWS 签发、验签与声明校验，并可选 `Token.Release` 把令牌归还
池中以实现零分配验签。本基准比较它与 `golang-jwt/jwt/v5`、`lestrrat-go/jwx/v4`、
`go-jose/v4` 的 HS256/ES256 路径。

## 对比对象

| 实现 | 版本 | 说明 |
|---|---|---|
| ydx/jwt | 本仓源码（工作区） | 免反射，支持 `Release` 复用 |
| `github.com/golang-jwt/jwt/v5` | v5.3.1 | 最常用的 JWT 库 |
| `github.com/lestrrat-go/jwx/v4` | v4.5.0 | JWS/JWE/JWK 全家桶，默认校验声明 |
| `github.com/go-jose/go-jose/v4` | v4.1.6 | JOSE 实现，只验签，声明需调用方校验 |
| `github.com/cristalhq/jwt/v5` | v5.4.0 | 轻量 JWT，注册声明 + Builder/Verifier |
| `github.com/kataras/jwt` | v0.3.0 | Kataras JWT，自定义声明结构 |

## 场景

- `SignHS256`：登录期签发，6 项声明。
- `SignES256`：ECDSA P-256 签发。
- `SignHS256Compare` 的 `ydx-struct`：同一份声明改用类型化结构体签发（推荐热路径形态）。
- `ParseHS256` / `ParseES256`：在 **ydx 生成的同一份规范 token** 上验签并校验
  `alg` 白名单、`iss`、`aud`、`exp`，使所有解析器读取完全相同的字节。
- `ParseHS256Parallel`：并发 HS256 验签。
- `ParseHS256Reuse`（仅 ydx）：调用方 `Release` 归还令牌的零分配路径。
- `SignCristal` / `ParseCristal` / `ParseParallelCristal`：cristalhq/jwt 的 HS256/ES256
  同 token 对比（合并自 yd 基准）。
- `SignKataras` / `ParseKataras` / `ParseParallelKataras`：kataras/jwt 的同 token 对比。

## 关键结果（2026-10-24，Zen 5 + Go 1.27.3）

主对比（同一进程、同一 token 字节；ns/op 中位数）：

| 场景 | ydx | golang-jwt | jwx | go-jose |
|---|---:|---:|---:|---:|
| Sign HS256（map 声明） | **1.257 µs** | 2.544 µs | 2.237 µs | 2.961 µs |
| Sign HS256（`ydx-struct`） | **535.3 ns** | — | — | — |
| Sign ES256 | **19.81 µs** | 21.08 µs | 20.70 µs | 22.15 µs |
| Parse HS256 | **782.6 ns** | 3.170 µs | 4.726 µs | 5.846 µs |
| Parse ES256 | **41.13 µs** | 42.59 µs | 43.97 µs | 45.87 µs |
| 并发 Parse HS256 | **145.8 ns** | 1.117 µs | 1.973 µs | 3.279 µs |

轻量库对比（同一轮、同一 token 字节）：

| 场景 | ydx | cristalhq/jwt | kataras/jwt |
|---|---:|---:|---:|
| Sign HS256 | **535.3 ns**（struct）/ 1.257 µs（map） | 1.061 µs（struct） | 1.808 µs |
| Parse HS256 | **782.6 ns** | 1.995 µs | 2.271 µs |
| Parse ES256 | **41.13 µs** | 41.17 µs | 41.31 µs |
| 并发 Parse HS256 | **145.8 ns** | 493.8 ns | 743.7 ns |

- HS256：ydx 的类型化签发出 535.3 ns，比 cristalhq 的同形态（1.061 µs）快约 2 倍；
  map 声明路径 1.257 µs 仍快于 golang-jwt（2.544 µs）、jwx（2.237 µs）与 go-jose
  （2.961 µs）。cristalhq 的 1.061 µs 是结构体口径，与 ydx 的 map 口径不可直接横比。
- 验签：782.6 ns，比 golang-jwt 快约 4 倍、比 jwx 快约 6 倍；并发验签 145.8 ns。
- ES256：ECDSA 标量乘占主导，四个实现集中在 19.8–22.1 µs；ydx 签发与验签都略快，
  但差距只有 4%–10%，同一轮内接近噪声。
- 分配：ydx `Parse` 为 2 allocs/op、289 B/op；golang-jwt 49、jwx 75、go-jose 96。
  ydx 的 `Release` 复用路径把验签降到 0 allocs（见下）。
- ydx 内部复用基准（全量轮次）：`ParseHS256Reuse` 576.5 ns / 0 allocs、
  `ParseHS256ParallelReuse` 36.36 ns / 0 allocs；其它库没有等价的归还 API。

## 完整数据

<details>
<summary>5 轮中位数（Zen 5 + Go 1.27.3，2026-10-24）</summary>

**github.com/shibingli/ydx/benchmarks/jwt**

| Benchmark | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| `SignHS256` | 1.115 µs | 940 | 19 |
| `ParseHS256` | 734.0 ns | 289 | 2 |
| `ParseES256` | 41.03 µs | 1.383 KiB | 21 |
| `ParseHS256Parallel` | 145.0 ns | 290 | 2 |
| `ParseHS256Reuse` | 576.5 ns | 0 | 0 |
| `ParseHS256ParallelReuse` | 36.36 ns | 0 | 0 |
| `SignHS256Compare/ydx` | 1.257 µs | 939 | 19 |
| `SignHS256Compare/ydx-struct` | 535.3 ns | 481 | 4 |
| `SignHS256Compare/golang-jwt` | 2.544 µs | 2.188 KiB | 45 |
| `SignHS256Compare/jwx` | 2.237 µs | 1.845 KiB | 38 |
| `SignHS256Compare/go-jose` | 2.961 µs | 3.635 KiB | 61 |
| `SignES256Compare/ydx` | 19.811 µs | 7.258 KiB | 82 |
| `SignES256Compare/golang-jwt` | 21.077 µs | 8.156 KiB | 103 |
| `SignES256Compare/jwx` | 20.697 µs | 7.900 KiB | 98 |
| `SignES256Compare/go-jose` | 22.149 µs | 9.672 KiB | 123 |
| `ParseHS256Compare/ydx` | 782.6 ns | 289 | 2 |
| `ParseHS256Compare/golang-jwt` | 3.170 µs | 2.541 KiB | 49 |
| `ParseHS256Compare/jwx` | 4.726 µs | 3.734 KiB | 75 |
| `ParseHS256Compare/go-jose` | 5.846 µs | 6.755 KiB | 96 |
| `ParseES256Compare/ydx` | 41.128 µs | 1.384 KiB | 21 |
| `ParseES256Compare/golang-jwt` | 42.586 µs | 3.394 KiB | 65 |
| `ParseES256Compare/jwx` | 43.966 µs | 4.576 KiB | 90 |
| `ParseES256Compare/go-jose` | 45.866 µs | 7.611 KiB | 111 |
| `ParseHS256ParallelCompare/ydx` | 145.8 ns | 290 | 2 |
| `ParseHS256ParallelCompare/golang-jwt` | 1.117 µs | 2.584 KiB | 49 |
| `ParseHS256ParallelCompare/jwx` | 1.973 µs | 3.859 KiB | 75 |
| `ParseHS256ParallelCompare/go-jose` | 3.279 µs | 6.963 KiB | 96 |
| `SignCristal` | 1.061 µs | 1.059 KiB | 14 |
| `ParseCristal/HS256` | 1.995 µs | 1013 | 16 |
| `ParseCristal/ES256` | 41.172 µs | 2.367 KiB | 37 |
| `ParseParallelCristal` | 493.8 ns | 806 | 15 |
| `SignKataras` | 1.808 µs | 2.239 KiB | 25 |
| `ParseKataras/HS256` | 2.271 µs | 1.231 KiB | 19 |
| `ParseKataras/ES256` | 41.305 µs | 2.060 KiB | 34 |
| `ParseParallelKataras` | 743.7 ns | 1.279 KiB | 19 |
</details>

## 复现

```bash
cd benchmarks/jwt
GOWORK=off go test -run '^$' -bench . -benchmem -count=5 -benchtime=500ms
```

## 口径与限制

- 规范 token 的 `aud` 是字符串数组，`kid` 为 `k1`；所有解析器都接受该形式。
- `go-jose` 只验证签名；基准在计时区内补做一次 JSON 解码与 `iss`/`aud`/`exp` 校验，
  使其与其它库的声明校验等价。
- jwx v4 默认验证 `exp`/`nbf`/`iat`；基准不额外传 `WithValidate`。
- ydx 的 `Parse` 默认不复用存储，只有调用 `Release` 的路径才是零分配；对比表使用默认
  路径，因此与其它库的分配口径一致（都包含目标/令牌构造）。
- cristalhq 的签发基准使用其惯用的类型化 `RegisteredClaims`；为同口径比较，ydx 同时给出
  map 声明与 `ydx-struct` 两行，后者才是与 cristalhq 对齐的形态。
- ES256 的绝对数字受 ECDSA 标量乘与 CPU 影响很大；不要把 20–46 µs 当作跨机器常量。
- 主对比表与内部基准来自同一主机相邻两轮采样，同一指标跨轮差异约 2%，小于表内 5% 的
  噪声阈值。
- 同一轮内 5 个样本不足以给出 95% 置信区间；同一轮内小于约 5% 的差异视为噪声；
  跨轮次绝对数值可能因 CPU 频率/温度漂移。
