# benchmarks/jwt — JWT 签发与验签对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/jwt` 提供免反射的 JWS 签发、验签与声明校验，并可选 `Token.Release` 把令牌归还
池中以实现零分配验签。本基准比较它与 `golang-jwt/jwt/v5`、`lestrrat-go/jwx/v4`、
`go-jose/v4` 的 HS256/ES256 路径。

## 对比对象

| 实现 | 版本 | 说明 |
|---|---|---|
| ydx/jwt | v0.1.6 | 免反射，支持 `Release` 复用 |
| `github.com/golang-jwt/jwt/v5` | v5.3.1 | 最常用的 JWT 库 |
| `github.com/lestrrat-go/jwx/v4` | v4.5.0 | JWS/JWE/JWK 全家桶，默认校验声明 |
| `github.com/go-jose/go-jose/v4` | v4.1.6 | JOSE 实现，只验签，声明需调用方校验 |

## 场景

- `SignHS256`：登录期签发，6 项声明。
- `SignES256`：ECDSA P-256 签发。
- `ParseHS256` / `ParseES256`：在 **ydx 生成的同一份规范 token** 上验签并校验
  `alg` 白名单、`iss`、`aud`、`exp`，使所有解析器读取完全相同的字节。
- `ParseHS256Parallel`：并发 HS256 验签。
- `ParseHS256Reuse`（仅 ydx）：调用方 `Release` 归还令牌的零分配路径。

## 关键结果

| 场景 | ydx | golang-jwt | jwx | go-jose |
|---|---:|---:|---:|---:|
| Sign HS256 | 3.558 µs | 6.865 µs | 12.28 µs | 13.86 µs |
| Sign ES256 | 73.78 µs | 63.15 µs | 54.80 µs | 52.32 µs |
| Parse HS256 | 2.819 µs | 7.676 µs | 11.20 µs | 13.29 µs |
| Parse ES256 | 77.18 µs | 84.27 µs | 89.90 µs | 90.43 µs |
| 并发 Parse HS256 | 783.9 ns | 3.951 µs | 6.085 µs | 8.180 µs |

- HS256：ydx 签发比 golang-jwt 快约 1.9 倍，验签快约 2.7 倍；并发验签快约 5 倍。
  分配上，ydx `Parse` 为 2 allocs/op、288 B/op，其它实现为 49–96 allocs/op、
  2.5–6.8 KiB/op。
- ES256：ECDSA 验签本身占主导，四个实现差距缩小到约 15%；ydx 验签最快，但签发比
  golang-jwt/jwx/go-jose 慢约 17%–41%。
- ydx 的可选复用路径：`ParseHS256Reuse` 2.249 µs / 0 allocs，`ParseHS256ParallelReuse`
  392.4 ns / 0 allocs；其它库没有等价的归还 API。
- 既有 ydx 内部基准（token 使用字符串 `aud`）为 `ParseHS256` 2.482 µs、
  `SignHS256` 3.476 µs，与对比表同一量级。

## 完整数据

<details>
<summary>5 轮均值</summary>

**github.com/shibingli/ydx/benchmarks/jwt**

| Benchmark | ns/op | B/op | allocs/op | MB/s |
|---|---:|---:|---:|---:|
| `SignHS256` | 3.476 µs | 933 | 19 |  |
| `ParseHS256` | 2.482 µs | 288 | 2 |  |
| `ParseES256` | 77.64 µs | 1.378 KiB | 21 |  |
| `ParseHS256Parallel` | 645.1 ns | 289 | 2 |  |
| `ParseHS256Reuse` | 2.249 µs | 0 | 0 |  |
| `ParseHS256ParallelReuse` | 392.4 ns | 0 | 0 |  |
| `SignHS256Compare/ydx` | 3.558 µs | 935 | 19 |  |
| `SignHS256Compare/golang-jwt` | 6.865 µs | 2.183 KiB | 45 |  |
| `SignHS256Compare/jwx` | 12.28 µs | 1.835 KiB | 38 |  |
| `SignHS256Compare/go-jose` | 13.86 µs | 3.623 KiB | 61 |  |
| `SignES256Compare/ydx` | 73.78 µs | 7.204 KiB | 82 |  |
| `SignES256Compare/golang-jwt` | 63.15 µs | 8.134 KiB | 103 |  |
| `SignES256Compare/jwx` | 54.80 µs | 7.852 KiB | 98 |  |
| `SignES256Compare/go-jose` | 52.32 µs | 9.644 KiB | 123 |  |
| `ParseHS256Compare/ydx` | 2.819 µs | 288 | 2 |  |
| `ParseHS256Compare/golang-jwt` | 7.676 µs | 2.536 KiB | 49 |  |
| `ParseHS256Compare/jwx` | 11.20 µs | 3.718 KiB | 75 |  |
| `ParseHS256Compare/go-jose` | 13.29 µs | 6.730 KiB | 96 |  |
| `ParseES256Compare/ydx` | 77.18 µs | 1.378 KiB | 21 |  |
| `ParseES256Compare/golang-jwt` | 84.27 µs | 3.389 KiB | 65 |  |
| `ParseES256Compare/jwx` | 89.90 µs | 4.563 KiB | 90 |  |
| `ParseES256Compare/go-jose` | 90.43 µs | 7.594 KiB | 111 |  |
| `ParseHS256ParallelCompare/ydx` | 783.9 ns | 289 | 2 |  |
| `ParseHS256ParallelCompare/golang-jwt` | 3.951 µs | 2.567 KiB | 49 |  |
| `ParseHS256ParallelCompare/jwx` | 6.085 µs | 3.788 KiB | 75 |  |
| `ParseHS256ParallelCompare/go-jose` | 8.180 µs | 6.801 KiB | 96 |  |
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
- ES256 的绝对数字受 ECDSA 实现与 CPU 影响很大；不要把 70–90 µs 当作跨机器常量。
- 同一轮内 5 个样本不足以给出 95% 置信区间；同一轮内小于约 5% 的差异视为噪声；
  跨轮次绝对数值可能因 CPU 频率/温度漂移。
