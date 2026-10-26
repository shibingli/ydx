# guomi — 纯 Go 国密套件（SM2/SM3/SM4）

`github.com/shibingli/ydx/guomi` 提供符合国密标准的 SM2 公钥密码、SM3 哈希与 SM4 分组
密码。原语来自纯 Go、无 cgo 的 [`emmansun/gmsm`](https://github.com/emmansun/gmsm)；
本包负责参数校验、格式转换、口令散列与安全默认值。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/guomi` |
| 包名 | `guomi` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |
| 标准 | GB/T 32918（SM2）、GB/T 32905-2016（SM3）、GB/T 32907-2016（SM4） |

## 功能

- **SM3**：`Sum`、`SumHex`、`New`、`HMAC`、`PBKDF2`。
- **SM4**：`NewCipher`、`NewGCM`、`SealGCM` / `OpenGCM`、`EncryptCBC` / `DecryptCBC`、
  `EncryptECB` / `DecryptECB`、`RandomKey`、`RandomIV`。
- **SM2**：`GenerateKey`、`Sign` / `Verify`、`SignHex` / `VerifyHex`、`Encrypt` / `Decrypt`、
  `EncryptRaw` / `DecryptRaw`（原始 C1C3C2，供前端互操作）。
- **密钥格式**：PEM、十六进制、`PrivateKey.Public()`、`Raw()` 取回底层 gmsm 密钥。
- **口令保护**：`HashPassword` / `VerifyPassword`（PBKDF2-SM3 + 随机盐）。
- **审计**：`CipherSuiteInfo` 返回算法、模式与实现来源，供 `/health` 与审计输出。

## 特性

- **纯 Go、无 cgo**：不依赖 OpenSSL，默认 `CGO_ENABLED=0` 可构建。
- **密码学随机**：所有随机数来自 `crypto/rand`。
- **SM2 安全默认**：解密前校验 C1 在曲线上，C3 用常量时间比较；空明文由本包显式处理。
- **标准字节布局**：原始 C1C3C2 为 `X1(32) || Y1(32) || C3(32) || C2`（无 `0x04` 前缀）。
- **默认用户标识**：SM2 签名/验签使用 `"1234567812345678"`（GB/T 32918.2）。
- **模式加速**：SM4 的 CBC/GCM/ECB 基于 `crypto/cipher`，优先使用底层密码提供的加速
  CBC/ECB 路径。
- **可复用 AEAD**：`NewGCM` 返回无状态 AEAD，可跨协程复用，避免每条消息重建密钥编排。
- **错误哨兵**：非法密文、非法私钥、非法口令散列编码等均可用 `errors.Is` 判定。

## 快速开始

```go
package main

import (
	"fmt"

	"github.com/shibingli/ydx/guomi"
)

func main() {
	// SM3
	fmt.Println(guomi.SumHex([]byte("abc")))

	// SM2 签名/验签
	priv, err := guomi.GenerateKey()
	if err != nil {
		return
	}
	pub := priv.Public()
	sig, err := guomi.Sign(priv, []byte("hello"))
	if err != nil {
		return
	}
	ok, err := guomi.Verify(pub, []byte("hello"), sig)
	if err != nil || !ok {
		return
	}

	// SM2 原始 C1C3C2 加解密（前端互操作）
	ct, err := guomi.EncryptRaw(pub, []byte("secret"))
	if err != nil {
		return
	}
	pt, err := guomi.DecryptRaw(priv, ct)
	if err != nil {
		return
	}
	fmt.Println(string(pt))

	// SM4-GCM
	key, err := guomi.RandomKey()
	if err != nil {
		return
	}
	iv, err := guomi.RandomIV()
	if err != nil {
		return
	}
	nonce := iv[:guomi.SM4GCMNonceSize]
	sealed, err := guomi.SealGCM(key, nonce, []byte("hello"), []byte("aad"))
	if err != nil {
		return
	}
	opened, err := guomi.OpenGCM(key, nonce, sealed, []byte("aad"))
	if err != nil {
		return
	}
	fmt.Println(string(opened))
}
```

口令散列：

```go
encoded, err := guomi.HashPassword("correct horse battery staple", guomi.PasswordOptions{
	Iterations: 100_000,
})
if err != nil {
	return err
}
ok, err := guomi.VerifyPassword(encoded, "correct horse battery staple")
```

## 应用场景

- **国密合规**：等保、密评与信创项目要求 SM2/SM3/SM4。
- **数据加密**：SM4-GCM 认证加密、SM2 公钥加密。
- **完整性校验**：SM3 摘要、HMAC-SM3、PBKDF2-SM3。
- **口令保护**：随机盐 + PBKDF2-SM3 存储口令散列。
- **前端互操作**：原始 C1C3C2 密文与 JS 国密库互通。
- **审计/健康检查**：`CipherSuiteInfo` 输出当前套件。

## 性能指标

基准模块：[`benchmarks/crypto`](../benchmarks/crypto/README.md)。参考环境为 AMD Ryzen
AI MAX+ 395、Go 1.27.3、Linux，`GOMAXPROCS=32`、5 轮中位数。

| 操作 | ydx/guomi（emmansun） | 对照 | 旧版 tjfoc |
|---|---:|---:|---:|
| SM3 4 KiB | **7.36 µs** | SHA-256 1.68 µs | 12.52 µs |
| SM4-GCM 4 KiB seal/open | **5.47 / 5.18 µs** | AES-GCM 0.79 / 0.79 µs | 45.05 / 44.89 µs |
| SM2 sign / verify | **14.02 / 33.91 µs** | ECDSA P-256 17.67 / 38.54 µs | 130.5 / 686.5 µs |
| SM2 encrypt / decrypt | **35.55 / 28.78 µs** | — | 707.8 / 548.4 µs |
| HMAC-SM3（256 B） | **729.6 ns** | HMAC-SHA256 213.7 ns | 1.745 µs |
| PBKDF2-SM3（1000 次） | **284.2 µs** | PBKDF2-SHA256 115.4 µs | 925.9 µs |

- 相对旧版 `tjfoc/gmsm`：SM3 4 KiB 快 1.70×，SM4-GCM 4 KiB 快 8.37×，SM2 签名/验签
  快 9.16×/20.0×。
- SM2 签名/验签快于 ECDSA P-256；Ed25519 的签名/验签更快，但没有加密能力。
- SM3/SM4 没有 SHA-NI/AES-NI 对应指令，SM3 4 KiB 约为 SHA-256 的 23%，SM4-GCM 4 KiB
  约为 AES-GCM 的 14%；这是算法与指令集差异，不是封装开销。
- 封装层相对直接调用 `emmansun` 的差异在 0.8% 以内（SM4-CBC 因 PKCS#7 填充略高）。
- SM3、SM4-GCM、HMAC、PBKDF2 等路径大量为 0 allocs/op；SM4-GCM 一次性入口有 1 次
  输出分配，复用 AEAD 与调用方缓冲可做到零分配。

> 完整表格、分配数据与安全口径见基准 README；跨机绝对值受 CPU 与负载影响。

## 第三方依赖与鸣谢

| 依赖 | 版本 | 许可证 | 用途 |
|---|---|---|---|
| [`emmansun/gmsm`](https://github.com/emmansun/gmsm) | v0.45.1 | MIT | SM2/SM3/SM4 原语 |

仓库内依赖：`base64`、`errs`。

鸣谢 `emmansun/gmsm` 提供的纯 Go 国密实现，以及 `tjfoc/gmsm` 作为历史基线的对比数据。

## 相关模块

- [`base64`](../base64/README.md)：密文/签名的文本编码。
- [`errs`](../errs/README.md)：错误哨兵与包装。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
