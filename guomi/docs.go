// Package guomi provides the GB/T national cryptography suite: SM2 public key cryptography, SM3 hashing and the SM4 block cipher. | Package guomi 提供符合国密标准的 SM2/SM3/SM4 密码套件。
// Typical uses are data encryption, integrity verification and password protection. | 用于数据加密、完整性校验与口令保护。
//
// Implementation notes | 实现约定：
//
//   - Primitives come from github.com/emmansun/gmsm, which is pure Go and cgo-free. | 原语来源：github.com/emmansun/gmsm（纯 Go，无 cgo）。
//   - gmsm supplies the SM2 curve arithmetic, signing and verification, encryption and decryption (including the GB/T 32918.4 KDF), the SM3 compression function and the SM4 block cipher. | gmsm 提供 SM2 曲线运算、签名验签、加解密（含 GB/T 32918.4 KDF）、SM3 压缩函数与 SM4 分组密码。
//   - No other third-party crypto library is imported, and there is no OpenSSL binding or cgo code. | 不引入任何其他第三方密码库，也不依赖 OpenSSL 绑定或任何 cgo 代码。
//   - All randomness comes from crypto/rand. | 随机数一律来自 crypto/rand。
//   - This package pins the raw C1C3C2 byte layout and handles the empty plaintext that the upstream primitive rejects. | 本包严格定义原始 C1C3C2 字节布局，并处理上游原语拒绝的空明文。
//   - SM2 signing and verification follow GB/T 32918.2 through gmsm, using the default user ID "1234567812345678". | SM2 签名/验签按 GB/T 32918.2 使用 gmsm 实现，用户标识为默认值 "1234567812345678"。
//   - SM4 modes (CBC, GCM and ECB) build on crypto/cipher over the SM4 block cipher, using the cipher's own accelerated CBC/ECB paths when it provides them. | SM4 的工作模式（CBC/GCM/ECB）基于标准库 crypto/cipher 组合；底层密码提供加速 CBC/ECB 路径时优先使用。
//   - Base64 encoding goes through the framework wrapper github.com/shibingli/yd/ydx/base64. | Base64 编解码统一走框架自封装层 github.com/shibingli/yd/ydx/base64。
//
// Standards | 标准依据：
//
//   - SM3: GB/T 32905-2016. | SM3：GB/T 32905-2016。
//   - SM4: GB/T 32907-2016. | SM4：GB/T 32907-2016。
//   - SM2: GB/T 32918 parts 1 to 4. | SM2：GB/T 32918（第 1~4 部分）。
//
// Typical usage | 典型用法：
//
//	sum := guomi.SumHex([]byte("abc"))                 // SM3 digest, lowercase hex | SM3 摘要（小写十六进制）
//	priv, err := guomi.GenerateKey()                   // SM2 key pair | SM2 密钥对
//	ct, err := guomi.EncryptRaw(priv.Public(), msg)    // raw C1C3C2 ciphertext for JS interop | 原始 C1C3C2 密文（前端互操作）
//	key, err := guomi.RandomKey()                      // SM4 key | SM4 密钥
//	sealed, err := guomi.SealGCM(key, nonce, msg, aad) // SM4-GCM sealed box | SM4-GCM 加密并认证

package guomi
