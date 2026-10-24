// Package crypto benchmarks the SM2/SM3/SM4 primitives used by yd's security layer against
// SHA-256, AES-GCM, ChaCha20-Poly1305, ECDSA and Ed25519, plus the legacy gmsm implementation.
// yd/security/guomi delegates to the maintained gmsm backend measured here; the wrapper adds no
// per-operation work beyond argument validation. | Package crypto 对比 yd 安全层使用的
// SM2/SM3/SM4 原语与 SHA-256、AES-GCM、ChaCha20-Poly1305、ECDSA、Ed25519，以及旧版 gmsm 实现。
// yd/security/guomi 委托给这里测量的维护版 gmsm 后端；封装层除参数校验外不增加每操作开销。
package crypto
