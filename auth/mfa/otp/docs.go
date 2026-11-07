// Package otp implements RFC 4226 counter-based (HOTP) and RFC 6238 time-based (TOTP)
// one-time passwords, otpauth:// enrollment URIs, recovery codes and replay protection.
// | Package otp 实现 RFC 4226 基于计数器（HOTP）与 RFC 6238 基于时间（TOTP）的一次性口令、
// otpauth:// 登记 URI、恢复码与重放保护。
//
// The package is deliberately independent of any storage or HTTP layer: callers own secret
// persistence and decide when a verification result may be trusted. Secrets are RFC 4648 base32
// strings without padding, which is what every mainstream authenticator application accepts.
// | 本包刻意不依赖任何存储或 HTTP 层：调用方负责密钥持久化，并决定何时可以信任校验结果。密钥是
// RFC 4648 无填充 base32 字符串，这也是所有主流认证器都接受的形式。
//
// # Algorithms | 算法
//
// HOTP computes HMAC over an eight-byte big-endian counter and applies the RFC 4226 dynamic
// truncation. TOTP replaces the counter with the number of Period-long intervals since the Unix
// epoch. SHA1, SHA256 and SHA512 are supported, with six to ten decimal digits. | HOTP 对八字节大端
// 计数器计算 HMAC 并应用 RFC 4226 动态截断。TOTP 用自 Unix 纪元起以 Period 为长度的时间区间序号
// 替代计数器。支持 SHA1、SHA256 与 SHA512，输出六到十位十进制数字。
//
// # Validation windows | 校验窗口
//
// Config.Skew is the number of adjacent counters or time steps accepted on each side of the
// expected value. Zero means exact matching, which is the safest default; DefaultSkew documents
// the commonly deployed tolerance of one step. ValidateHOTP and ValidateTOTP return the matched
// counter or step so callers can advance a stored HOTP counter or feed a ReplayGuard. | Config.Skew
// 是期望值两侧接受的相邻计数器或时间步数量。零值表示精确匹配，这是最安全的默认值；DefaultSkew
// 记录了常见部署的一步容差。ValidateHOTP 与 ValidateTOTP 返回命中的计数器或时间步，因此调用方可以
// 推进已存 HOTP 计数器或把时间步交给 ReplayGuard。
//
// # Replay protection | 重放保护
//
// A TOTP code remains valid for its whole time step (plus any skew window), so a captured code can
// be presented twice. Validator and the auth.MFAVerifier adapter accept an optional ReplayGuard
// that remembers accepted (key, step) pairs; NewMemoryReplayGuard provides a single-process
// implementation, while multi-instance deployments should supply a shared store. | TOTP 口令在其
// 整个时间步（加上容差窗口）内始终有效，因此被截获的口令可以被重复提交。Validator 与
// auth.MFAVerifier 适配器接受可选的 ReplayGuard，用于记住已接受的 (key, step) 对；
// NewMemoryReplayGuard 提供单进程实现，多实例部署应提供共享存储。
//
// # Recovery codes | 恢复码
//
// GenerateRecoveryCodes returns high-entropy random codes. RecoveryCodeHasher protects them with
// a caller-supplied pepper and RecoveryCodeHasher.Verify documents the one-time consumption
// contract: the caller must atomically remove a matching hash after a successful verification.
// | GenerateRecoveryCodes 返回高熵随机恢复码。RecoveryCodeHasher 使用调用方提供的 pepper 保护
// 它们，RecoveryCodeHasher.Verify 写明一次性消费契约：校验成功后调用方必须原子移除匹配的哈希。
//
// # Typical flows | 典型流程
//
// Enrollment and verification with YD auth | 使用 YD auth 的登记与校验：
//
//	secret, err := otp.GenerateSecret(0)
//	uri := otp.GenerateURI("Example", "alice@example.com", secret, otp.Config{})
//	svc.RegisterMFAVerifier(auth.CredentialTOTP, otp.NewVerifier(
//		otp.WithVerifierGuard(otp.NewMemoryReplayGuard()),
//	))
//
// Standalone validation without the auth service | 不经过 auth 服务的独立校验：
//
//	validator := otp.NewValidator(otp.Config{Skew: 1},
//		otp.WithReplayGuard(otp.NewMemoryReplayGuard()),
//	)
//	step, ok, err := validator.ValidateTOTP(ctx, secret, code)
//
// URI round trip | URI 往返：
//
//	uri := otp.GenerateURI("Example", "alice@example.com", secret, otp.Config{Digits: 8})
//	parsed, err := otp.ParseURI(uri)
//
// Steam Guard compatibility is available through SteamCode and ValidateSteamCode; it is a
// five-character proprietary variant and is intentionally kept out of Config and otpauth URIs.
// | Steam Guard 兼容性通过 SteamCode 与 ValidateSteamCode 提供；它是五字符专有变体，刻意不纳入
// Config 与 otpauth URI。
//
// # Security notes | 安全说明
//
// Secrets come from crypto/rand and are never derived from user input. Code comparison is
// constant time. Error messages and details never contain the shared secret. The package uses no
// reflection, no cgo and no external dependency beyond ydx/errs and the auth types. | 密钥来自
// crypto/rand，绝不从用户输入派生。口令比较使用常量时间。错误消息与细节绝不包含共享密钥。本包不
// 使用反射、cgo，除 ydx/errs 与 auth 类型外不引入外部依赖。
package otp
