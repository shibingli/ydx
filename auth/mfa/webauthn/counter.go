package webauthn

import "context"

// CounterPolicy selects how an assertion signature counter is checked against the stored value. |
// CounterPolicy 选择断言签名计数器与已存值的校验策略。
//
// Synchronized passkeys are copied between devices; WebAuthn marks them with the BE (backup
// eligible) and BS (backup state) flags. A restored passkey may legitimately restart its counter,
// so relying parties that accept synced passkeys must choose whether that reset is treated as a
// clone signal. | 同步通行密钥会在设备间复制；WebAuthn 用 BE（备份资格）与 BS（备份状态）标志标记
// 它们。恢复后的通行密钥可能合法地重启计数器，因此接受同步通行密钥的依赖方必须选择是否把该重置视为
// 克隆信号。
type CounterPolicy string

// The supported sign-counter policies. | 支持的签名计数器策略。
const (
	// CounterStrict rejects every counter that does not increase beyond a non-zero stored counter.
	// It is the default and the safest policy for single-device authenticators. | CounterStrict 在
	// 已存计数器非零时拒绝一切未超过已存值的计数器。它是默认值，也是单设备认证器最安全的策略。
	CounterStrict CounterPolicy = "strict"
	// CounterAllowBackupEligibleReset accepts a non-increasing counter only when the assertion
	// reports both BE=1 and BS=1. A backup-eligible credential that is not currently backed up
	// (BE=1, BS=0) and a non-backup credential (BE=0) remain strictly monotonic. | CounterAllowBackupEligibleReset
	// 仅在断言同时报告 BE=1 与 BS=1 时接受未增长的计数器。当前未备份的备份资格凭据（BE=1、BS=0）
	// 与非备份凭据（BE=0）仍保持严格单调。
	CounterAllowBackupEligibleReset CounterPolicy = "allow-backup-eligible-reset"
	// CounterAllowAny accepts every counter. It disables clone detection and is intended only for
	// deployments that detect cloned authenticators by other means. | CounterAllowAny 接受所有计数器。
	// 它会关闭克隆检测，仅用于通过其他手段检测克隆认证器的部署。
	CounterAllowAny CounterPolicy = "allow-any"
)

// validCounterPolicy reports whether policy is supported. | validCounterPolicy 报告策略是否受支持。
func validCounterPolicy(policy CounterPolicy) bool {
	switch policy {
	case CounterStrict, CounterAllowBackupEligibleReset, CounterAllowAny:
		return true
	default:
		return false
	}
}

// counterAccepted reports whether the assertion counter is accepted for stored under policy. |
// counterAccepted 报告在 policy 下断言计数器是否可被 stored 接受。
//
// A stored counter of zero means the authenticator does not maintain a counter, so every value is
// accepted. An increased counter is always accepted. A non-increase is accepted only by
// CounterAllowAny, or by CounterAllowBackupEligibleReset when the assertion reports BE=1 and BS=1.
// | 已存计数器为零表示认证器不维护计数器，因此接受任意值。增长后的计数器始终接受。未增长仅由
// CounterAllowAny 接受，或由 CounterAllowBackupEligibleReset 在断言报告 BE=1 与 BS=1 时接受。
func counterAccepted(policy CounterPolicy, stored uint32, authData *AuthenticatorData) bool {
	if authData == nil {
		return false
	}
	if stored == 0 {
		return true
	}
	if authData.SignCount > stored {
		return true
	}
	switch policy {
	case CounterAllowAny:
		return true
	case CounterAllowBackupEligibleReset:
		return authData.Flags.BackupEligible() && authData.Flags.BackupState()
	default:
		return false
	}
}

// BackupStateUpdater is an optional CredentialStore extension that persists the BS flag. |
// BackupStateUpdater 是持久化 BS 标志的可选 CredentialStore 扩展。
//
// completeAssertion calls UpdateBackupState after a successful assertion when the store implements
// this interface and the asserted BS value differs from the stored value. Stores that do not
// implement it leave the BS flag only on the returned Credential for the caller to persist. | 断言
// 成功且存储实现了本接口、断言的 BS 值与已存值不同时，completeAssertion 会调用 UpdateBackupState。
// 未实现本接口的存储只在返回的 Credential 上保留 BS 标志，由调用方自行持久化。
type BackupStateUpdater interface {
	// UpdateBackupState persists the current BS flag for a credential. | UpdateBackupState 持久化凭据当前的 BS 标志。
	UpdateBackupState(ctx context.Context, credentialID []byte, backupState bool) error
}

var (
	_ BackupStateUpdater = (*MemoryCredentialStore)(nil)
	_ BackupStateUpdater = (*AuthCredentialStore)(nil)
)
