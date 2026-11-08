package scim

import (
	"context"
	"errors"

	"github.com/shibingli/ydx/errs"
)

// PasswordProvisioner starts a two-phase external password provisioning. The server calls
// BeginPassword before it writes the profile, CommitPassword after the profile is stored, and
// RollbackPassword when either step fails. BeginPassword must not publish the password; it only
// prepares an external transaction. On create the User has no identifier yet; on replace and patch
// it carries the existing identifier. When both PasswordProvisioner and PasswordSetter are
// configured the provisioner takes precedence and the setter is not called. PasswordPrecheck still
// runs before BeginPassword. | PasswordProvisioner 启动两阶段外部口令预配。服务端在写入资料前调用
// BeginPassword，在资料存储后调用 CommitPassword，任一步失败时调用 RollbackPassword。
// BeginPassword 不得发布口令，只准备外部事务。创建时 User 尚无标识；替换与补丁时携带既有标识。
// PasswordProvisioner 与 PasswordSetter 同时配置时预配器优先，不再调用 setter。PasswordPrecheck
// 仍在 BeginPassword 之前运行。
type PasswordProvisioner interface {
	// BeginPassword prepares an external password change and returns its transaction. An error
	// rejects the request before the profile is written. A nil transaction without an error is
	// reported as ErrInternal because the password would otherwise be lost. | BeginPassword 准备外部
	// 口令变更并返回其事务。返回错误会在写入资料前拒绝请求。返回 nil 事务且无错误会被报告为
	// ErrInternal，否则口令将丢失。
	BeginPassword(ctx context.Context, user *User, password string) (PasswordTransaction, error)
}

// PasswordTransaction is a prepared external password change. The server calls exactly one of
// Commit or Rollback: Commit after the profile write succeeds, Rollback when the profile write or
// Commit fails. Commit returning an error means the external change did not commit (or can still
// be rolled back); the server then calls Rollback. Both methods must be safe for a single call and
// should tolerate a cancelled request context because the server detaches compensation contexts. |
// PasswordTransaction 是已准备的外部口令变更。服务端恰好调用 Commit 或 Rollback 之一：资料写入
// 成功后调用 Commit，资料写入或 Commit 失败时调用 Rollback。Commit 返回错误表示外部变更未提交
// （或仍可回滚）；服务端随后调用 Rollback。两个方法都必须可安全调用一次，并应容忍已取消的请求
// 上下文，因为服务端会脱离取消执行补偿。
type PasswordTransaction interface {
	// Commit publishes the prepared password change. | Commit 发布已准备的口令变更。
	Commit(ctx context.Context) error
	// Rollback discards the prepared password change. | Rollback 丢弃已准备的口令变更。
	Rollback(ctx context.Context) error
}

// PasswordProvisionerFunc adapts an ordinary function to PasswordProvisioner. A nil function fails
// with ErrNotConfigured. | PasswordProvisionerFunc 把普通函数适配为 PasswordProvisioner。nil 函数
// 返回 ErrNotConfigured。
type PasswordProvisionerFunc func(ctx context.Context, user *User, password string) (PasswordTransaction, error)

// BeginPassword calls f(ctx, user, password). | BeginPassword 调用 f(ctx, user, password)。
func (f PasswordProvisionerFunc) BeginPassword(ctx context.Context, user *User, password string) (PasswordTransaction, error) {
	if f == nil {
		return nil, errs.Detail(ErrNotConfigured, "password provisioner is nil | 口令预配器为空")
	}
	return f(ctx, user, password)
}

// PasswordTransactionFuncs adapts functions to PasswordTransaction. A nil CommitFunc commits
// nothing and a nil RollbackFunc rolls back nothing. | PasswordTransactionFuncs 把函数适配为
// PasswordTransaction。nil CommitFunc 不提交任何内容，nil RollbackFunc 不回滚任何内容。
type PasswordTransactionFuncs struct {
	// CommitFunc publishes the prepared change. | CommitFunc 发布已准备变更。
	CommitFunc func(ctx context.Context) error
	// RollbackFunc discards the prepared change. | RollbackFunc 丢弃已准备变更。
	RollbackFunc func(ctx context.Context) error
}

// Commit calls CommitFunc. | Commit 调用 CommitFunc。
func (t PasswordTransactionFuncs) Commit(ctx context.Context) error {
	if t.CommitFunc == nil {
		return nil
	}
	return t.CommitFunc(ctx)
}

// Rollback calls RollbackFunc. | Rollback 调用 RollbackFunc。
func (t PasswordTransactionFuncs) Rollback(ctx context.Context) error {
	if t.RollbackFunc == nil {
		return nil
	}
	return t.RollbackFunc(ctx)
}

// passwordProvisioningConfigured reports whether any password hook is configured. |
// passwordProvisioningConfigured 报告是否配置了任一口令钩子。
func (s *Server) passwordProvisioningConfigured() bool {
	return s != nil && (s.passwordProvisioner != nil || s.passwordSetter != nil)
}

// beginPassword starts a two-phase provision when password is non-empty and a provisioner is
// configured. It returns a nil transaction for the empty-password and legacy-setter paths. |
// beginPassword 在 password 非空且配置了预配器时启动两阶段预配。空口令与旧版 setter 路径返回 nil
// 事务。
func (s *Server) beginPassword(ctx context.Context, user *User, password string) (PasswordTransaction, error) {
	if password == "" || s == nil || s.passwordProvisioner == nil {
		return nil, nil
	}
	tx, err := s.passwordProvisioner.BeginPassword(ctx, user, password)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidValue, "password provisioning rejected | 口令预配被拒绝")
	}
	if tx == nil {
		return nil, errs.Detail(ErrInternal, "password provisioner returned no transaction | 口令预配器未返回事务")
	}
	return tx, nil
}

// commitPasswordTransaction commits tx. A failure is reported as an invalid value; callers
// compensate the profile and the transaction. | commitPasswordTransaction 提交 tx。失败报告为取值
// 非法；调用方补偿资料与事务。
func (s *Server) commitPasswordTransaction(ctx context.Context, tx PasswordTransaction) error {
	if tx == nil {
		return nil
	}
	if err := tx.Commit(ctx); err != nil {
		return errs.WrapDetail(err, ErrInvalidValue, "password provisioning rejected | 口令预配被拒绝")
	}
	return nil
}

// rollbackPasswordTransaction rolls back tx on a context detached from request cancellation. A
// failure is reported as ErrPasswordRollbackFailed. | rollbackPasswordTransaction 在脱离请求取消的
// 上下文上回滚 tx。失败报告为 ErrPasswordRollbackFailed。
func (s *Server) rollbackPasswordTransaction(ctx context.Context, tx PasswordTransaction) error {
	if tx == nil {
		return nil
	}
	if err := tx.Rollback(detachedCompensationContext(ctx)); err != nil {
		return errs.WrapDetail(err, ErrPasswordRollbackFailed,
			"external password transaction could not be rolled back | 无法回滚外部口令事务")
	}
	return nil
}

// abortPasswordProvisioning rolls back tx after the profile write did not commit and returns cause,
// or an explicit combined ErrPasswordRollbackFailed when the rollback also fails. |
// abortPasswordProvisioning 在资料写入未提交时回滚 tx 并返回 cause；回滚也失败时返回明确的组合
// ErrPasswordRollbackFailed。
func (s *Server) abortPasswordProvisioning(ctx context.Context, tx PasswordTransaction, cause error) error {
	if tx == nil {
		return cause
	}
	if err := s.rollbackPasswordTransaction(ctx, tx); err != nil {
		return errs.WrapDetail(errors.Join(cause, err), ErrPasswordRollbackFailed,
			"profile write failed and the external password transaction could not be rolled back | 资料写入失败且无法回滚外部口令事务")
	}
	return cause
}

// compensateCreatedUser deletes a newly created profile and rolls back tx after password
// provisioning failed. deleteProfile is false when an atomic bulk undo log owns the profile
// rollback. Any compensation failure is returned as ErrPasswordRollbackFailed joined with cause
// and every failed step. | compensateCreatedUser 在口令预配失败后删除新建资料并回滚 tx。原子批量
// 撤销日志负责资料回滚时 deleteProfile 为 false。任何补偿失败都会与 cause 及所有失败步骤合并为
// ErrPasswordRollbackFailed 返回。
func (s *Server) compensateCreatedUser(ctx context.Context, tx PasswordTransaction, created *User, cause error, deleteProfile bool) error {
	rollbackCtx := detachedCompensationContext(ctx)
	var compensation []error
	if tx != nil {
		if err := tx.Rollback(rollbackCtx); err != nil {
			compensation = append(compensation, errs.WrapDetail(err, ErrPasswordRollbackFailed,
				"external password transaction could not be rolled back | 无法回滚外部口令事务"))
		}
	}
	if deleteProfile && created != nil && created.ID != "" {
		if err := s.store.DeleteUser(rollbackCtx, created.ID); err != nil && !errors.Is(err, ErrNotFound) {
			compensation = append(compensation, err)
		}
	}
	if len(compensation) == 0 {
		return cause
	}
	joined := errors.Join(append([]error{cause}, compensation...)...)
	return errs.WrapDetail(joined, ErrPasswordRollbackFailed,
		"password provisioning failed and the created User could not be fully compensated | 口令预配失败且无法完全补偿已创建的 User")
}

// compensateReplacedUser restores the prior profile and rolls back tx after password provisioning
// failed. Profile compensation preserves a concurrent change as ErrPasswordRollbackConflict. An
// external rollback failure is reported as ErrPasswordRollbackFailed and takes precedence over a
// profile conflict because external state is then unknown. | compensateReplacedUser 在口令预配失败
// 后恢复先前资料并回滚 tx。资料补偿把并发修改保留为 ErrPasswordRollbackConflict。外部回滚失败报告
// 为 ErrPasswordRollbackFailed，并因外部状态未知而优先于资料冲突。
func (s *Server) compensateReplacedUser(ctx context.Context, tx PasswordTransaction, prior, applied *User, cause error) error {
	var externalErr error
	if tx != nil {
		if err := tx.Rollback(detachedCompensationContext(ctx)); err != nil {
			externalErr = errs.WrapDetail(err, ErrPasswordRollbackFailed,
				"external password transaction could not be rolled back | 无法回滚外部口令事务")
		}
	}
	profileErr := s.compensatePasswordFailure(ctx, prior, applied, cause)
	if externalErr == nil {
		return profileErr
	}
	return errs.WrapDetail(errors.Join(profileErr, externalErr), ErrPasswordRollbackFailed,
		"password provisioning failed and the external transaction could not be rolled back | 口令预配失败且无法回滚外部事务")
}

// detachedCompensationContext returns a context that keeps values but ignores request cancellation.
// | detachedCompensationContext 返回保留值但忽略请求取消的上下文。
func detachedCompensationContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return context.WithoutCancel(ctx)
}
