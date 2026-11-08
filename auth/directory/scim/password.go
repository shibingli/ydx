package scim

import (
	"context"
	"errors"

	"github.com/shibingli/ydx/errs"
)

// precheckPassword runs the optional pre-commit password hook. A rejection is reported as an
// invalid value before the store is touched, so the persisted profile stays unchanged. | precheckPassword
// 运行可选的提交前口令钩子。拒绝会在触碰存储前报告为取值非法，因此已持久化资料保持不变。
func (s *Server) precheckPassword(ctx context.Context, user *User, password string) error {
	if password == "" || s.passwordPrecheck == nil {
		return nil
	}
	if err := s.passwordPrecheck.PreparePassword(ctx, user, password); err != nil {
		return errs.WrapDetail(err, ErrInvalidValue, "password rejected | 口令被拒绝")
	}
	return nil
}

// setPassword provisions a password through the configured hook. | setPassword 通过已配置钩子预配
// 口令。
func (s *Server) setPassword(ctx context.Context, user *User, password string) error {
	if password == "" {
		return nil
	}
	if s.passwordSetter == nil {
		return errs.Detail(ErrNotConfigured, "password provisioning requires PasswordSetter | 口令预配需要 PasswordSetter")
	}
	if err := s.passwordSetter(ctx, user, password); err != nil {
		return errs.WrapDetail(err, ErrInvalidValue, "password rejected | 口令被拒绝")
	}
	return nil
}

// compensatePasswordFailure restores the profile captured before a password hook rejected an
// update. It returns cause when the prior profile was restored. A concurrent change is reported as
// ErrPasswordRollbackConflict and the newer profile is kept; any other restore failure is reported
// as ErrPasswordRollbackFailed sharing the cause. The restore runs on a context detached from
// request cancellation so a disconnected client cannot leave a half-applied update behind. |
// compensatePasswordFailure 恢复口令钩子拒绝更新前捕获的资料。先前资料恢复成功时返回 cause。并发
// 修改报告为 ErrPasswordRollbackConflict 并保留较新资料；其它恢复失败报告为与 cause 合并的
// ErrPasswordRollbackFailed。恢复在脱离请求取消的上下文上运行，因此客户端断开不会留下半应用的更新。
func (s *Server) compensatePasswordFailure(ctx context.Context, prior, applied *User, cause error) error {
	restored := prior.Clone()
	if restored == nil || restored.ID == "" {
		return errs.WrapDetail(cause, ErrPasswordRollbackFailed,
			"password rejected and the prior User is unavailable | 口令被拒绝且先前的 User 不可用")
	}
	restored.Password = ""
	restoreCtx := context.Background()
	if ctx != nil {
		restoreCtx = context.WithoutCancel(ctx)
	}
	if err := s.restoreUserVersion(restoreCtx, restored, userVersion(applied)); err != nil {
		if errors.Is(err, ErrPreconditionFailed) || errors.Is(err, ErrNotFound) {
			return errs.Detail(ErrPasswordRollbackConflict,
				"User %q changed concurrently; the newer profile was kept | User %q 已被并发修改；已保留较新资料",
				restored.ID, restored.ID)
		}
		return errs.WrapDetail(errors.Join(cause, err), ErrPasswordRollbackFailed,
			"password rejected and the prior User could not be restored | 口令被拒绝且无法恢复先前的 User")
	}
	return cause
}

// restoreUserVersion restores user only when the store still exposes expectedVersion. A store that
// implements UserVersionReplacer performs the comparison and the write atomically. Other stores use
// a best-effort read-compare-write, which leaves a small race window because the Store interface
// has no conditional write. An empty expectedVersion means the store exposes no versions, so the
// restore is unconditional and concurrent changes cannot be detected. | restoreUserVersion 仅在存储
// 仍暴露 expectedVersion 时恢复 user。实现 UserVersionReplacer 的存储原子地完成比较与写入。其它
// 存储使用尽力而为的读取-比较-写入，由于 Store 接口没有条件写入而留下很小的竞态窗口。
// expectedVersion 为空表示存储不暴露版本，因此恢复是无条件的且无法检测并发修改。
func (s *Server) restoreUserVersion(ctx context.Context, user *User, expectedVersion string) error {
	if expectedVersion != "" {
		if replacer, ok := s.store.(UserVersionReplacer); ok {
			_, err := replacer.ReplaceUserIfVersion(ctx, user, expectedVersion)
			return err
		}
		current, err := s.store.GetUser(ctx, user.ID)
		if err != nil {
			return err
		}
		if normalizeETag(userVersion(current)) != normalizeETag(expectedVersion) {
			return errs.Detail(ErrPreconditionFailed, "User %q version changed | User %q 版本已变化",
				user.ID, user.ID)
		}
	}
	_, err := s.store.ReplaceUser(ctx, user)
	return err
}
