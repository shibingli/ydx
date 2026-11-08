package kms

import (
	"context"
	"math"
	"sort"
	"time"

	"github.com/shibingli/ydx/errs"
	ydlog "github.com/shibingli/ydx/log"
)

// Activate moves a pre-active key to active. | Activate 把预激活密钥迁移为 active。
//
// Only StatePreActive may be activated; reactivating a deactivated key is rejected because NIST
// SP 800-57 treats deactivation as one-way. The operation is audited. | 仅 StatePreActive 可激活；
// 已停用密钥不可重新激活，因为 NIST SP 800-57 把停用视为单向操作。该操作会写入审计。
func (s *Service) Activate(ctx context.Context, id string) (*Key, error) {
	now := s.Now()
	key, err := s.mutateStoredKey(ctx, id, func(k *Key) error {
		if err := k.Transition(StateActive, now); err != nil {
			return err
		}
		if version := k.CurrentVersion(); version != nil {
			version.State = StateActive
			version.ActivatedAt = now
		}
		return nil
	})
	if err != nil {
		s.fail(ctx, OperationKeyActivate, id, 0, err)
		return nil, err
	}
	s.succeed(ctx, OperationKeyActivate, key.ID, key.Version, map[string]string{"state": string(StateActive)})
	return key.PublicView(), nil
}

// Deactivate moves a pre-active or active key to deactivated. | Deactivate 把预激活或 active 密钥迁移为 deactivated。
//
// A deactivated key refuses encryption and signing but still decrypts legacy data, unwraps legacy
// keys and verifies old signatures. The operation is audited. | 已停用密钥拒绝加密与签名，但仍可
// 解密历史数据、解包历史密钥并校验旧签名。该操作会写入审计。
func (s *Service) Deactivate(ctx context.Context, id string) (*Key, error) {
	now := s.Now()
	key, err := s.mutateStoredKey(ctx, id, func(k *Key) error {
		if err := k.Transition(StateDeactivated, now); err != nil {
			return err
		}
		if version := k.CurrentVersion(); version != nil {
			version.State = StateDeactivated
			version.DeactivatedAt = now
		}
		return nil
	})
	if err != nil {
		s.fail(ctx, OperationKeyDeactivate, id, 0, err)
		return nil, err
	}
	s.succeed(ctx, OperationKeyDeactivate, key.ID, key.Version, map[string]string{"state": string(StateDeactivated)})
	s.forgetNonces(key.ID)
	return key.PublicView(), nil
}

// Compromise marks a pre-active, active or deactivated key as compromised. | Compromise 把预激活、
// active 或 deactivated 密钥标记为 compromised。
//
// Every cryptographic use is refused afterwards. The material is retained until Destroy so the
// incident can be investigated. The operation is audited. | 此后一切密码使用都会被拒绝。材料保留
// 至 Destroy，以便调查事件。该操作会写入审计。
func (s *Service) Compromise(ctx context.Context, id string) (*Key, error) {
	now := s.Now()
	key, err := s.mutateStoredKey(ctx, id, func(k *Key) error {
		if err := k.Transition(StateCompromised, now); err != nil {
			return err
		}
		for _, version := range k.Versions {
			if version == nil || version.State == StateDestroyed {
				continue
			}
			version.State = StateCompromised
		}
		return nil
	})
	if err != nil {
		s.fail(ctx, OperationKeyCompromise, id, 0, err)
		return nil, err
	}
	s.succeed(ctx, OperationKeyCompromise, key.ID, key.Version, map[string]string{"state": string(StateCompromised)})
	s.forgetNonces(key.ID)
	return key.PublicView(), nil
}

// Destroy permanently erases the material of a non-active key. | Destroy 永久擦除非 active 密钥的材料。
//
// A key must be deactivated, compromised, pre-active or pending deletion first; destroying an active
// key returns ErrInvalidState. Only metadata survives. The operation is audited. | 密钥必须已停用、
// 已泄露、预激活或待删除；销毁 active 密钥返回 ErrInvalidState。只有元数据保留。该操作会写入审计。
func (s *Service) Destroy(ctx context.Context, id string) (*Key, error) {
	now := s.Now()
	key, err := s.mutateStoredKey(ctx, id, func(k *Key) error {
		if err := k.Transition(StateDestroyed, now); err != nil {
			return err
		}
		for _, version := range k.Versions {
			if version == nil {
				continue
			}
			version.State = StateDestroyed
			version.DestroyedAt = now
		}
		return nil
	})
	if err != nil {
		s.fail(ctx, OperationKeyDestroy, id, 0, err)
		return nil, err
	}
	s.succeed(ctx, OperationKeyDestroy, key.ID, key.Version, map[string]string{"state": string(StateDestroyed)})
	s.forgetNonces(key.ID)
	return key.PublicView(), nil
}

// ScheduleDelete marks a key for destruction after delay. | ScheduleDelete 把密钥标记为 delay 之后销毁。
//
// delay <= 0 uses Config.DeletionDelay, and a zero config delays 24 hours. The key becomes unusable
// immediately. The operation is audited. | delay <= 0 使用 Config.DeletionDelay，配置为零时延迟 24
// 小时。密钥立即不可用。该操作会写入审计。
func (s *Service) ScheduleDelete(ctx context.Context, id string, delay time.Duration) (*Key, error) {
	now := s.Now()
	if delay <= 0 {
		delay = s.deletionDelay
	}
	if delay <= 0 {
		delay = defaultDeletionDelay
	}
	key, err := s.mutateStoredKey(ctx, id, func(k *Key) error {
		if err := k.Transition(StatePendingDeletion, now); err != nil {
			return err
		}
		k.DeleteAfter = now.Add(delay)
		for _, version := range k.Versions {
			if version == nil || version.State == StateDestroyed {
				continue
			}
			version.State = StateDeactivated
			if version.DeactivatedAt.IsZero() {
				version.DeactivatedAt = now
			}
		}
		return nil
	})
	if err != nil {
		s.fail(ctx, OperationKeyScheduleDelete, id, 0, err)
		return nil, err
	}
	s.succeed(ctx, OperationKeyScheduleDelete, key.ID, key.Version, map[string]string{
		"state":       string(StatePendingDeletion),
		"deleteAfter": key.DeleteAfter.Format(time.RFC3339),
	})
	s.forgetNonces(key.ID)
	return key.PublicView(), nil
}

// DestroyExpired destroys pending-deletion keys whose DeleteAfter is at or before now. | DestroyExpired
// 销毁 DeleteAfter 不晚于 now 的待删除密钥。
//
// It returns the number of destroyed keys and the first error; remaining keys are still processed. | 它
// 返回销毁数量与首个错误；其余密钥仍会被处理。
func (s *Service) DestroyExpired(ctx context.Context, now time.Time) (int, error) {
	if now.IsZero() {
		now = s.Now()
	} else {
		now = now.UTC()
	}
	keys, err := s.store.ListKeys(ctx, KeyFilter{State: StatePendingDeletion})
	if err != nil {
		return 0, err
	}
	destroyed := 0
	var firstErr error
	for _, key := range keys {
		if key == nil || key.DeleteAfter.IsZero() || key.DeleteAfter.After(now) {
			continue
		}
		if _, err := s.Destroy(ctx, key.ID); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			s.log().Warn("kms: scheduled destroy failed | kms：计划销毁失败",
				ydlog.Str("key_id", key.ID), ydlog.Err(err))
			continue
		}
		destroyed++
	}
	return destroyed, firstErr
}

// Rotate creates a new active version and retires the current version. | Rotate 创建新的 active 版本
// 并退役当前版本。
//
// The key must be active. Both the previous and the new material are retained: the previous version
// becomes deactivated and still decrypts data protected before rotation, while the new version is
// used for new encryption. The operation is audited. | 密钥必须为 active。旧材料与新材料都会保留：
// 旧版本变为 deactivated，仍可解密轮换前保护的数据；新版本用于新的加密。该操作会写入审计。
func (s *Service) Rotate(ctx context.Context, id string) (*Key, error) {
	target := id
	for attempt := 0; attempt < mutationRetries; attempt++ {
		key, err := resolveStoredKey(ctx, s.store, target)
		if err != nil {
			s.fail(ctx, OperationKeyRotate, target, 0, err)
			return nil, err
		}
		target = key.ID
		if key.State != StateActive {
			err := errs.Detail(ErrKeyNotUsable, "rotation requires state active, got %[1]s | 轮换要求 active 状态，实际为 %[1]s", key.State)
			s.fail(ctx, OperationKeyRotate, key.ID, key.Version, err)
			return nil, err
		}
		if len(key.Material) == 0 {
			err := errs.Detail(ErrInvalidMaterial, "key %[1]q has no private material to rotate | 密钥 %[1]q 没有可轮换的私钥材料", key.ID)
			s.fail(ctx, OperationKeyRotate, key.ID, key.Version, err)
			return nil, err
		}
		maxVersion := key.MaxVersion()
		if maxVersion == math.MaxUint32 {
			err := errs.Detail(ErrInvalidState, "key %[1]q has exhausted the 32-bit version space | 密钥 %[1]q 的 32 位版本号空间已耗尽", key.ID)
			s.fail(ctx, OperationKeyRotate, key.ID, key.Version, err)
			return nil, err
		}
		next := maxVersion + 1
		private, public, algorithm, bits, err := generateMaterial(key.Type, key.Bits)
		if err != nil {
			s.fail(ctx, OperationKeyRotate, key.ID, key.Version, err)
			return nil, err
		}
		wrapped, err := s.wrapForStorage(ctx, key.ID, next, private)
		zeroBytes(private)
		if err != nil {
			s.fail(ctx, OperationKeyRotate, key.ID, key.Version, err)
			return nil, err
		}
		now := s.Now()
		previous := key.Version
		if current := key.CurrentVersion(); current != nil {
			current.State = StateDeactivated
			current.DeactivatedAt = now
		}
		version := &KeyVersion{
			Version:        next,
			State:          StateActive,
			Material:       wrapped,
			PublicMaterial: public,
			CreatedAt:      now,
			ActivatedAt:    now,
		}
		key.Versions = append(key.Versions, version)
		sort.Slice(key.Versions, func(i, j int) bool { return key.Versions[i].Version < key.Versions[j].Version })
		key.Version = next
		key.Material = wrapped
		key.PublicMaterial = public
		key.Algorithm = algorithm
		key.Bits = bits
		revision := key.Revision
		if err := s.store.UpdateKey(ctx, key); err != nil {
			key.eraseMaterial()
			zeroBytes(wrapped)
			if errorsIs(err, ErrConflict) {
				continue
			}
			s.fail(ctx, OperationKeyRotate, key.ID, previous, err)
			return nil, err
		}
		key.Revision = revision + 1
		s.succeed(ctx, OperationKeyRotate, key.ID, next, map[string]string{
			"previousVersion": strconvUint32(previous),
			"version":         strconvUint32(next),
			"algorithm":       algorithm,
		})
		view := key.PublicView()
		key.eraseMaterial()
		s.forgetNonceVersion(key.ID, previous)
		return view, nil
	}
	err := errs.Detail(ErrConflict, "key %[1]q changed repeatedly | 密钥 %[1]q 反复变更", target)
	s.fail(ctx, OperationKeyRotate, target, 0, err)
	return nil, err
}

// RotateAllDue rotates every active key whose RotationInterval has elapsed. | RotateAllDue 轮换每个
// 已超过 RotationInterval 的 active 密钥。
//
// now 0 uses the service clock. It returns the number rotated and the first error; remaining keys are
// still processed. Each successful rotation is audited by Rotate. | now 为零时使用服务时钟。它返回
// 轮换数量与首个错误；其余密钥仍会被处理。每次成功轮换由 Rotate 写入审计。
func (s *Service) RotateAllDue(ctx context.Context, now time.Time) (int, error) {
	if now.IsZero() {
		now = s.Now()
	} else {
		now = now.UTC()
	}
	keys, err := s.store.ListKeys(ctx, KeyFilter{State: StateActive})
	if err != nil {
		return 0, err
	}
	rotated := 0
	var firstErr error
	for _, key := range keys {
		if key == nil || key.RotationInterval <= 0 {
			continue
		}
		start := key.CreatedAt
		if current := key.CurrentVersion(); current != nil && !current.CreatedAt.IsZero() {
			start = current.CreatedAt
		}
		if start.IsZero() || now.Before(start.Add(key.RotationInterval)) {
			continue
		}
		if _, err := s.Rotate(ctx, key.ID); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			s.log().Warn("kms: scheduled rotation failed | kms：计划轮换失败",
				ydlog.Str("key_id", key.ID), ydlog.Err(err))
			continue
		}
		rotated++
	}
	return rotated, firstErr
}

// Timing and size constants of the lifecycle layer. | 生命周期层的时间与长度常量。
const (
	// maxAliasLength bounds an alias. | maxAliasLength 限制别名长度。
	maxAliasLength = 255
	// defaultDeletionDelay is used when neither the call nor Config sets a delay. | defaultDeletionDelay
	// 在调用与 Config 均未设置延迟时使用。
	defaultDeletionDelay = 24 * time.Hour
)
