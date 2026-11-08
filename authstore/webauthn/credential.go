package webauthn

import (
	"context"
	"sort"
	"strconv"
	"strings"

	authwebauthn "github.com/shibingli/ydx/auth/mfa/webauthn"
	"github.com/shibingli/ydx/errs"
)

// GetByCredentialID returns a credential by raw credential ID. | GetByCredentialID 按原始凭据 ID
// 返回凭据。
//
// The returned value is a fresh deep copy decoded from Redis, so mutating it never changes the
// stored record or another caller's copy. An unknown or empty ID reports
// webauthn.ErrCredentialNotFound. | 返回值是从 Redis 解码出的全新深拷贝，因此修改它绝不会改变已存
// 记录或其它调用方的副本。未知或空 ID 返回 webauthn.ErrCredentialNotFound。
func (s *Store) GetByCredentialID(ctx context.Context, credentialID []byte) (*authwebauthn.Credential, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	id := credentialIDString(credentialID)
	fields, err := s.client.HGetAll(ctx, s.keys.credential(id)).Result()
	if err != nil {
		return nil, s.backend("get credential", err)
	}
	if len(fields) == 0 {
		return nil, errs.Detail(authwebauthn.ErrCredentialNotFound, "credential %q | 凭据 %q", id, id)
	}
	return credentialFromFields(fields)
}

// Save stores a new credential and returns webauthn.ErrCredentialExists on a duplicate ID.
// | Save 保存新凭据，ID 重复时返回 webauthn.ErrCredentialExists。
//
// The record and its user index membership are written by one Lua script, so two instances cannot
// both create the same credential ID and an index entry never exists without its record. The input
// is validated and serialized, so the store never shares memory with the caller. | 记录及其用户索引
// 成员由单个 Lua 脚本写入，因此两个实例不可能同时创建相同的凭据 ID，索引条目也绝不会脱离记录存在。
// 输入会被校验并序列化，因此存储绝不与调用方共享内存。
func (s *Store) Save(ctx context.Context, credential *authwebauthn.Credential) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := validateCredential(credential); err != nil {
		return err
	}
	id := credentialIDString(credential.ID)
	member := s.keys.credential(id)
	data, err := encodeCredential(credential)
	if err != nil {
		return err
	}
	reply, err := scriptSaveCredential.Run(ctx, s.client,
		[]string{member, s.keys.userIndex(credential.UserID)},
		data,
		strconv.FormatUint(uint64(credential.SignCount), 10),
		flag(credential.BackupState),
		member,
	).Int64()
	if err != nil {
		return s.backend("save credential", err)
	}
	if reply == 0 {
		return errs.Detail(authwebauthn.ErrCredentialExists,
			"credential %q already exists | 凭据 %q 已存在", id, id)
	}
	return nil
}

// UpdateSignCount persists a new authenticator sign count. | UpdateSignCount 持久化新的认证器签名
// 计数器。
//
// The update is a single atomic Lua script and only changes the authoritative counter field, so
// concurrent assertions cannot resurrect an older serialized snapshot. An unknown ID reports
// webauthn.ErrCredentialNotFound. | 更新是单个原子 Lua 脚本，只修改权威计数器字段，因此并发断言不会
// 复活更旧的序列化快照。未知 ID 返回 webauthn.ErrCredentialNotFound。
func (s *Store) UpdateSignCount(ctx context.Context, credentialID []byte, signCount uint32) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	id := credentialIDString(credentialID)
	reply, err := scriptUpdateSignCount.Run(ctx, s.client,
		[]string{s.keys.credential(id)},
		strconv.FormatUint(uint64(signCount), 10),
	).Int64()
	if err != nil {
		return s.backend("update sign count", err)
	}
	if reply == 0 {
		return errs.Detail(authwebauthn.ErrCredentialNotFound, "credential %q | 凭据 %q", id, id)
	}
	return nil
}

// UpdateBackupState persists the current BS flag. | UpdateBackupState 持久化凭据当前的 BS 标志。
//
// It implements the optional webauthn.BackupStateUpdater extension. The update is a single atomic
// Lua script; an unknown ID reports webauthn.ErrCredentialNotFound. | 它实现可选的
// webauthn.BackupStateUpdater 扩展。更新是单个原子 Lua 脚本；未知 ID 返回
// webauthn.ErrCredentialNotFound。
func (s *Store) UpdateBackupState(ctx context.Context, credentialID []byte, backupState bool) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	id := credentialIDString(credentialID)
	reply, err := scriptUpdateBackupState.Run(ctx, s.client,
		[]string{s.keys.credential(id)},
		flag(backupState),
	).Int64()
	if err != nil {
		return s.backend("update backup state", err)
	}
	if reply == 0 {
		return errs.Detail(authwebauthn.ErrCredentialNotFound, "credential %q | 凭据 %q", id, id)
	}
	return nil
}

// ListByUser returns every credential owned by userID. | ListByUser 返回 userID 拥有的全部凭据。
//
// The user index and the credential records share one Redis hash tag, so they live in one cluster
// slot. Every returned value is a fresh deep copy. Results are sorted by creation time and then by
// credential ID, matching the in-memory store. An unknown user returns an empty slice. |
// 用户索引与凭据记录共享同一个 Redis 哈希标签，因此位于同一集群槽位。每个返回值都是全新深拷贝。
// 结果按创建时间与凭据 ID 排序，与内存存储一致。未知用户返回空切片。
func (s *Store) ListByUser(ctx context.Context, userID string) ([]*authwebauthn.Credential, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	members, err := s.client.SMembers(ctx, s.keys.userIndex(userID)).Result()
	if err != nil {
		return nil, s.backend("list user credentials", err)
	}
	out := make([]*authwebauthn.Credential, 0, len(members))
	for _, member := range members {
		fields, err := s.client.HGetAll(ctx, member).Result()
		if err != nil {
			return nil, s.backend("load user credential", err)
		}
		if len(fields) == 0 {
			continue
		}
		credential, err := credentialFromFields(fields)
		if err != nil {
			return nil, err
		}
		out = append(out, credential)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return string(out[i].ID) < string(out[j].ID)
	})
	return out, nil
}

// validateCredential checks the invariants required by every CredentialStore. | validateCredential
// 检查每个 CredentialStore 都必须满足的不变量。
func validateCredential(credential *authwebauthn.Credential) error {
	if credential == nil {
		return errs.Detail(authwebauthn.ErrInvalidCredential, "nil credential | 凭据为空")
	}
	if len(credential.ID) == 0 || len(credential.ID) > maxCredentialIDLength {
		return errs.Detail(authwebauthn.ErrInvalidCredential,
			"credential ID length %d is outside 1..%d | 凭据 ID 长度 %d 超出 1..%d",
			len(credential.ID), maxCredentialIDLength, len(credential.ID), maxCredentialIDLength)
	}
	if strings.TrimSpace(credential.UserID) == "" {
		return errs.Detail(authwebauthn.ErrInvalidCredential, "credential user ID is empty | 凭据用户 ID 为空")
	}
	if credential.PublicKey == nil {
		return errs.Detail(authwebauthn.ErrInvalidCredential, "credential public key is nil | 凭据公钥为空")
	}
	if _, err := credential.PublicKey.PublicKey(); err != nil {
		return errs.WrapDetail(err, authwebauthn.ErrInvalidCredential,
			"credential public key is invalid | 凭据公钥非法")
	}
	return nil
}
