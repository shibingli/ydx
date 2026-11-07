package webauthn

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
)

// auth.Credential.Data keys written by AuthCredentialStore. | AuthCredentialStore 写入的 auth.Credential.Data 键。
//
// Layout:
//
//	credentialId    unpadded base64url raw credential ID (must equal auth.Credential.ID)
//	publicKey       unpadded base64url canonical COSE_Key
//	signCount       unsigned decimal authenticator signature counter
//	aaguid          unpadded base64url 16-byte AAGUID
//	transports      comma-separated transport tokens
//	backupEligible  "true" or "false" BE flag
//	backupState     "true" or "false" BS flag
//	userHandle      optional unpadded base64url WebAuthn user handle
//	discoverable    "true" or "false" discoverable (passkey) marker
//	attestationType "none", "self", "basic", "attca" or "anonca"
//
// The auth.Credential ID is the unpadded base64url credential ID, so credential lookups by
// auth.CredentialStore.GetCredential map directly to WebAuthn credential IDs. | 布局：credentialId
// 为无填充 base64url 原始凭据 ID（必须等于 auth.Credential.ID）；publicKey 为无填充 base64url 规范
// COSE_Key；signCount 为无符号十进制签名计数器；aaguid 为无填充 base64url 16 字节 AAGUID；
// transports 为逗号分隔的传输令牌；backupEligible 与 backupState 为 "true" 或 "false"；userHandle
// 为可选无填充 base64url 用户句柄；discoverable 为 "true" 或 "false" 可发现标记；attestationType
// 为 "none"、"self"、"basic"、"attca" 或 "anonca"。auth.Credential.ID 即无填充 base64url 凭据 ID，
// 因此 auth.CredentialStore.GetCredential 可直接映射到 WebAuthn 凭据 ID。
const (
	// CredentialDataCredentialID is the raw credential ID in base64url. | CredentialDataCredentialID 是 base64url 原始凭据 ID。
	CredentialDataCredentialID = "credentialId"
	// CredentialDataPublicKey is the canonical COSE_Key in base64url. | CredentialDataPublicKey 是 base64url 规范 COSE_Key。
	CredentialDataPublicKey = "publicKey"
	// CredentialDataSignCount is the decimal sign count. | CredentialDataSignCount 是十进制签名计数器。
	CredentialDataSignCount = "signCount"
	// CredentialDataAAGUID is the 16-byte AAGUID in base64url. | CredentialDataAAGUID 是 base64url 16 字节 AAGUID。
	CredentialDataAAGUID = "aaguid"
	// CredentialDataTransports is the comma-separated transport list. | CredentialDataTransports 是逗号分隔的传输列表。
	CredentialDataTransports = "transports"
	// CredentialDataBackupEligible is the BE flag. | CredentialDataBackupEligible 是 BE 标志。
	CredentialDataBackupEligible = "backupEligible"
	// CredentialDataBackupState is the BS flag. | CredentialDataBackupState 是 BS 标志。
	CredentialDataBackupState = "backupState"
	// CredentialDataUserHandle is the optional user handle in base64url. | CredentialDataUserHandle 是可选 base64url 用户句柄。
	CredentialDataUserHandle = "userHandle"
	// CredentialDataDiscoverable marks a discoverable credential. | CredentialDataDiscoverable 标记可发现凭据。
	CredentialDataDiscoverable = "discoverable"
	// CredentialDataAttestationType records the attestation class. | CredentialDataAttestationType 记录认证声明类别。
	CredentialDataAttestationType = "attestationType"
)

// AuthCredentialStore adapts an auth.CredentialStore to CredentialStore. | AuthCredentialStore 把 auth.CredentialStore 适配为 CredentialStore。
//
// Only auth.CredentialWebAuthn records are read or written. See the CredentialData* constants for the
// persisted Data layout. | 仅读取与写入 auth.CredentialWebAuthn 记录。持久化 Data 布局见
// CredentialData* 常量。
type AuthCredentialStore struct {
	store auth.CredentialStore
	mu    sync.Mutex
}

// NewAuthCredentialStore wraps an auth.CredentialStore. | NewAuthCredentialStore 包装 auth.CredentialStore。
func NewAuthCredentialStore(store auth.CredentialStore) (*AuthCredentialStore, error) {
	if store == nil {
		return nil, errs.Detail(ErrInvalidConfig, "nil auth credential store | auth 凭据存储为空")
	}
	return &AuthCredentialStore{store: store}, nil
}

var _ CredentialStore = (*AuthCredentialStore)(nil)

// GetByCredentialID implements CredentialStore. | GetByCredentialID 实现 CredentialStore。
func (a *AuthCredentialStore) GetByCredentialID(ctx context.Context, credentialID []byte) (*Credential, error) {
	if a == nil || a.store == nil {
		return nil, errs.Detail(ErrInvalidConfig, "nil auth credential store | auth 凭据存储为空")
	}
	if len(credentialID) == 0 {
		return nil, errs.Detail(ErrCredentialNotFound, "empty credential ID | 凭据 ID 为空")
	}
	id := base64.RawURLEncoding.EncodeToString(credentialID)
	stored, err := a.store.GetCredential(ctx, id)
	if err != nil {
		if errors.Is(err, auth.ErrCredentialNotFound) {
			return nil, errs.Wrap(err, ErrCredentialNotFound)
		}
		return nil, errs.WrapDetail(err, ErrInvalidCredential, "auth credential lookup failed | auth 凭据查询失败")
	}
	return credentialFromAuth(stored)
}

// Save implements CredentialStore. | Save 实现 CredentialStore。
func (a *AuthCredentialStore) Save(ctx context.Context, credential *Credential) error {
	if a == nil || a.store == nil {
		return errs.Detail(ErrInvalidConfig, "nil auth credential store | auth 凭据存储为空")
	}
	if err := validateCredential(credential); err != nil {
		return err
	}
	record, err := authCredentialFrom(credential)
	if err != nil {
		return err
	}
	if err := a.store.CreateCredential(ctx, record); err != nil {
		if errors.Is(err, auth.ErrCredentialExists) {
			return errs.Wrap(err, ErrCredentialExists)
		}
		return errs.WrapDetail(err, ErrInvalidCredential, "auth credential create failed | auth 凭据创建失败")
	}
	return nil
}

// UpdateSignCount implements CredentialStore. | UpdateSignCount 实现 CredentialStore。
func (a *AuthCredentialStore) UpdateSignCount(ctx context.Context, credentialID []byte, signCount uint32) error {
	return a.updateCredential(ctx, credentialID, func(stored *auth.Credential) {
		stored.Data[CredentialDataSignCount] = strconv.FormatUint(uint64(signCount), 10)
	})
}

// UpdateBackupState implements BackupStateUpdater. | UpdateBackupState 实现 BackupStateUpdater。
func (a *AuthCredentialStore) UpdateBackupState(ctx context.Context, credentialID []byte, backupState bool) error {
	return a.updateCredential(ctx, credentialID, func(stored *auth.Credential) {
		stored.Data[CredentialDataBackupState] = strconv.FormatBool(backupState)
	})
}

// updateCredential applies mutate to a WebAuthn record and persists it. | updateCredential 对 WebAuthn 记录应用 mutate 并持久化。
func (a *AuthCredentialStore) updateCredential(ctx context.Context, credentialID []byte, mutate func(*auth.Credential)) error {
	if a == nil || a.store == nil {
		return errs.Detail(ErrInvalidConfig, "nil auth credential store | auth 凭据存储为空")
	}
	id := base64.RawURLEncoding.EncodeToString(credentialID)
	a.mu.Lock()
	defer a.mu.Unlock()
	stored, err := a.store.GetCredential(ctx, id)
	if err != nil {
		if errors.Is(err, auth.ErrCredentialNotFound) {
			return errs.Wrap(err, ErrCredentialNotFound)
		}
		return errs.WrapDetail(err, ErrInvalidCredential, "auth credential lookup failed | auth 凭据查询失败")
	}
	if stored.Type != auth.CredentialWebAuthn {
		return errs.Detail(ErrInvalidCredential, "auth credential type %q is not webauthn | auth 凭据类型 %q 不是 webauthn", stored.Type, stored.Type)
	}
	if stored.Data == nil {
		stored.Data = make(map[string]string, 4)
	}
	mutate(stored)
	now := time.Now().UTC()
	stored.UpdatedAt = now
	stored.LastUsedAt = now
	if err := a.store.UpdateCredential(ctx, stored); err != nil {
		return errs.WrapDetail(err, ErrInvalidCredential, "auth credential update failed | auth 凭据更新失败")
	}
	return nil
}

// ListByUser implements CredentialStore. | ListByUser 实现 CredentialStore。
func (a *AuthCredentialStore) ListByUser(ctx context.Context, userID string) ([]*Credential, error) {
	if a == nil || a.store == nil {
		return nil, errs.Detail(ErrInvalidConfig, "nil auth credential store | auth 凭据存储为空")
	}
	records, err := a.store.ListCredentialsByUserType(ctx, userID, auth.CredentialWebAuthn)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidCredential, "auth credential list failed | auth 凭据列表失败")
	}
	out := make([]*Credential, 0, len(records))
	for _, record := range records {
		credential, err := credentialFromAuth(record)
		if err != nil {
			return nil, err
		}
		out = append(out, credential)
	}
	return out, nil
}

// authCredentialFrom converts a webauthn Credential to an auth.Credential record. | authCredentialFrom 把 webauthn 凭据转换为 auth.Credential 记录。
func authCredentialFrom(credential *Credential) (*auth.Credential, error) {
	publicKey, err := credential.PublicKey.Encode()
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidCredential, "COSE key encoding failed | COSE 公钥编码失败")
	}
	data := map[string]string{
		CredentialDataCredentialID:    base64.RawURLEncoding.EncodeToString(credential.ID),
		CredentialDataPublicKey:       base64.RawURLEncoding.EncodeToString(publicKey),
		CredentialDataSignCount:       strconv.FormatUint(uint64(credential.SignCount), 10),
		CredentialDataAAGUID:          base64.RawURLEncoding.EncodeToString(credential.AAGUID[:]),
		CredentialDataTransports:      strings.Join(normalizeTransports(credential.Transports), ","),
		CredentialDataBackupEligible:  strconv.FormatBool(credential.BackupEligible),
		CredentialDataBackupState:     strconv.FormatBool(credential.BackupState),
		CredentialDataDiscoverable:    strconv.FormatBool(credential.Discoverable),
		CredentialDataAttestationType: string(credential.AttestationType),
	}
	if len(credential.UserHandle) > 0 {
		data[CredentialDataUserHandle] = base64.RawURLEncoding.EncodeToString(credential.UserHandle)
	}
	now := time.Now().UTC()
	created := credential.CreatedAt
	if created.IsZero() {
		created = now
	}
	return &auth.Credential{
		ID:         base64.RawURLEncoding.EncodeToString(credential.ID),
		UserID:     credential.UserID,
		Type:       auth.CredentialWebAuthn,
		Name:       credential.Name,
		Data:       data,
		Disabled:   credential.Disabled,
		CreatedAt:  created,
		UpdatedAt:  now,
		LastUsedAt: credential.LastUsedAt,
	}, nil
}

// credentialFromAuth converts an auth.Credential record to a webauthn Credential. | credentialFromAuth 把 auth.Credential 记录转换为 webauthn 凭据。
func credentialFromAuth(record *auth.Credential) (*Credential, error) {
	if record == nil {
		return nil, errs.Detail(ErrInvalidCredential, "nil auth credential | auth 凭据为空")
	}
	if record.Type != auth.CredentialWebAuthn {
		return nil, errs.Detail(ErrInvalidCredential, "auth credential type %q is not webauthn | auth 凭据类型 %q 不是 webauthn", record.Type, record.Type)
	}
	id, err := base64.RawURLEncoding.DecodeString(record.ID)
	if err != nil || len(id) == 0 {
		return nil, errs.Detail(ErrInvalidCredential, "auth credential ID is not non-empty base64url | auth 凭据 ID 不是非空 base64url")
	}
	if strings.TrimSpace(record.UserID) == "" {
		return nil, errs.Detail(ErrInvalidCredential, "auth credential user ID is empty | auth 凭据用户 ID 为空")
	}
	if record.Data == nil {
		return nil, errs.Detail(ErrInvalidCredential, "auth credential Data is empty | auth 凭据 Data 为空")
	}
	encodedKey := record.Data[CredentialDataPublicKey]
	if encodedKey == "" {
		return nil, errs.Detail(ErrInvalidCredential, "auth credential lacks %s | auth 凭据缺少 %s", CredentialDataPublicKey, CredentialDataPublicKey)
	}
	keyBytes, err := base64.RawURLEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidCredential, "auth credential %s is not base64url | auth 凭据 %s 不是 base64url", CredentialDataPublicKey, CredentialDataPublicKey)
	}
	publicKey, err := ParseCOSEKey(keyBytes)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidCredential, "auth credential public key is invalid | auth 凭据公钥非法")
	}
	if encodedID := record.Data[CredentialDataCredentialID]; encodedID != "" {
		dataID, err := base64.RawURLEncoding.DecodeString(encodedID)
		if err != nil || !constantTimeEqual(dataID, id) {
			return nil, errs.Detail(ErrCredentialIDMismatch, "auth credential ID and %s differ | auth 凭据 ID 与 %s 不一致", CredentialDataCredentialID, CredentialDataCredentialID)
		}
	}
	var signCount uint32
	if raw := record.Data[CredentialDataSignCount]; raw != "" {
		value, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidCredential, "auth credential signCount is invalid | auth 凭据 signCount 非法")
		}
		signCount = uint32(value)
	}
	var aaguid [16]byte
	if raw := record.Data[CredentialDataAAGUID]; raw != "" {
		value, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil || len(value) != len(aaguid) {
			return nil, errs.Detail(ErrInvalidCredential, "auth credential aaguid is invalid | auth 凭据 aaguid 非法")
		}
		copy(aaguid[:], value)
	}
	var transports []string
	if raw := record.Data[CredentialDataTransports]; raw != "" {
		transports = normalizeTransports(strings.Split(raw, ","))
	}
	backupEligible, err := parseCredentialBool(record.Data[CredentialDataBackupEligible])
	if err != nil {
		return nil, err
	}
	backupState, err := parseCredentialBool(record.Data[CredentialDataBackupState])
	if err != nil {
		return nil, err
	}
	discoverable, err := parseCredentialBool(record.Data[CredentialDataDiscoverable])
	if err != nil {
		return nil, err
	}
	var userHandle []byte
	if raw := record.Data[CredentialDataUserHandle]; raw != "" {
		userHandle, err = base64.RawURLEncoding.DecodeString(raw)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidCredential, "auth credential userHandle is not base64url | auth 凭据 userHandle 不是 base64url")
		}
	}
	attestationType := AttestationType(record.Data[CredentialDataAttestationType])
	switch attestationType {
	case "", AttestationTypeNone, AttestationTypeSelf, AttestationTypeBasic, AttestationTypeAttCA, AttestationTypeAnonCA:
	default:
		return nil, errs.Detail(ErrInvalidCredential, "auth credential attestationType %q | auth 凭据 attestationType %q", attestationType, attestationType)
	}
	return &Credential{
		ID:              id,
		UserID:          record.UserID,
		UserHandle:      userHandle,
		PublicKey:       publicKey,
		SignCount:       signCount,
		AAGUID:          aaguid,
		Transports:      transports,
		BackupEligible:  backupEligible,
		BackupState:     backupState,
		Discoverable:    discoverable,
		Disabled:        record.Disabled,
		Name:            record.Name,
		AttestationType: attestationType,
		CreatedAt:       record.CreatedAt,
		LastUsedAt:      record.LastUsedAt,
	}, nil
}

// parseCredentialBool parses an optional boolean Data value. | parseCredentialBool 解析可选布尔 Data 值。
func parseCredentialBool(raw string) (bool, error) {
	if raw == "" {
		return false, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, errs.WrapDetail(err, ErrInvalidCredential, "credential boolean %q is invalid | 凭据布尔值 %q 非法", raw, raw)
	}
	return value, nil
}
