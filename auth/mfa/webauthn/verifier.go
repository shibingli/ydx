package webauthn

import (
	"context"
	"strconv"
	"strings"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// Verifier adapts a Server to auth.MFAVerifier for auth.CredentialWebAuthn. | Verifier 把 Server
// 适配为 auth.CredentialWebAuthn 的 auth.MFAVerifier。
//
// The caller starts an authentication ceremony with BeginLogin or BeginDiscoverableLogin and stores
// the returned Ceremony in Config.ChallengeStore; Verify consumes that challenge, verifies the
// serialized CredentialAssertionResponse against credential, and on success updates
// credential.Data[CredentialDataSignCount] and credential.Data[CredentialDataBackupState]. The
// auth.Service persists the mutated record after Verify returns true, so callers must not share one
// *auth.Credential value across concurrent verifications. | 调用方使用 BeginLogin 或
// BeginDiscoverableLogin 启动认证流程，并把返回的 Ceremony 存入 Config.ChallengeStore；Verify
// 消费该挑战，用 credential 校验序列化的 CredentialAssertionResponse，成功时更新
// credential.Data[CredentialDataSignCount] 与 credential.Data[CredentialDataBackupState]。
// auth.Service 会在 Verify 返回 true 后持久化被修改的记录，因此调用方不得在并发校验之间共享同一个
// *auth.Credential 值。
type Verifier struct {
	service *Service
}

// The compile-time proof that Verifier implements auth.MFAVerifier. | 编译期证明 Verifier 实现了
// auth.MFAVerifier。
var _ auth.MFAVerifier = (*Verifier)(nil)

// NewVerifier returns an auth.MFAVerifier backed by service. | NewVerifier 返回由 service 支撑的
// auth.MFAVerifier。
func NewVerifier(service *Service) (*Verifier, error) {
	if service == nil {
		return nil, errs.Detail(ErrInvalidConfig, "nil webauthn service | WebAuthn 服务为空")
	}
	return &Verifier{service: service}, nil
}

// Verify implements auth.MFAVerifier. | Verify 实现 auth.MFAVerifier。
//
// An empty response returns false with a nil error. Malformed JSON, unknown challenges, invalid
// client data and failed cryptographic checks return false with an error that matches
// auth.ErrMFAInvalid. | 空响应返回 false 且错误为空。非法 JSON、未知挑战、非法客户端数据与失败的
// 密码学校验返回 false，并附带可匹配 auth.ErrMFAInvalid 的错误。
func (v *Verifier) Verify(ctx context.Context, user *auth.User, credential *auth.Credential, response string) (bool, error) {
	if v == nil || v.service == nil {
		return false, errs.Detail(auth.ErrMFAInvalid, "nil webauthn verifier | WebAuthn 校验器为空")
	}
	if credential == nil {
		return false, auth.ErrCredentialNotFound
	}
	if err := mfaCredentialPrecondition(user, credential); err != nil {
		return false, err
	}
	response = strings.TrimSpace(response)
	if response == "" {
		return false, nil
	}
	var assertion CredentialAssertionResponse
	if err := json.Unmarshal([]byte(response), &assertion); err != nil {
		return false, mfaError(err, credential.ID, "response is not a valid CredentialAssertionResponse | 响应不是合法的 CredentialAssertionResponse")
	}
	webCredential, err := credentialFromAuth(credential)
	if err != nil {
		return false, mfaError(err, credential.ID, "stored credential is invalid | 存储的凭据非法")
	}
	decoded, err := decodeAssertionResponse(&assertion)
	if err != nil {
		return false, mfaError(err, credential.ID, "assertion response is invalid | 断言响应非法")
	}
	if !constantTimeEqual(decoded.credentialID, webCredential.ID) {
		return false, mfaError(errs.Detail(ErrCredentialIDMismatch,
			"assertion credential ID does not match the stored credential | 断言凭据 ID 与存储凭据不匹配"),
			credential.ID, "")
	}
	basic, err := ParseClientData(decoded.clientDataRaw)
	if err != nil {
		return false, mfaError(err, credential.ID, "")
	}
	challengeKey, err := canonicalChallengeKey(basic.Challenge)
	if err != nil {
		return false, mfaError(err, credential.ID, "")
	}
	stored, err := v.service.challenges.Consume(ctx, challengeKey)
	if err != nil {
		return false, mfaError(err, credential.ID, "challenge was not issued or was already used | 挑战未签发或已被使用")
	}
	if stored == nil {
		return false, mfaError(errs.Detail(ErrChallengeNotFound, "challenge %q | 挑战 %q", challengeKey, challengeKey),
			credential.ID, "")
	}
	if stored.Kind != CeremonyAuthentication {
		return false, mfaError(errs.Detail(ErrCeremonyMismatch, "ceremony is not an authentication ceremony | 流程不是认证流程"),
			credential.ID, "")
	}
	if !stored.ExpiresAt.IsZero() && v.service.now().After(stored.ExpiresAt) {
		return false, mfaError(errs.Detail(ErrChallengeExpired, "ceremony expired at %s | 流程于 %s 过期",
			stored.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"), stored.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")),
			credential.ID, "")
	}
	if !stored.Discoverable && stored.UserID != "" && stored.UserID != credential.UserID {
		return false, mfaError(errs.Detail(ErrCeremonyMismatch, "ceremony belongs to another user | 流程属于其他用户"),
			credential.ID, "")
	}
	if len(stored.AllowCredentialIDs) > 0 && !descriptorIDsEqual(stored.AllowCredentialIDs, decoded.credentialID) {
		return false, mfaError(errs.Detail(ErrCredentialNotFound, "credential is not allowed by this ceremony | 该流程不允许此凭据"),
			credential.ID, "")
	}
	clientData, err := VerifyClientData(decoded.clientDataRaw, stored.clientDataVerifyOptions(ClientDataTypeGet))
	if err != nil {
		return false, mfaError(err, credential.ID, "")
	}
	payload := &assertionPayload{
		credentialID:  decoded.credentialID,
		clientData:    clientData,
		authData:      decoded.authData,
		signature:     decoded.signature,
		userHandle:    decoded.userHandle,
		hasUserHandle: decoded.hasUserHandle,
	}
	if err := v.service.verifyAssertion(stored, payload, webCredential); err != nil {
		return false, mfaError(err, credential.ID, "")
	}
	if credential.Data == nil {
		credential.Data = make(map[string]string, 2)
	}
	credential.Data[CredentialDataSignCount] = strconv.FormatUint(uint64(payload.authData.SignCount), 10)
	credential.Data[CredentialDataBackupState] = strconv.FormatBool(payload.authData.Flags.BackupState())
	return true, nil
}

// mfaCredentialPrecondition validates the user and credential arguments. | mfaCredentialPrecondition 校验 user 与 credential 参数。
func mfaCredentialPrecondition(user *auth.User, credential *auth.Credential) error {
	if credential.Type != auth.CredentialWebAuthn {
		return errs.Detail(auth.ErrMFAInvalid, "credential %s type %q is not webauthn | 凭据 %s 类型 %q 不是 webauthn",
			credential.ID, credential.Type, credential.ID, credential.Type)
	}
	if credential.Disabled {
		return errs.Detail(auth.ErrMFAInvalid, "credential %s is disabled | 凭据 %s 已禁用", credential.ID, credential.ID)
	}
	if user == nil {
		return nil
	}
	if user.ID == "" {
		return errs.Detail(auth.ErrMFAInvalid, "user ID is empty | 用户 ID 为空")
	}
	if user.ID != credential.UserID {
		return errs.Detail(auth.ErrMFAInvalid, "credential %s belongs to another user | 凭据 %s 属于其他用户", credential.ID, credential.ID)
	}
	return nil
}

// mfaError classifies an assertion failure as auth.ErrMFAInvalid without discarding the cause. | mfaError 把断言失败归类为 auth.ErrMFAInvalid，同时保留原因。
func mfaError(err error, credentialID, detail string) error {
	if detail == "" {
		return errs.WrapDetail(err, auth.ErrMFAInvalid, "credential %s | 凭据 %s", credentialID, credentialID)
	}
	return errs.WrapDetail(err, auth.ErrMFAInvalid, "credential %s: %s | 凭据 %s：%s", credentialID, detail, credentialID, detail)
}
