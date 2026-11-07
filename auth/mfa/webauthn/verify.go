package webauthn

import (
	"context"
	"crypto/sha256"
	"sync"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
)

// assertionPayload is a decoded and challenge-checked authentication response. | assertionPayload 是已解码并校验挑战的认证响应。
type assertionPayload struct {
	credentialID  []byte
	clientData    *ClientData
	authData      *AuthenticatorData
	signature     []byte
	userHandle    []byte
	hasUserHandle bool
}

// canonicalChallengeKey normalizes a client data challenge to the ChallengeStore key. | canonicalChallengeKey 把客户端数据挑战规范化为 ChallengeStore 键。
func canonicalChallengeKey(challenge string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil || len(raw) == 0 {
		return "", errs.Detail(ErrInvalidClientData, "challenge is not non-empty unpadded base64url | 挑战不是非空无填充 base64url")
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// consumeCeremony consumes the challenge and compares the stored ceremony with the caller copy. | consumeCeremony 消费挑战并把存储的流程与调用方副本比较。
func (s *Service) consumeCeremony(ctx context.Context, challenge string, provided *Ceremony) (*Ceremony, error) {
	if provided == nil {
		return nil, errs.Detail(ErrInvalidRequest, "nil ceremony | 流程为空")
	}
	stored, err := s.challenges.Consume(ctx, challenge)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, errs.Detail(ErrChallengeNotFound, "challenge %q | 挑战 %q", challenge, challenge)
	}
	if stored.ID != provided.ID || stored.Kind != provided.Kind {
		return nil, errs.Detail(ErrCeremonyMismatch, "ceremony copy does not match the stored ceremony | 流程副本与存储的流程不匹配")
	}
	if !constantTimeEqual(stored.Challenge, provided.Challenge) {
		return nil, errs.Detail(ErrCeremonyMismatch, "ceremony challenge copy does not match | 流程挑战副本不匹配")
	}
	if stored.UserID != provided.UserID {
		return nil, errs.Detail(ErrCeremonyMismatch, "ceremony user does not match | 流程用户不匹配")
	}
	if !bytesEqual(stored.UserHandle, provided.UserHandle) {
		return nil, errs.Detail(ErrCeremonyMismatch, "ceremony user handle does not match | 流程用户句柄不匹配")
	}
	if !stored.ExpiresAt.IsZero() && s.now().After(stored.ExpiresAt) {
		return nil, errs.Detail(ErrChallengeExpired, "ceremony expired at %s | 流程于 %s 过期",
			stored.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"), stored.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"))
	}
	return stored, nil
}

// bytesEqual compares byte slices treating nil and empty as equal. | bytesEqual 比较字节切片，把 nil 与空视为相等。
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	return constantTimeEqual(a, b)
}

// verifyFlagPolicy enforces the UP flag and the UV requirement. | verifyFlagPolicy 强制 UP 标志与 UV 要求。
func verifyFlagPolicy(authData *AuthenticatorData, requirement UserVerificationRequirement) error {
	if authData == nil {
		return errs.Detail(ErrInvalidAuthenticatorData, "nil authenticator data | 空认证器数据")
	}
	if !authData.Flags.UserPresent() {
		return errs.Detail(ErrUserPresenceRequired, "authenticator did not assert user presence | 认证器未声明用户在场")
	}
	if requirement == UserVerificationRequired && !authData.Flags.UserVerified() {
		return errs.Detail(ErrUserVerificationRequired, "authenticator did not assert user verification | 认证器未声明用户验证")
	}
	return nil
}

// verifyOfferedAlgorithm checks that the credential key algorithm was offered by the ceremony. | verifyOfferedAlgorithm 检查凭据密钥算法是否由流程提供。
func verifyOfferedAlgorithm(key *COSEKey, algorithms []int) error {
	if key == nil {
		return errs.Detail(ErrInvalidCOSEKey, "nil credential key | 凭据密钥为空")
	}
	alg := key.Algorithm()
	if _, ok := HashForAlgorithm(alg); !ok {
		return errs.Detail(ErrUnsupportedAlgorithm, "credential algorithm %d | 凭据算法 %d", alg, alg)
	}
	if !containsInt(algorithms, alg) {
		return errs.Detail(ErrUnsupportedAlgorithm, "credential algorithm %s was not offered | 凭据算法 %s 未在提供列表中", AlgorithmName(alg), AlgorithmName(alg))
	}
	return nil
}

// decodedAssertion is the decoded binary form of an authentication response. | decodedAssertion 是认证响应的解码二进制形式。
type decodedAssertion struct {
	credentialID  []byte
	clientDataRaw []byte
	authData      *AuthenticatorData
	signature     []byte
	userHandle    []byte
	hasUserHandle bool
}

// decodeAssertionResponse decodes the binary fields of an authentication response. | decodeAssertionResponse 解码认证响应的二进制字段。
func decodeAssertionResponse(response *CredentialAssertionResponse) (*decodedAssertion, error) {
	if response == nil {
		return nil, errs.Detail(ErrInvalidRequest, "nil assertion response | 断言响应为空")
	}
	if response.Type != "public-key" {
		return nil, errs.Detail(ErrInvalidRequest, "credential type %q is not public-key | 凭据类型 %q 不是 public-key", response.Type, response.Type)
	}
	credentialID, err := decodeCredentialResponseID(response.ID, response.RawID)
	if err != nil {
		return nil, err
	}
	clientDataRaw, err := decodeBase64URLField("clientDataJSON", response.Response.ClientDataJSON, true)
	if err != nil {
		return nil, err
	}
	authDataRaw, err := decodeBase64URLField("authenticatorData", response.Response.AuthenticatorData, true)
	if err != nil {
		return nil, err
	}
	authData, err := ParseAuthenticatorData(authDataRaw)
	if err != nil {
		return nil, err
	}
	if authData.Flags.AttestedCredentialData() {
		return nil, errs.Detail(ErrInvalidAuthenticatorData, "assertion authData contains attested credential data | 断言 authData 包含认证凭据数据")
	}
	signature, err := decodeBase64URLField("signature", response.Response.Signature, true)
	if err != nil {
		return nil, err
	}
	if len(signature) == 0 {
		return nil, errs.Detail(ErrSignatureInvalid, "empty assertion signature | 断言签名为空")
	}
	var userHandle []byte
	hasUserHandle := response.Response.UserHandle != ""
	if hasUserHandle {
		userHandle, err = decodeBase64URLField("userHandle", response.Response.UserHandle, true)
		if err != nil {
			return nil, err
		}
	}
	return &decodedAssertion{
		credentialID:  credentialID,
		clientDataRaw: clientDataRaw,
		authData:      authData,
		signature:     signature,
		userHandle:    userHandle,
		hasUserHandle: hasUserHandle,
	}, nil
}

// parseAndConsumeAssertion parses an authentication response and consumes its ceremony. | parseAndConsumeAssertion 解析认证响应并消费其流程。
func (s *Service) parseAndConsumeAssertion(ctx context.Context, ceremony *Ceremony, response *CredentialAssertionResponse) (*Ceremony, *assertionPayload, error) {
	decoded, err := decodeAssertionResponse(response)
	if err != nil {
		return nil, nil, err
	}
	basic, err := ParseClientData(decoded.clientDataRaw)
	if err != nil {
		return nil, nil, err
	}
	challengeKey, err := canonicalChallengeKey(basic.Challenge)
	if err != nil {
		return nil, nil, err
	}
	stored, err := s.consumeCeremony(ctx, challengeKey, ceremony)
	if err != nil {
		return nil, nil, err
	}
	if stored.Kind != CeremonyAuthentication {
		return nil, nil, errs.Detail(ErrCeremonyMismatch, "ceremony is not an authentication ceremony | 流程不是认证流程")
	}
	clientData, err := VerifyClientData(decoded.clientDataRaw, stored.clientDataVerifyOptions(ClientDataTypeGet))
	if err != nil {
		return nil, nil, err
	}
	return stored, &assertionPayload{
		credentialID:  decoded.credentialID,
		clientData:    clientData,
		authData:      decoded.authData,
		signature:     decoded.signature,
		userHandle:    decoded.userHandle,
		hasUserHandle: decoded.hasUserHandle,
	}, nil
}

// verifyAssertion verifies an assertion cryptographically without persisting state. | verifyAssertion 以密码学方式校验断言，但不持久化状态。
func (s *Service) verifyAssertion(ceremony *Ceremony, payload *assertionPayload, credential *Credential) error {
	if credential == nil {
		return errs.Detail(ErrInvalidCredential, "nil credential | 凭据为空")
	}
	if credential.Disabled {
		return errs.Detail(ErrCredentialDisabled, "credential is disabled | 凭据已禁用")
	}
	if err := verifyFlagPolicy(payload.authData, ceremony.UserVerification); err != nil {
		return err
	}
	if err := payload.authData.VerifyRPIDHash(ceremony.RPID); err != nil {
		return err
	}
	if payload.authData.Flags.BackupEligible() != credential.BackupEligible {
		return errs.Detail(ErrBackupEligibilityMismatch, "backup eligibility flag changed | 备份资格标志发生变化")
	}
	key := credential.PublicKey
	if key == nil {
		return errs.Detail(ErrInvalidCredential, "credential has no public key | 凭据没有公钥")
	}
	publicKey, err := key.PublicKey()
	if err != nil {
		return errs.WrapDetail(err, ErrInvalidCredential, "credential public key is invalid | 凭据公钥非法")
	}
	clientDataHash := sha256.Sum256(payload.clientData.Raw)
	signed := signedAttestationData(payload.authData.Raw, clientDataHash[:])
	if err := VerifySignature(key.Algorithm(), publicKey, signed, payload.signature); err != nil {
		return errs.WrapDetail(err, ErrSignatureInvalid, "assertion signature is invalid | 断言签名无效")
	}
	expectedHandle := credential.UserHandle
	if len(expectedHandle) == 0 {
		expectedHandle = []byte(credential.UserID)
	}
	if payload.hasUserHandle {
		if !constantTimeEqual(payload.userHandle, expectedHandle) {
			return errs.Detail(ErrUserHandleMismatch, "assertion user handle does not match the credential | 断言用户句柄与凭据不匹配")
		}
	} else if ceremony.Discoverable {
		return errs.Detail(ErrUserHandleMismatch, "discoverable assertion lacks a user handle | 可发现断言缺少用户句柄")
	}
	if !s.counterAccepted(credential.SignCount, payload.authData) {
		return errs.Detail(ErrCloneDetected, "sign count %d did not increase beyond %d under counter policy %q | 在计数器策略 %q 下签名计数器 %d 未超过 %d",
			payload.authData.SignCount, credential.SignCount, s.counterPolicy, s.counterPolicy, payload.authData.SignCount, credential.SignCount)
	}
	return nil
}

// counterAccepted reports whether the assertion counter is accepted for stored under the service
// policy. | counterAccepted 报告在服务策略下断言计数器是否可被 stored 接受。
func (s *Service) counterAccepted(stored uint32, authData *AuthenticatorData) bool {
	return counterAccepted(s.counterPolicy, stored, authData)
}

// completeAssertion verifies the assertion cryptographically and persists the sign count and BS
// flag. | completeAssertion 以密码学方式校验断言并持久化签名计数器与 BS 标志。
//
// The sign count is re-read from the store under a per-credential striped lock so concurrent
// assertions cannot all pass clone detection. When the store implements BackupStateUpdater and the
// asserted BS value changed, the backup state is persisted before the sign count. | 签名计数器在按
// 凭据分片的锁内从存储重新读取，避免并发断言全部通过克隆检测。存储实现 BackupStateUpdater 且断言的
// BS 值发生变化时，先持久化备份状态，再持久化签名计数器。
func (s *Service) completeAssertion(ctx context.Context, ceremony *Ceremony, payload *assertionPayload, credential *Credential) error {
	if err := s.verifyAssertion(ceremony, payload, credential); err != nil {
		return err
	}
	lock := s.signCountLock(credential.ID)
	lock.Lock()
	defer lock.Unlock()
	fresh, err := s.credentials.GetByCredentialID(ctx, credential.ID)
	if err != nil {
		return errs.WrapDetail(err, ErrInvalidCredential, "credential reload failed | 凭据重新读取失败")
	}
	if fresh == nil {
		return errs.Detail(ErrCredentialNotFound, "credential disappeared before sign count update | 签名计数器更新前凭据已消失")
	}
	if fresh.Disabled {
		return errs.Detail(ErrCredentialDisabled, "credential is disabled | 凭据已禁用")
	}
	if !s.counterAccepted(fresh.SignCount, payload.authData) {
		return errs.Detail(ErrCloneDetected, "sign count %d did not increase beyond %d under counter policy %q | 在计数器策略 %q 下签名计数器 %d 未超过 %d",
			payload.authData.SignCount, fresh.SignCount, s.counterPolicy, s.counterPolicy, payload.authData.SignCount, fresh.SignCount)
	}
	backupState := payload.authData.Flags.BackupState()
	if updater, ok := s.credentials.(BackupStateUpdater); ok && fresh.BackupState != backupState {
		if err := updater.UpdateBackupState(ctx, credential.ID, backupState); err != nil {
			return errs.WrapDetail(err, ErrInvalidCredential, "backup state update failed | 备份状态更新失败")
		}
	}
	if err := s.credentials.UpdateSignCount(ctx, credential.ID, payload.authData.SignCount); err != nil {
		return errs.WrapDetail(err, ErrInvalidCredential, "sign count update failed | 签名计数器更新失败")
	}
	credential.SignCount = payload.authData.SignCount
	credential.BackupState = backupState
	credential.LastUsedAt = s.now()
	return nil
}

// signCountLock returns the striped mutex that serializes sign count updates for a credential. |
// signCountLock 返回用于串行化某凭据签名计数器更新的分片互斥锁。
func (s *Service) signCountLock(credentialID []byte) *sync.Mutex {
	hash := uint32(2166136261)
	for _, b := range credentialID {
		hash ^= uint32(b)
		hash *= 16777619
	}
	return &s.signLocks[hash%uint32(len(s.signLocks))]
}

// attestationVerifyOptions builds verification options from the service configuration. | attestationVerifyOptions 从服务配置构建校验选项。
func (s *Service) attestationVerifyOptions(clientData *ClientData) AttestationOptions {
	return AttestationOptions{
		Roots:              s.roots,
		SafetyNetRoots:     s.safetynetRoots,
		AndroidKeyRoots:    s.androidRoots,
		AndroidKeyVerifier: s.androidKey,
		AndroidPackageName: s.androidPackage,
		CurrentTime:        s.now(),
		SafetyNetVerifier:  s.safetynet,
		ClientData:         clientData,
	}
}
