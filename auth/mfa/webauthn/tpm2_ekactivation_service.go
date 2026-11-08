package webauthn

import (
	"context"
	"crypto/rand"
	"sync"
	"time"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
)

// TPMEKActivationEvidence is the optional registration response extension carrying TPM
// endorsement-key credential activation proof. | TPMEKActivationEvidence 是可选注册响应扩展，携带 TPM
// 背书密钥凭据激活证明。
//
// CertInfo is the unpadded base64url encoding of the TPM2B_ATTEST returned by
// TPM2_ActivateCredential. | CertInfo 是 TPM2_ActivateCredential 返回的 TPM2B_ATTEST 的无填充 base64url
// 编码。
type TPMEKActivationEvidence struct {
	// ChallengeID is the identifier returned by BeginTPMEKActivation. | ChallengeID 是
	// BeginTPMEKActivation 返回的标识。
	ChallengeID string `json:"challengeId"`
	// CertInfo is the base64url-encoded TPM2B_ATTEST activation proof. | CertInfo 是 base64url 编码的
	// TPM2B_ATTEST 激活证明。
	CertInfo string `json:"certInfo"`
}

// tpmEKActivationSession holds the server state of one pending activation. |
// tpmEKActivationSession 保存一次待处理激活的服务器状态。
type tpmEKActivationSession struct {
	credential      []byte
	credentialBlob  []byte
	encryptedSecret []byte
	ekPublic        []byte
	ekCertificates  [][]byte
	akPublic        []byte
	aaguid          [16]byte
	userID          string
	expiresAt       time.Time
}

// tpmEKActivationSessionStore is a bounded, single-use TTL store for activation sessions. |
// tpmEKActivationSessionStore 是有界、一次性、带 TTL 的激活会话存储。
type tpmEKActivationSessionStore struct {
	mu       sync.Mutex
	sessions map[string]*tpmEKActivationSession
	max      int
	clock    func() time.Time
}

// newTPMEKActivationSessionStore creates an empty store. | newTPMEKActivationSessionStore 创建空存储。
func newTPMEKActivationSessionStore(max int, clock func() time.Time) *tpmEKActivationSessionStore {
	return &tpmEKActivationSessionStore{
		sessions: make(map[string]*tpmEKActivationSession),
		max:      max,
		clock:    clock,
	}
}

// put stores a session and returns a fresh unguessable identifier. Expired sessions are purged and
// the earliest-expiring session is evicted when the store is full. | put 保存会话并返回新的不可猜测标识。
// 过期会话会被清理，存储已满时淘汰最早到期的会话。
func (s *tpmEKActivationSessionStore) put(session *tpmEKActivationSession) (string, error) {
	if session == nil {
		return "", errs.Detail(ErrEKActivation, "nil EK activation session | EK 激活会话为空")
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", errs.WrapDetail(err, ErrEKActivation, "EK activation challenge generation failed | EK 激活挑战生成失败")
	}
	id := base64.RawURLEncoding.EncodeToString(random)
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, existing := range s.sessions {
		if !now.Before(existing.expiresAt) {
			delete(s.sessions, key)
		}
	}
	if len(s.sessions) >= s.max {
		oldestKey := ""
		var oldest time.Time
		for key, existing := range s.sessions {
			if oldestKey == "" || existing.expiresAt.Before(oldest) {
				oldestKey = key
				oldest = existing.expiresAt
			}
		}
		if oldestKey != "" {
			delete(s.sessions, oldestKey)
		}
	}
	s.sessions[id] = session
	return id, nil
}

// take removes and returns a session. | take 移除并返回会话。
func (s *tpmEKActivationSessionStore) take(id string) (*tpmEKActivationSession, error) {
	s.mu.Lock()
	session, ok := s.sessions[id]
	if ok {
		delete(s.sessions, id)
	}
	s.mu.Unlock()
	if !ok {
		return nil, errs.Detail(ErrEKActivation, "EK activation challenge was not found or was already used | EK 激活挑战不存在或已被使用")
	}
	if !s.now().Before(session.expiresAt) {
		return nil, errs.Detail(ErrEKActivation, "EK activation challenge expired | EK 激活挑战已过期")
	}
	return session, nil
}

// now returns the store clock. | now 返回存储时钟。
func (s *tpmEKActivationSessionStore) now() time.Time {
	clock := s.clock
	if clock == nil {
		clock = time.Now
	}
	return clock().UTC()
}

// BeginTPMEKActivation starts a TPM endorsement-key credential activation. |
// BeginTPMEKActivation 启动 TPM 背书密钥凭据激活。
//
// The request must carry the EK certificate chain, the raw EK and AK TPMT_PUBLIC areas and the
// authenticator AAGUID. The returned challenge is bound to a random server credential, expires
// after Config.ChallengeTTL and can be consumed once. The caller passes CredentialBlob and
// EncryptedSecret to TPM2_ActivateCredential and returns certInfo to FinishTPMEKActivation. |
// 请求必须携带 EK 证书链、原始 EK 与 AK TPMT_PUBLIC 区域及认证器 AAGUID。返回的挑战绑定到随机服务器
// 凭据，在 Config.ChallengeTTL 后过期且只能消费一次。调用方把 CredentialBlob 与 EncryptedSecret 传给
// TPM2_ActivateCredential，并把 certInfo 返回给 FinishTPMEKActivation。
func (s *Service) BeginTPMEKActivation(ctx context.Context, request *TPMEKActivationRequest) (*TPMEKActivationChallenge, error) {
	if s == nil || s.tpmEKActivation == nil || s.tpmEKActivationStore == nil {
		return nil, errs.Detail(ErrInvalidConfig, "TPM EK activation is not configured | 未配置 TPM EK 激活")
	}
	if request == nil {
		return nil, errs.Detail(ErrInvalidRequest, "nil TPM EK activation request | TPM EK 激活请求为空")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := s.now().UTC()
	policy := s.tpmEKActivation
	ekPublic, akName, _, _, err := verifyTPMEKActivationMaterial(
		request.EKPublic, request.AKPublic, request.EKCertificates, request.AAGUID, policy, now)
	if err != nil {
		return nil, err
	}
	hash, ok := TPMHash(ekPublic.Public.NameAlg)
	if !ok {
		return nil, errs.Detail(ErrUnsupportedAlgorithm, "endorsement key name algorithm %#04x | 背书密钥名称算法 %#04x",
			ekPublic.Public.NameAlg, ekPublic.Public.NameAlg)
	}
	credential := make([]byte, hash.Size())
	if _, err := rand.Read(credential); err != nil {
		return nil, errs.WrapDetail(err, ErrEKActivation, "EK activation credential generation failed | EK 激活凭据生成失败")
	}
	made, err := MakeCredential(&ekPublic.Public, akName, credential)
	if err != nil {
		return nil, err
	}
	session := &tpmEKActivationSession{
		credential:      credential,
		credentialBlob:  append([]byte(nil), made.CredentialBlob.Buffer...),
		encryptedSecret: append([]byte(nil), made.Secret.Buffer...),
		ekPublic:        append([]byte(nil), request.EKPublic...),
		ekCertificates:  cloneByteSlices(request.EKCertificates),
		akPublic:        append([]byte(nil), request.AKPublic...),
		aaguid:          request.AAGUID,
		userID:          request.UserID,
		expiresAt:       now.Add(policy.ChallengeTTL),
	}
	id, err := s.tpmEKActivationStore.put(session)
	if err != nil {
		return nil, err
	}
	return &TPMEKActivationChallenge{
		ID:              id,
		CredentialBlob:  append([]byte(nil), session.credentialBlob...),
		EncryptedSecret: append([]byte(nil), session.encryptedSecret...),
		AKName:          append([]byte(nil), akName.Name...),
		AAGUID:          request.AAGUID,
		ExpiresAt:       session.expiresAt,
	}, nil
}

// FinishTPMEKActivation verifies a TPM2_ActivateCredential certInfo against a pending challenge. |
// FinishTPMEKActivation 针对待处理挑战校验 TPM2_ActivateCredential certInfo。
//
// The challenge is consumed even when verification fails. | 即使校验失败，挑战也会被消费。
func (s *Service) FinishTPMEKActivation(ctx context.Context, challengeID string, certInfo []byte) (*TPMEKActivationResult, error) {
	if s == nil || s.tpmEKActivation == nil || s.tpmEKActivationStore == nil {
		return nil, errs.Detail(ErrInvalidConfig, "TPM EK activation is not configured | 未配置 TPM EK 激活")
	}
	if len(challengeID) == 0 || len(challengeID) > maxTPMEKActivationChallengeID {
		return nil, errs.Detail(ErrInvalidRequest, "EK activation challenge identifier has %d bytes | EK 激活挑战标识为 %d 字节",
			len(challengeID), len(challengeID))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	session, err := s.tpmEKActivationStore.take(challengeID)
	if err != nil {
		return nil, err
	}
	verification := &TPMEKActivationVerification{
		EKCertificates:  cloneByteSlices(session.ekCertificates),
		EKPublic:        append([]byte(nil), session.ekPublic...),
		AKPublic:        append([]byte(nil), session.akPublic...),
		AAGUID:          session.aaguid,
		Credential:      append([]byte(nil), session.credential...),
		CredentialBlob:  append([]byte(nil), session.credentialBlob...),
		EncryptedSecret: append([]byte(nil), session.encryptedSecret...),
		CertInfo:        append([]byte(nil), certInfo...),
		Now:             s.now().UTC(),
	}
	return VerifyEKActivation(ctx, verification, s.tpmEKActivation)
}

// verifyRegistrationEKActivation enforces optional EK activation evidence during registration. |
// verifyRegistrationEKActivation 在注册期间强制执行可选的 EK 激活证据。
func (s *Service) verifyRegistrationEKActivation(ctx context.Context, userID string, object *AttestationObject, result *AttestationResult, evidence *TPMEKActivationEvidence) error {
	if s == nil || s.tpmEKActivation == nil {
		return nil
	}
	if evidence == nil || (evidence.ChallengeID == "" && evidence.CertInfo == "") {
		if s.tpmEKActivation.RequiredForTPMAttestation && object.Format == FormatTPM {
			return errs.Detail(ErrEKActivation, "tpm attestation requires TPM EK activation evidence | tpm 认证声明要求 TPM EK 激活证据")
		}
		return nil
	}
	if object.Format != FormatTPM {
		return errs.Detail(ErrEKActivation, "TPM EK activation evidence requires the tpm attestation format | TPM EK 激活证据要求 tpm 认证声明格式")
	}
	if len(evidence.ChallengeID) == 0 || len(evidence.ChallengeID) > maxTPMEKActivationChallengeID {
		return errs.Detail(ErrInvalidRequest, "EK activation challenge identifier has %d bytes | EK 激活挑战标识为 %d 字节",
			len(evidence.ChallengeID), len(evidence.ChallengeID))
	}
	certInfo, err := decodeBase64URLField("tpmEkActivation.certInfo", evidence.CertInfo, true)
	if err != nil {
		return err
	}
	session, err := s.tpmEKActivationStore.take(evidence.ChallengeID)
	if err != nil {
		return err
	}
	if session.userID != "" && session.userID != userID {
		return errs.Detail(ErrEKActivation, "EK activation challenge belongs to another user | EK 激活挑战属于其他用户")
	}
	if len(result.TrustPath) == 0 {
		return errs.Detail(ErrEKActivation, "tpm attestation lacks an AIK certificate for EK activation binding | tpm 认证声明缺少用于 EK 激活绑定的 AIK 证书")
	}
	akPublic, err := ParseTPMTPublic(session.akPublic)
	if err != nil {
		return err
	}
	akKey, err := akPublic.PublicKey()
	if err != nil {
		return err
	}
	if !samePublicKey(akKey, result.TrustPath[0].PublicKey) {
		return errs.Detail(ErrEKActivation, "EK activation attestation key differs from the registration AIK certificate | EK 激活认证密钥与注册 AIK 证书不一致")
	}
	if session.aaguid != result.AAGUID {
		return errs.Detail(ErrEKActivation, "EK activation AAGUID differs from the registration AAGUID | EK 激活 AAGUID 与注册 AAGUID 不一致")
	}
	activation, err := VerifyEKActivation(ctx, &TPMEKActivationVerification{
		EKCertificates:  cloneByteSlices(session.ekCertificates),
		EKPublic:        append([]byte(nil), session.ekPublic...),
		AKPublic:        append([]byte(nil), session.akPublic...),
		AAGUID:          session.aaguid,
		Credential:      append([]byte(nil), session.credential...),
		CredentialBlob:  append([]byte(nil), session.credentialBlob...),
		EncryptedSecret: append([]byte(nil), session.encryptedSecret...),
		CertInfo:        certInfo,
		Now:             s.now().UTC(),
	}, s.tpmEKActivation)
	if err != nil {
		return err
	}
	result.EKActivation = activation
	return nil
}

// cloneByteSlices deep-copies a byte-slice slice. | cloneByteSlices 深拷贝字节切片切片。
func cloneByteSlices(values [][]byte) [][]byte {
	if values == nil {
		return nil
	}
	out := make([][]byte, len(values))
	for index, value := range values {
		out[index] = append([]byte(nil), value...)
	}
	return out
}
