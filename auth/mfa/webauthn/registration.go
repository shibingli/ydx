package webauthn

import (
	"context"
	"crypto/sha256"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
)

// BeginRegistration starts a navigator.credentials.create ceremony. | BeginRegistration 启动 navigator.credentials.create 流程。
//
// The returned CredentialCreationOptions are JSON-serializable and are passed to
// navigator.credentials.create({ publicKey: options.PublicKey }). The returned Ceremony must be stored
// in the user's session and supplied to FinishRegistration. | 返回的 CredentialCreationOptions 可 JSON
// 序列化，传给 navigator.credentials.create({ publicKey: options.PublicKey })。返回的 Ceremony 必须存入
// 用户会话并传给 FinishRegistration。
func (s *Service) BeginRegistration(ctx context.Context, user *auth.User, opts RegistrationOptions) (*CredentialCreationOptions, *Ceremony, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	handle, err := userHandleFor(user)
	if err != nil {
		return nil, nil, err
	}
	userVerification := opts.UserVerification
	if userVerification == "" {
		userVerification = s.userVerif
	}
	if !validUserVerification(userVerification) {
		return nil, nil, errs.Detail(ErrInvalidRequest, "user verification %q | 用户验证 %q", userVerification, userVerification)
	}
	attestation := opts.Attestation
	if attestation == "" {
		attestation = s.attestation
	}
	if !validConveyance(attestation) {
		return nil, nil, errs.Detail(ErrInvalidRequest, "attestation %q | 认证声明 %q", attestation, attestation)
	}
	if !validAttachment(opts.AuthenticatorAttachment) {
		return nil, nil, errs.Detail(ErrInvalidRequest, "authenticator attachment %q | 认证器连接方式 %q",
			opts.AuthenticatorAttachment, opts.AuthenticatorAttachment)
	}
	residentKey := opts.ResidentKey
	if residentKey == "" {
		residentKey = ResidentKeyPreferred
	}
	if !validResidentKey(residentKey) {
		return nil, nil, errs.Detail(ErrInvalidRequest, "resident key %q | 常驻密钥 %q", residentKey, residentKey)
	}
	if opts.RequireResidentKey != nil {
		if *opts.RequireResidentKey {
			residentKey = ResidentKeyRequired
		} else {
			residentKey = ResidentKeyDiscouraged
		}
	}
	algorithms := opts.Algorithms
	if algorithms == nil {
		algorithms = s.algorithms
	} else {
		algorithms, err = validAlgorithms(algorithms)
		if err != nil {
			return nil, nil, err
		}
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = s.timeout
	}
	stored, err := s.credentials.ListByUser(ctx, user.ID)
	if err != nil {
		return nil, nil, errs.WrapDetail(err, ErrInvalidCredential, "credential store list failed | 凭据存储列表失败")
	}
	exclude, excludeIDs, err := mergeExcludeCredentials(stored, opts.ExcludeCredentials)
	if err != nil {
		return nil, nil, err
	}
	extensions, err := registrationExtensions(opts.Extensions, residentKey == ResidentKeyRequired)
	if err != nil {
		return nil, nil, err
	}
	ceremony, err := s.newCeremonyBase(CeremonyRegistration, timeout)
	if err != nil {
		return nil, nil, err
	}
	ceremony.UserID = user.ID
	ceremony.UserHandle = handle
	ceremony.Username = usernameFor(user)
	ceremony.DisplayName = displayNameFor(user)
	ceremony.UserVerification = userVerification
	ceremony.Attestation = attestation
	ceremony.ResidentKey = residentKey
	ceremony.Algorithms = append([]int(nil), algorithms...)
	ceremony.ExcludeCredentialIDs = excludeIDs
	ceremony.CredentialName = validateDescription(opts.Name)
	ceremony.RegistrationExtensions = extensions
	if _, err := s.putCeremony(ctx, ceremony); err != nil {
		return nil, nil, err
	}
	parameters := make([]CredentialParameter, 0, len(algorithms))
	for _, alg := range algorithms {
		parameters = append(parameters, CredentialParameter{Type: "public-key", Alg: alg})
	}
	selection := &AuthenticatorSelection{
		AuthenticatorAttachment: string(opts.AuthenticatorAttachment),
		ResidentKey:             string(residentKey),
		RequireResidentKey:      residentKey == ResidentKeyRequired,
		UserVerification:        string(userVerification),
	}
	creation := &CredentialCreationOptions{PublicKey: PublicKeyCredentialCreationOptions{
		Challenge:              base64.RawURLEncoding.EncodeToString(ceremony.Challenge),
		RP:                     RelyingPartyEntity{ID: s.rpID, Name: s.rpDisplayName},
		User:                   UserEntity{ID: base64.RawURLEncoding.EncodeToString(handle), Name: usernameFor(user), DisplayName: displayNameFor(user)},
		PubKeyCredParams:       parameters,
		Timeout:                timeoutMillis(timeout),
		ExcludeCredentials:     exclude,
		AuthenticatorSelection: selection,
		Attestation:            string(attestation),
		Extensions:             extensions,
	}}
	return creation, ceremony, nil
}

// FinishRegistration verifies a registration response and stores the credential. | FinishRegistration 校验注册响应并保存凭据。
//
// The challenge is consumed before verification, so a failed attempt cannot be retried with the same
// ceremony. | 挑战会在校验前被消费，因此失败尝试不能用同一流程重试。
func (s *Service) FinishRegistration(ctx context.Context, ceremony *Ceremony, response *CredentialCreationResponse) (*Credential, error) {
	if response == nil {
		return nil, errs.Detail(ErrInvalidRequest, "nil registration response | 注册响应为空")
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
	basic, err := ParseClientData(clientDataRaw)
	if err != nil {
		return nil, err
	}
	challengeKey, err := canonicalChallengeKey(basic.Challenge)
	if err != nil {
		return nil, err
	}
	stored, err := s.consumeCeremony(ctx, challengeKey, ceremony)
	if err != nil {
		return nil, err
	}
	if stored.Kind != CeremonyRegistration {
		return nil, errs.Detail(ErrCeremonyMismatch, "ceremony is not a registration ceremony | 流程不是注册流程")
	}
	clientData, err := VerifyClientData(clientDataRaw, stored.clientDataVerifyOptions(ClientDataTypeCreate))
	if err != nil {
		return nil, err
	}
	attestationRaw, err := decodeBase64URLField("attestationObject", response.Response.AttestationObject, true)
	if err != nil {
		return nil, err
	}
	attestationObject, err := ParseAttestationObject(attestationRaw)
	if err != nil {
		return nil, err
	}
	if err := verifyFlagPolicy(attestationObject.AuthData, stored.UserVerification); err != nil {
		return nil, err
	}
	if err := attestationObject.AuthData.VerifyRPIDHash(stored.RPID); err != nil {
		return nil, err
	}
	if !attestationObject.AuthData.Flags.AttestedCredentialData() {
		return nil, errs.Detail(ErrInvalidAuthenticatorData, "registration authData lacks attested credential data | 注册 authData 缺少认证凭据数据")
	}
	if !constantTimeEqual(attestationObject.AuthData.CredentialID, credentialID) {
		return nil, errs.Detail(ErrCredentialIDMismatch, "response credential ID differs from authData | 响应凭据 ID 与 authData 不一致")
	}
	clientDataHash := sha256.Sum256(clientData.Raw)
	result, err := attestationObject.Verify(ctx, clientDataHash[:], s.attestationVerifyOptions(clientData))
	if err != nil {
		return nil, err
	}
	key := attestationObject.AuthData.CredentialPublicKey
	if err := verifyOfferedAlgorithm(key, stored.Algorithms); err != nil {
		return nil, err
	}
	if err := verifyCredentialProtection(attestationObject.AuthData, stored.RegistrationExtensions); err != nil {
		return nil, err
	}
	if descriptorIDsEqual(stored.ExcludeCredentialIDs, credentialID) {
		return nil, errs.Detail(ErrCredentialExists, "client created an excluded credential | 客户端创建了被排除的凭据")
	}
	discoverable := stored.ResidentKey == ResidentKeyRequired
	if credProps := response.ClientExtensionResults.CredProps; credProps != nil {
		if stored.ResidentKey == ResidentKeyRequired && !credProps.RK {
			return nil, errs.Detail(ErrResidentKeyRequired, "client reported a non-discoverable credential | 客户端报告了非可发现凭据")
		}
		discoverable = credProps.RK
	}
	credential := &Credential{
		ID:              append([]byte(nil), credentialID...),
		UserID:          stored.UserID,
		Username:        stored.Username,
		UserDisplayName: stored.DisplayName,
		UserHandle:      append([]byte(nil), stored.UserHandle...),
		PublicKey:       cloneCOSEKey(key),
		SignCount:       attestationObject.AuthData.SignCount,
		AAGUID:          attestationObject.AuthData.AAGUID,
		Transports:      normalizeTransports(response.Response.Transports),
		BackupEligible:  attestationObject.AuthData.Flags.BackupEligible(),
		BackupState:     attestationObject.AuthData.Flags.BackupState(),
		Discoverable:    discoverable,
		Name:            stored.CredentialName,
		AttestationType: result.Type,
		CreatedAt:       s.now(),
	}
	if err := s.credentials.Save(ctx, credential); err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidCredential, "credential store save failed | 凭据存储保存失败")
	}
	return credential, nil
}

// mergeExcludeCredentials combines stored credentials with caller-supplied exclusions. | mergeExcludeCredentials 合并已存凭据与调用方排除项。
func mergeExcludeCredentials(stored []*Credential, extra []CredentialDescriptor) ([]CredentialDescriptor, [][]byte, error) {
	out := make([]CredentialDescriptor, 0, len(stored)+len(extra))
	ids := make([][]byte, 0, len(stored)+len(extra))
	seen := make(map[string]struct{}, len(stored)+len(extra))
	for _, credential := range stored {
		if credential == nil || len(credential.ID) == 0 {
			continue
		}
		key := string(credential.ID)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, CredentialDescriptor{
			Type:       "public-key",
			ID:         base64.RawURLEncoding.EncodeToString(credential.ID),
			Transports: normalizeTransports(credential.Transports),
		})
		ids = append(ids, append([]byte(nil), credential.ID...))
	}
	normalized, extraIDs, err := normalizeDescriptors(extra)
	if err != nil {
		return nil, nil, err
	}
	for i, descriptor := range normalized {
		if _, ok := seen[string(extraIDs[i])]; ok {
			continue
		}
		seen[string(extraIDs[i])] = struct{}{}
		out = append(out, descriptor)
		ids = append(ids, extraIDs[i])
	}
	return out, ids, nil
}

// registrationExtensions copies and validates creation extensions. | registrationExtensions 复制并校验创建扩展。
func registrationExtensions(extensions *RegistrationExtensions, requireResidentKey bool) (*RegistrationExtensions, error) {
	var out *RegistrationExtensions
	if extensions != nil {
		copy := *extensions
		out = &copy
	}
	if out != nil && out.CredentialProtectionPolicy != "" && credentialProtectionRank(out.CredentialProtectionPolicy) < 0 {
		return nil, errs.Detail(ErrInvalidRequest, "credential protection policy %q | 凭据保护策略 %q",
			out.CredentialProtectionPolicy, out.CredentialProtectionPolicy)
	}
	if out != nil && out.EnforceCredentialProtectionPolicy && out.CredentialProtectionPolicy == "" {
		return nil, errs.Detail(ErrInvalidRequest, "credential protection enforcement without a policy | 凭据保护强制开启但未提供策略")
	}
	if requireResidentKey {
		if out == nil {
			out = &RegistrationExtensions{}
		}
		out.CredProps = true
	}
	return out, nil
}

// credentialProtectionRank ranks credProtect policies; -1 marks an unknown policy. | credentialProtectionRank 对 credProtect 策略排序；-1 表示未知策略。
func credentialProtectionRank(policy string) int {
	switch policy {
	case "userVerificationOptional":
		return 0
	case "userVerificationOptionalWithCredentialIDList":
		return 1
	case "userVerificationRequired":
		return 2
	default:
		return -1
	}
}

// verifyCredentialProtection checks an enforced credProtect policy. | verifyCredentialProtection 校验强制的 credProtect 策略。
func verifyCredentialProtection(authData *AuthenticatorData, extensions *RegistrationExtensions) error {
	if extensions == nil || extensions.CredentialProtectionPolicy == "" {
		return nil
	}
	requested := credentialProtectionRank(extensions.CredentialProtectionPolicy)
	actual, present := authData.CredentialProtection()
	if !present {
		if extensions.EnforceCredentialProtectionPolicy {
			return errs.Detail(ErrInvalidCredential, "credProtect extension is missing | credProtect 扩展缺失")
		}
		return nil
	}
	if extensions.EnforceCredentialProtectionPolicy && credentialProtectionRank(actual) < requested {
		return errs.Detail(ErrInvalidCredential, "credProtect policy %q is weaker than the enforced %q | credProtect 策略 %q 弱于强制的 %q",
			actual, extensions.CredentialProtectionPolicy, actual, extensions.CredentialProtectionPolicy)
	}
	return nil
}
