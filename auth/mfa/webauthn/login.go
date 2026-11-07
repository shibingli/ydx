package webauthn

import (
	"context"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
)

// BeginLogin starts a user-bound navigator.credentials.get ceremony. | BeginLogin 启动用户绑定的 navigator.credentials.get 流程。
//
// The returned Ceremony must be stored in the user's session and supplied to FinishLogin. | 返回的
// Ceremony 必须存入用户会话并传给 FinishLogin。
func (s *Service) BeginLogin(ctx context.Context, user *auth.User, opts LoginOptions) (*CredentialRequestOptions, *Ceremony, error) {
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
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = s.timeout
	}
	var descriptors []CredentialDescriptor
	var allowIDs [][]byte
	if len(opts.AllowCredentials) > 0 {
		descriptors, allowIDs, err = normalizeDescriptors(opts.AllowCredentials)
		if err != nil {
			return nil, nil, err
		}
	} else {
		credentials, err := s.credentials.ListByUser(ctx, user.ID)
		if err != nil {
			return nil, nil, errs.WrapDetail(err, ErrInvalidCredential, "credential store list failed | 凭据存储列表失败")
		}
		for _, credential := range credentials {
			if credential == nil || credential.Disabled || len(credential.ID) == 0 {
				continue
			}
			descriptors = append(descriptors, credential.Descriptor())
			allowIDs = append(allowIDs, append([]byte(nil), credential.ID...))
		}
	}
	if len(descriptors) == 0 {
		return nil, nil, errs.Detail(ErrCredentialNotFound, "user has no authentication credentials | 用户没有认证凭据")
	}
	extensions := cloneAuthenticationExtensions(opts.Extensions)
	ceremony, err := s.newCeremonyBase(CeremonyAuthentication, timeout)
	if err != nil {
		return nil, nil, err
	}
	ceremony.UserID = user.ID
	ceremony.UserHandle = handle
	ceremony.Username = usernameFor(user)
	ceremony.DisplayName = displayNameFor(user)
	ceremony.UserVerification = userVerification
	ceremony.AllowCredentialIDs = allowIDs
	ceremony.AuthenticationExtensions = extensions
	if _, err := s.putCeremony(ctx, ceremony); err != nil {
		return nil, nil, err
	}
	options := &CredentialRequestOptions{PublicKey: PublicKeyCredentialRequestOptions{
		Challenge:        base64.RawURLEncoding.EncodeToString(ceremony.Challenge),
		Timeout:          timeoutMillis(timeout),
		RPID:             s.rpID,
		AllowCredentials: descriptors,
		UserVerification: string(userVerification),
		Extensions:       extensions,
	}}
	return options, ceremony, nil
}

// FinishLogin verifies a user-bound authentication response. | FinishLogin 校验用户绑定的认证响应。
//
// The challenge is consumed before verification. Sign count regression fails with ErrCloneDetected;
// the new sign count is persisted before success is returned. | 挑战在校验前消费。签名计数器回退会返回
// ErrCloneDetected；新计数器在成功返回前持久化。
func (s *Service) FinishLogin(ctx context.Context, ceremony *Ceremony, response *CredentialAssertionResponse) (*Credential, error) {
	stored, payload, err := s.parseAndConsumeAssertion(ctx, ceremony, response)
	if err != nil {
		return nil, err
	}
	if stored.Discoverable {
		return nil, errs.Detail(ErrCeremonyMismatch, "ceremony is a discoverable login | 流程是可发现登录")
	}
	if stored.UserID == "" {
		return nil, errs.Detail(ErrCeremonyMismatch, "user-bound login ceremony has no user | 用户绑定登录流程没有用户")
	}
	credential, err := s.credentials.GetByCredentialID(ctx, payload.credentialID)
	if err != nil {
		return nil, err
	}
	if credential.UserID != stored.UserID {
		return nil, errs.Detail(ErrUserHandleMismatch, "credential belongs to another user | 凭据属于其他用户")
	}
	if len(stored.AllowCredentialIDs) > 0 && !descriptorIDsEqual(stored.AllowCredentialIDs, payload.credentialID) {
		return nil, errs.Detail(ErrCredentialNotFound, "credential is not allowed by this ceremony | 该流程不允许此凭据")
	}
	if err := s.completeAssertion(ctx, stored, payload, credential); err != nil {
		return nil, err
	}
	return credential, nil
}

// BeginDiscoverableLogin starts a usernameless navigator.credentials.get ceremony. | BeginDiscoverableLogin 启动无用户名的 navigator.credentials.get 流程。
//
// AllowCredentials is left empty so the client can select a discoverable credential. | AllowCredentials
// 留空，以便客户端选择可发现凭据。
func (s *Service) BeginDiscoverableLogin(ctx context.Context, opts DiscoverableLoginOptions) (*CredentialRequestOptions, *Ceremony, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	userVerification := opts.UserVerification
	if userVerification == "" {
		userVerification = s.userVerif
	}
	if !validUserVerification(userVerification) {
		return nil, nil, errs.Detail(ErrInvalidRequest, "user verification %q | 用户验证 %q", userVerification, userVerification)
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = s.timeout
	}
	extensions := cloneAuthenticationExtensions(opts.Extensions)
	ceremony, err := s.newCeremonyBase(CeremonyAuthentication, timeout)
	if err != nil {
		return nil, nil, err
	}
	ceremony.UserVerification = userVerification
	ceremony.Discoverable = true
	ceremony.AuthenticationExtensions = extensions
	if _, err := s.putCeremony(ctx, ceremony); err != nil {
		return nil, nil, err
	}
	options := &CredentialRequestOptions{PublicKey: PublicKeyCredentialRequestOptions{
		Challenge:        base64.RawURLEncoding.EncodeToString(ceremony.Challenge),
		Timeout:          timeoutMillis(timeout),
		RPID:             s.rpID,
		UserVerification: string(userVerification),
		Extensions:       extensions,
	}}
	return options, ceremony, nil
}

// FinishDiscoverableLogin verifies a usernameless authentication response. | FinishDiscoverableLogin 校验无用户名认证响应。
//
// It returns the credential and the raw user handle asserted by the authenticator. | 它返回凭据与认证器
// 声明的原始用户句柄。
func (s *Service) FinishDiscoverableLogin(ctx context.Context, ceremony *Ceremony, response *CredentialAssertionResponse) (*Credential, []byte, error) {
	stored, payload, err := s.parseAndConsumeAssertion(ctx, ceremony, response)
	if err != nil {
		return nil, nil, err
	}
	if !stored.Discoverable {
		return nil, nil, errs.Detail(ErrCeremonyMismatch, "ceremony is not a discoverable login | 流程不是可发现登录")
	}
	if !payload.hasUserHandle || len(payload.userHandle) == 0 {
		return nil, nil, errs.Detail(ErrUserHandleMismatch, "discoverable assertion lacks a user handle | 可发现断言缺少用户句柄")
	}
	credential, err := s.credentials.GetByCredentialID(ctx, payload.credentialID)
	if err != nil {
		return nil, nil, err
	}
	if err := s.completeAssertion(ctx, stored, payload, credential); err != nil {
		return nil, nil, err
	}
	return credential, append([]byte(nil), payload.userHandle...), nil
}

// cloneAuthenticationExtensions deep-copies authentication extensions. | cloneAuthenticationExtensions 深拷贝认证扩展。
func cloneAuthenticationExtensions(extensions *AuthenticationExtensions) *AuthenticationExtensions {
	if extensions == nil {
		return nil
	}
	out := *extensions
	if extensions.HMACGetSecret != nil {
		input := *extensions.HMACGetSecret
		out.HMACGetSecret = &input
	}
	return &out
}
