package saml

import (
	"context"
	"errors"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/xml"
)

// SignatureVerifier verifies an XMLDSig signature over the element with elementID. | SignatureVerifier
// 校验 elementID 元素上的 XMLDSig 签名。
type SignatureVerifier interface {
	// VerifySignature returns nil only when a valid signature covers the expected element. | VerifySignature
	// 仅在有效签名覆盖预期元素时返回 nil。
	VerifySignature(ctx context.Context, document []byte, elementID string) error
}

// SignatureVerifierFunc adapts a function to SignatureVerifier. | SignatureVerifierFunc 把函数适配为 SignatureVerifier。
type SignatureVerifierFunc func(ctx context.Context, document []byte, elementID string) error

// VerifySignature calls f. | VerifySignature 调用 f。
func (f SignatureVerifierFunc) VerifySignature(ctx context.Context, document []byte, elementID string) error {
	return f(ctx, document, elementID)
}

// EncryptedAssertionDecryptor decrypts an EncryptedAssertion into Assertion XML. | EncryptedAssertionDecryptor
// 把 EncryptedAssertion 解密为 Assertion XML。
type EncryptedAssertionDecryptor interface {
	// DecryptAssertion returns the decrypted assertion XML. | DecryptAssertion 返回解密后的断言 XML。
	DecryptAssertion(ctx context.Context, encrypted *EncryptedAssertion) ([]byte, error)
}

// MetadataResolver resolves an entity's metadata. | MetadataResolver 解析实体元数据。
type MetadataResolver interface {
	// Resolve returns metadata for entityID. | Resolve 返回 entityID 的元数据。
	Resolve(ctx context.Context, entityID string) (*EntityDescriptor, error)
}

// ResponseValidationOptions configures ValidateResponse. | ResponseValidationOptions 配置 ValidateResponse。
type ResponseValidationOptions struct {
	// SPEntityID is the local service-provider entity ID. | SPEntityID 是本地服务提供方实体标识。
	SPEntityID string
	// ACSURL is the local assertion consumer URL. | ACSURL 是本地断言消费 URL。
	ACSURL string
	// IDPEntityID is the expected identity-provider entity ID. | IDPEntityID 是期望的身份提供方实体标识。
	IDPEntityID string
	// Store correlates requests and rejects replayed assertions. A response carrying a signature or
	// requiring InResponseTo should always configure a Store. | Store 关联请求并拒绝重放断言。携带签名
	// 或要求 InResponseTo 的响应应始终配置 Store。
	Store Store
	// AssertionReplayStore enforces Conditions/OneTimeUse. When nil, Store is used when it implements
	// AssertionReplayStore. When neither is available, OneTimeUse assertions are rejected unless
	// AllowOneTimeUseWithoutReplayStore is set. | AssertionReplayStore 强制 Conditions/OneTimeUse。
	// 为空时若 Store 实现 AssertionReplayStore 则使用它。两者均不可用时拒绝 OneTimeUse 断言，除非
	// 设置 AllowOneTimeUseWithoutReplayStore。
	AssertionReplayStore AssertionReplayStore
	// AllowOneTimeUseWithoutReplayStore accepts OneTimeUse assertions without replay detection when
	// no replay store is available. The default false fails closed. | AllowOneTimeUseWithoutReplayStore
	// 在没有重放存储时接受 OneTimeUse 断言且不检测重放。默认 false 失败关闭。
	AllowOneTimeUseWithoutReplayStore bool
	// SignatureVerifier verifies XML signatures; nil means present signatures are rejected because
	// they cannot be checked. | SignatureVerifier 校验 XML 签名；为空时因无法校验而拒绝存在的签名。
	SignatureVerifier SignatureVerifier
	// Decryptor decrypts EncryptedAssertion elements. | Decryptor 解密 EncryptedAssertion 元素。
	Decryptor EncryptedAssertionDecryptor
	// RequireSignedResponse requires a verified signature on the Response element. | RequireSignedResponse
	// 要求 Response 元素上存在已校验的签名。
	RequireSignedResponse bool
	// RequireSignedAssertion requires a verified signature on the assertion or on the enclosing
	// response. | RequireSignedAssertion 要求断言或外层响应上存在已校验的签名。
	RequireSignedAssertion bool
	// RequireInResponseTo requires a matching outstanding request. | RequireInResponseTo 要求匹配的未完成请求。
	RequireInResponseTo bool
	// RequireSubjectConfirmation requires a bearer SubjectConfirmation. | RequireSubjectConfirmation
	// 要求承载 SubjectConfirmation。
	RequireSubjectConfirmation bool
	// ClockSkew is the tolerated clock difference; zero means two minutes. | ClockSkew 是容忍的时钟差；零值表示 2 分钟。
	ClockSkew time.Duration
	// MaxIssueAge rejects messages issued longer ago than this; zero disables the check. | MaxIssueAge
	// 拒绝签发时间早于此时长的消息；零值禁用。
	MaxIssueAge time.Duration
	// AllowedNameIDFormats restricts the accepted NameID formats. | AllowedNameIDFormats 限定接受的 NameID 格式。
	AllowedNameIDFormats []string
	// Now overrides the clock. | Now 替换时钟。
	Now func() time.Time
}

// ValidationResult is a validated assertion. | ValidationResult 是已校验断言。
type ValidationResult struct {
	// Response is the parsed protocol response. | Response 是解析后的协议响应。
	Response *Response
	// Assertion is the validated assertion. | Assertion 是已校验断言。
	Assertion *Assertion
	// Principal is the authenticated principal. | Principal 是已认证主体。
	Principal *auth.Principal
	// Attributes is the multi-value attribute map. | Attributes 是多值属性映射。
	Attributes map[string][]string
	// NameID is the assertion subject identifier. | NameID 是断言主体标识。
	NameID string
	// SessionIndex is the assertion session index. | SessionIndex 是断言的会话索引。
	SessionIndex string
	// RelayState is the relay state from the correlated request. | RelayState 是关联请求中的转发状态。
	RelayState string
}

// assertionEntry couples a parsed assertion with the exact bytes that carry its signature. |
// assertionEntry 把已解析断言与其签名所覆盖的精确字节关联起来。
type assertionEntry struct {
	assertion *Assertion
	raw       []byte
	verified  bool
	encrypted bool
}

// ValidateResponse parses, verifies and validates a SAML Response. Every signature that is present
// is verified before the covered data is used; a signature that cannot be verified is an error. |
// ValidateResponse 解析、验签并校验 SAML Response。所有存在的签名都会在数据被使用前校验；无法校验
// 的签名视为错误。
func ValidateResponse(ctx context.Context, raw []byte, opts ResponseValidationOptions) (*ValidationResult, error) {
	var response Response
	if err := xml.Unmarshal(raw, &response); err != nil {
		return nil, errs.Wrap(err, ErrInvalidResponse)
	}
	now := Now(opts.Now)
	skew := opts.ClockSkew
	if skew <= 0 {
		skew = 2 * time.Minute
	}
	if response.Version != Version {
		return nil, errs.Detail(ErrInvalidResponse, "unsupported version %[1]q | 不支持的版本 %[1]q", response.Version)
	}
	if response.ID == "" {
		return nil, errs.Detail(ErrInvalidResponse, "response ID is missing | 缺少响应 ID")
	}
	if err := validateProtocolInstant("response", response.IssueInstant, now, skew, opts.MaxIssueAge, ErrInvalidResponse); err != nil {
		return nil, err
	}
	if err := validateStatus(response.Status); err != nil {
		return nil, err
	}
	if response.Issuer == nil || response.Issuer.Value == "" {
		return nil, errs.Detail(ErrInvalidIssuer, "response issuer is missing | 缺少响应签发方")
	}
	if opts.IDPEntityID != "" && response.Issuer.Value != opts.IDPEntityID {
		return nil, errs.Detail(ErrInvalidIssuer, "response issuer %[1]q | 响应签发方 %[1]q", response.Issuer.Value)
	}
	requireDestination := opts.ACSURL != "" && (response.Signature != nil || opts.RequireSignedResponse || opts.SignatureVerifier != nil)
	if opts.ACSURL != "" && response.Destination != "" && response.Destination != opts.ACSURL {
		return nil, errs.Detail(ErrInvalidRecipient, "destination %[1]q | 目标 %[1]q", response.Destination)
	}
	if requireDestination && response.Destination == "" {
		return nil, errs.Detail(ErrInvalidRecipient, "destination is missing | 缺少目标")
	}
	if opts.RequireInResponseTo && opts.Store == nil {
		return nil, errs.Detail(ErrInvalidConfig, "InResponseTo validation requires a Store | InResponseTo 校验需要 Store")
	}

	responseVerified, err := verifyResponseSignature(ctx, raw, &response, opts)
	if err != nil {
		return nil, err
	}
	entries, err := collectAssertions(ctx, raw, &response, opts)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, ErrNoAssertion
	}
	requestID, err := correlationRequestID(&response, entries, opts)
	if err != nil {
		return nil, err
	}
	var state *RequestState
	if requestID != "" && opts.Store != nil {
		consumed, consumeErr := opts.Store.ConsumeRequest(ctx, requestID, now)
		if consumeErr != nil {
			if opts.RequireInResponseTo {
				return nil, consumeErr
			}
		} else {
			state = consumed
		}
	}
	if state != nil {
		if opts.ACSURL != "" && state.ACSURL != "" && state.ACSURL != opts.ACSURL {
			return nil, errs.Detail(ErrInvalidRecipient, "request ACS URL mismatch | 请求 ACS URL 不匹配")
		}
		if opts.SPEntityID != "" && state.SPEntityID != "" && state.SPEntityID != opts.SPEntityID {
			return nil, errs.Detail(ErrInvalidAudience, "request SP entity mismatch | 请求 SP 实体不匹配")
		}
	}
	relayState := ""
	if state != nil {
		relayState = state.RelayState
	}
	var lastErr error
	for index := range entries {
		result, err := validateAssertion(ctx, entries[index], response, opts, now, skew, requestID, responseVerified, relayState)
		if err == nil {
			return result, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = ErrNoAssertion
	}
	return nil, lastErr
}

// verifyResponseSignature verifies a present Response signature and reports whether one was
// verified. | verifyResponseSignature 校验存在的 Response 签名，并报告是否完成了校验。
func verifyResponseSignature(ctx context.Context, raw []byte, response *Response, opts ResponseValidationOptions) (bool, error) {
	if response.Signature == nil {
		if opts.RequireSignedResponse {
			return false, errs.Detail(ErrInvalidSignature, "response is not signed | 响应未签名")
		}
		return false, nil
	}
	if opts.SignatureVerifier == nil {
		return false, errs.Detail(ErrInvalidSignature, "no signature verifier configured | 未配置签名校验器")
	}
	if err := opts.SignatureVerifier.VerifySignature(ctx, raw, response.ID); err != nil {
		return false, errs.Wrap(err, ErrInvalidSignature)
	}
	return true, nil
}

// collectAssertions verifies every assertion signature before any assertion content is used and
// keeps each assertion bound to the bytes that carried its signature. | collectAssertions 在使用任何
// 断言内容前校验所有断言签名，并把每个断言绑定到承载其签名的字节。
func collectAssertions(ctx context.Context, raw []byte, response *Response, opts ResponseValidationOptions) ([]assertionEntry, error) {
	entries := make([]assertionEntry, 0, len(response.Assertion)+len(response.EncryptedAssertion))
	for index := range response.Assertion {
		assertion := &response.Assertion[index]
		entry := assertionEntry{assertion: assertion, raw: raw}
		if assertion.Signature != nil {
			if opts.SignatureVerifier == nil {
				return nil, errs.Detail(ErrInvalidSignature, "no signature verifier configured | 未配置签名校验器")
			}
			if err := opts.SignatureVerifier.VerifySignature(ctx, raw, assertion.ID); err != nil {
				return nil, errs.Wrap(err, ErrInvalidSignature)
			}
			entry.verified = true
		}
		entries = append(entries, entry)
	}
	for index := range response.EncryptedAssertion {
		if opts.Decryptor == nil {
			return nil, errs.Detail(ErrDecryption, "encrypted assertion without a decryptor | 加密断言但没有解密器")
		}
		decrypted, err := opts.Decryptor.DecryptAssertion(ctx, &response.EncryptedAssertion[index])
		if err != nil {
			return nil, errs.Wrap(err, ErrDecryption)
		}
		var assertion Assertion
		if err := xml.Unmarshal(decrypted, &assertion); err != nil {
			return nil, errs.Wrap(err, ErrInvalidResponse)
		}
		entry := assertionEntry{assertion: &assertion, raw: decrypted, encrypted: true}
		if assertion.Signature != nil {
			if opts.SignatureVerifier == nil {
				return nil, errs.Detail(ErrInvalidSignature, "no signature verifier configured | 未配置签名校验器")
			}
			if err := opts.SignatureVerifier.VerifySignature(ctx, decrypted, assertion.ID); err != nil {
				return nil, errs.Wrap(err, ErrInvalidSignature)
			}
			entry.verified = true
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// correlationRequestID returns the single request ID referenced by the response and its bearer
// confirmations, rejecting conflicting values. | correlationRequestID 返回响应及其承载确认所引用的
// 唯一请求 ID，并拒绝冲突取值。
func correlationRequestID(response *Response, entries []assertionEntry, opts ResponseValidationOptions) (string, error) {
	requestID := response.InResponseTo
	assign := func(value string) error {
		if value == "" {
			return nil
		}
		if requestID == "" {
			requestID = value
			return nil
		}
		if requestID != value {
			return errs.Detail(ErrInvalidRequest, "conflicting InResponseTo values | InResponseTo 取值冲突")
		}
		return nil
	}
	for _, entry := range entries {
		subject := entry.assertion.Subject
		if subject == nil {
			continue
		}
		for _, confirmation := range subject.SubjectConfirmation {
			if confirmation.Method != SubjectConfirmationBearer || confirmation.SubjectConfirmationData == nil {
				continue
			}
			if err := assign(confirmation.SubjectConfirmationData.InResponseTo); err != nil {
				return "", err
			}
		}
	}
	if opts.RequireInResponseTo && requestID == "" {
		return "", errs.Detail(ErrInvalidRequest, "InResponseTo is required | 必须提供 InResponseTo")
	}
	return requestID, nil
}

// validateProtocolInstant checks a required IssueInstant for malformed, future and stale values. |
// validateProtocolInstant 检查必需的 IssueInstant 是否格式错误、来自未来或过旧。
func validateProtocolInstant(kind, value string, now time.Time, skew, maxAge time.Duration, sentinel error) error {
	if value == "" {
		return errs.Detail(sentinel, "%s IssueInstant is missing | 缺少 %s 的 IssueInstant", kind, kind)
	}
	issued, err := ParseTime(value)
	if err != nil {
		return errs.WrapDetail(err, sentinel, "%s IssueInstant is invalid | %s 的 IssueInstant 非法", kind, kind)
	}
	if now.Add(skew).Before(issued) {
		return errs.Detail(sentinel, "%s is from the future | %s 来自未来", kind, kind)
	}
	if maxAge > 0 && issued.Before(now.Add(-maxAge-skew)) {
		return errs.Detail(sentinel, "%s is too old | %s 过旧", kind, kind)
	}
	return nil
}

// validateStatus verifies a success status. | validateStatus 校验成功状态。
func validateStatus(status *Status) error {
	if status == nil || status.StatusCode == nil {
		return errs.Detail(ErrInvalidResponse, "status is missing | 缺少状态")
	}
	code := status.StatusCode.Value
	if code == StatusSuccess {
		return nil
	}
	message := ""
	if status.StatusMessage != nil {
		message = status.StatusMessage.Value
	}
	return errs.Detail(ErrStatusFailure, "status %[1]q %[2]s | 状态 %[1]q %[2]s", code, message)
}

// validateAssertion validates one assertion. | validateAssertion 校验一个断言。
func validateAssertion(ctx context.Context, entry assertionEntry, response Response, opts ResponseValidationOptions, now time.Time, skew time.Duration, requestID string, responseVerified bool, relayState string) (*ValidationResult, error) {
	assertion := entry.assertion
	if assertion.ID == "" {
		return nil, errs.Detail(ErrInvalidResponse, "assertion ID is missing | 缺少断言 ID")
	}
	if assertion.Version != Version {
		return nil, errs.Detail(ErrInvalidResponse, "unsupported assertion version %[1]q | 不支持的断言版本 %[1]q", assertion.Version)
	}
	if err := validateProtocolInstant("assertion", assertion.IssueInstant, now, skew, opts.MaxIssueAge, ErrInvalidResponse); err != nil {
		return nil, err
	}
	if assertion.Issuer == nil || assertion.Issuer.Value == "" {
		return nil, errs.Detail(ErrInvalidIssuer, "assertion issuer is missing | 缺少断言签发方")
	}
	if opts.IDPEntityID != "" && assertion.Issuer.Value != opts.IDPEntityID {
		return nil, errs.Detail(ErrInvalidIssuer, "assertion issuer %[1]q | 断言签发方 %[1]q", assertion.Issuer.Value)
	}
	if assertion.Signature != nil && !entry.verified {
		return nil, errs.Detail(ErrInvalidSignature, "assertion signature was not verified | 断言签名未校验")
	}
	if opts.RequireSignedAssertion && !entry.verified && !responseVerified {
		return nil, errs.Detail(ErrInvalidSignature, "assertion is not signed | 断言未签名")
	}
	subject := assertion.Subject
	if subject == nil || subject.NameID == nil || subject.NameID.Value == "" {
		return nil, errs.Detail(ErrInvalidResponse, "subject NameID is missing | 缺少主体 NameID")
	}
	if len(opts.AllowedNameIDFormats) > 0 {
		format := subject.NameID.Format
		if format == "" {
			format = NameIDUnspecified
		}
		if !containsString(opts.AllowedNameIDFormats, format) {
			return nil, errs.Detail(ErrInvalidResponse, "NameID format %[1]q is not allowed | 不允许 NameID 格式 %[1]q", format)
		}
	}
	if assertion.Conditions != nil {
		if err := checkWindow(assertion.Conditions.NotBefore, assertion.Conditions.NotOnOrAfter, now, skew); err != nil {
			return nil, err
		}
	}
	if opts.SPEntityID != "" {
		if assertion.Conditions == nil || !audienceContains(assertion.Conditions.AudienceRestriction, opts.SPEntityID) {
			return nil, errs.Detail(ErrInvalidAudience, "audience does not contain %[1]q | 受众不包含 %[1]q", opts.SPEntityID)
		}
	}
	bearer, err := validateSubjectConfirmation(subject, opts, now, skew, requestID)
	if err != nil {
		return nil, err
	}
	if bearer != nil && response.InResponseTo != "" && bearer.InResponseTo != "" && bearer.InResponseTo != response.InResponseTo {
		return nil, errs.Detail(ErrInvalidRequest, "subject confirmation InResponseTo mismatch | 主体确认 InResponseTo 不匹配")
	}
	expiresAt := now.Add(10 * time.Minute)
	if assertion.Conditions != nil && assertion.Conditions.NotOnOrAfter != "" {
		if parsed, err := ParseTime(assertion.Conditions.NotOnOrAfter); err == nil {
			expiresAt = parsed
		}
	}
	if bearer != nil && bearer.NotOnOrAfter != "" {
		if parsed, err := ParseTime(bearer.NotOnOrAfter); err == nil && parsed.Before(expiresAt) {
			expiresAt = parsed
		}
	}
	// SessionNotOnOrAfter bounds the IdP session exactly like Conditions/NotOnOrAfter bounds the
	// assertion: a value at or before the tolerated clock boundary is expired. | SessionNotOnOrAfter
	// 与 Conditions/NotOnOrAfter 约束断言的方式一致地约束 IdP 会话：等于或早于容忍时钟边界即过期。
	for index := range assertion.AuthnStatement {
		statement := &assertion.AuthnStatement[index]
		if statement.SessionNotOnOrAfter == "" {
			continue
		}
		parsed, err := ParseTime(statement.SessionNotOnOrAfter)
		if err != nil {
			return nil, err
		}
		if !now.Add(-skew).Before(parsed) {
			return nil, ErrResponseExpired
		}
		if parsed.Before(expiresAt) {
			expiresAt = parsed
		}
	}
	recorded := false
	if assertion.Conditions != nil && assertion.Conditions.OneTimeUse != nil {
		replayStore := opts.AssertionReplayStore
		storeBacked := false
		if replayStore == nil && opts.Store != nil {
			if candidate, ok := opts.Store.(AssertionReplayStore); ok {
				replayStore = candidate
				storeBacked = true
			}
		}
		if replayStore != nil {
			seen, err := replayStore.SeenAndStore(ctx, assertion.ID, expiresAt, now)
			if err != nil {
				return nil, err
			}
			if seen {
				return nil, ErrReplay
			}
			// The store already recorded this identifier; saving it again through Store would report
			// the first legitimate use as a replay. A separately configured replay store does not
			// satisfy Store's own replay detection, so both records are kept in that case. | 该存储已
			// 记录此标识；再次经 Store 保存会把首次合法使用误报为重放。单独配置的重放存储不满足
			// Store 自身的重放检测，因此该情况下两者都会记录。
			recorded = storeBacked
		} else if !opts.AllowOneTimeUseWithoutReplayStore {
			return nil, errs.Detail(ErrInvalidConfig, "one-time-use assertion requires an AssertionReplayStore | 一次性断言需要 AssertionReplayStore")
		}
	}
	// A nil Store disables replay detection; callers that accept signed assertions or rely on
	// InResponseTo should always configure one. | Store 为空时禁用重放检测；接受签名断言或依赖
	// InResponseTo 的调用方应始终配置 Store。
	if opts.Store != nil && !recorded {
		fresh, err := opts.Store.SaveAssertion(ctx, assertion.ID, expiresAt, now)
		if err != nil {
			return nil, err
		}
		if !fresh {
			return nil, ErrReplay
		}
	}
	attributes := AttributeMap(assertion.AttributeStatement)
	principal := principalFromAssertion(assertion, attributes)
	principal.Issuer = responseIssuer(response, assertion)
	if opts.SPEntityID != "" {
		principal.Audience = []string{opts.SPEntityID}
	}
	return &ValidationResult{
		Response:     &response,
		Assertion:    assertion,
		Principal:    principal,
		Attributes:   attributes,
		NameID:       subject.NameID.Value,
		SessionIndex: sessionIndex(assertion),
		RelayState:   relayState,
	}, nil
}

// audienceContains reports whether every audience restriction lists audience, as required by SAML
// Core 2.5.1.4 intersection semantics. | audienceContains 报告是否每个受众限制都列出了 audience，
// 符合 SAML Core 2.5.1.4 的交集语义。
func audienceContains(restrictions []AudienceRestriction, audience string) bool {
	if len(restrictions) == 0 {
		return false
	}
	for _, restriction := range restrictions {
		if !containsString(restriction.Audience, audience) {
			return false
		}
	}
	return true
}

// SubjectConfirmationBearer is the SAML bearer confirmation method. | SubjectConfirmationBearer 是
// SAML 承载确认方法。
const SubjectConfirmationBearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer"

// validateSubjectConfirmation validates the bearer SubjectConfirmation. | validateSubjectConfirmation
// 校验承载 SubjectConfirmation。
func validateSubjectConfirmation(subject *Subject, opts ResponseValidationOptions, now time.Time, skew time.Duration, requestID string) (*SubjectConfirmationData, error) {
	if subject == nil || len(subject.SubjectConfirmation) == 0 {
		if opts.RequireSubjectConfirmation {
			return nil, errs.Detail(ErrInvalidResponse, "subject confirmation is missing | 缺少主体确认")
		}
		return nil, nil
	}
	for index := range subject.SubjectConfirmation {
		confirmation := &subject.SubjectConfirmation[index]
		if confirmation.Method != SubjectConfirmationBearer {
			continue
		}
		data := confirmation.SubjectConfirmationData
		if data == nil {
			continue
		}
		if opts.ACSURL != "" && (data.Recipient == "" || data.Recipient != opts.ACSURL) {
			continue
		}
		if data.NotOnOrAfter == "" {
			continue
		}
		if err := checkWindow(data.NotBefore, data.NotOnOrAfter, now, skew); err != nil {
			continue
		}
		if requestID != "" && data.InResponseTo != "" && data.InResponseTo != requestID {
			continue
		}
		if opts.RequireInResponseTo && data.InResponseTo == "" {
			continue
		}
		return data, nil
	}
	return nil, errs.Detail(ErrInvalidResponse, "no valid bearer subject confirmation | 没有有效的承载主体确认")
}

// checkWindow validates a NotBefore/NotOnOrAfter pair. | checkWindow 校验 NotBefore/NotOnOrAfter 组合。
func checkWindow(notBefore, notOnOrAfter string, now time.Time, skew time.Duration) error {
	if notBefore != "" {
		parsed, err := ParseTime(notBefore)
		if err != nil {
			return err
		}
		if now.Add(skew).Before(parsed) {
			return ErrResponseNotYetValid
		}
	}
	if notOnOrAfter != "" {
		parsed, err := ParseTime(notOnOrAfter)
		if err != nil {
			return err
		}
		if !now.Add(-skew).Before(parsed) {
			return ErrResponseExpired
		}
	}
	return nil
}

// principalFromAssertion builds a principal from an assertion. | principalFromAssertion 从断言构建主体。
func principalFromAssertion(assertion *Assertion, attributes map[string][]string) *auth.Principal {
	principal := &auth.Principal{
		Subject:     SubjectNameID(assertion.Subject),
		Username:    firstAttribute(attributes, "username", "uid", "sAMAccountName", "urn:oid:0.9.2342.19200300.100.1.1"),
		Email:       firstAttribute(attributes, "email", "mail", "urn:oid:0.9.2342.19200300.100.1.3"),
		DisplayName: firstAttribute(attributes, "displayName", "cn", "name", "urn:oid:2.16.840.1.113730.3.1.241"),
		Groups:      append([]string(nil), attributes["groups"]...),
		AMR:         []string{"saml"},
		Attributes:  flattenAttributes(attributes),
	}
	if len(principal.Groups) == 0 {
		principal.Groups = append(principal.Groups, attributes["memberOf"]...)
	}
	if len(principal.Groups) == 0 {
		principal.Groups = append(principal.Groups, attributes["urn:oid:1.3.6.1.4.1.5923.1.5.1.1"]...)
	}
	if assertion.Subject.NameID != nil {
		principal.ACR = assertion.Subject.NameID.Format
	}
	if len(assertion.AuthnStatement) > 0 {
		statement := assertion.AuthnStatement[0]
		principal.SessionID = statement.SessionIndex
		if statement.AuthnInstant != "" {
			if parsed, err := ParseTime(statement.AuthnInstant); err == nil {
				principal.AuthTime = parsed
			}
		}
		if statement.AuthnContext != nil && statement.AuthnContext.AuthnContextClassRef != "" {
			principal.ACR = statement.AuthnContext.AuthnContextClassRef
		}
	}
	return principal
}

// responseIssuer returns the response or assertion issuer value. | responseIssuer 返回响应或断言签发方取值。
func responseIssuer(response Response, assertion *Assertion) string {
	if response.Issuer != nil && response.Issuer.Value != "" {
		return response.Issuer.Value
	}
	if assertion != nil && assertion.Issuer != nil {
		return assertion.Issuer.Value
	}
	return ""
}

// sessionIndex returns the first session index. | sessionIndex 返回第一个会话索引。
func sessionIndex(assertion *Assertion) string {
	if assertion == nil || len(assertion.AuthnStatement) == 0 {
		return ""
	}
	return assertion.AuthnStatement[0].SessionIndex
}

// firstAttribute returns the first value among names. | firstAttribute 返回 names 中的第一个取值。
func firstAttribute(attributes map[string][]string, names ...string) string {
	for _, name := range names {
		if values := attributes[name]; len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

// flattenAttributes keeps the first value of every attribute as a principal attribute. | flattenAttributes
// 把每个属性的第一个取值保留为主体属性。
func flattenAttributes(attributes map[string][]string) map[string]string {
	if len(attributes) == 0 {
		return nil
	}
	out := make(map[string]string, len(attributes))
	for key, values := range attributes {
		if len(values) > 0 {
			out[key] = values[0]
		}
	}
	return out
}

// containsString reports whether values contains want. | containsString 报告 values 是否包含 want。
func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// ParseResponse parses a SAML Response without validating it. | ParseResponse 解析 SAML Response 但不校验。
func ParseResponse(data []byte) (*Response, error) {
	var response Response
	if err := xml.Unmarshal(data, &response); err != nil {
		return nil, errs.Wrap(err, ErrInvalidResponse)
	}
	return &response, nil
}

// ParseAuthnRequest parses a SAML AuthnRequest. | ParseAuthnRequest 解析 SAML AuthnRequest。
func ParseAuthnRequest(data []byte) (*AuthnRequest, error) {
	var request AuthnRequest
	if err := xml.Unmarshal(data, &request); err != nil {
		return nil, errs.Wrap(err, ErrInvalidRequest)
	}
	return &request, nil
}

// ValidateAuthnRequest validates an AuthnRequest for an IdP. | ValidateAuthnRequest 为 IdP 校验 AuthnRequest。
type AuthnRequestValidationOptions struct {
	// IDPEntityID is the local IdP entity ID. | IDPEntityID 是本地 IdP 实体标识。
	IDPEntityID string
	// SSOURL is the local SSO endpoint URL. | SSOURL 是本地 SSO 端点 URL。
	SSOURL string
	// SPResolver resolves requester metadata. | SPResolver 解析请求方元数据。
	SPResolver MetadataResolver
	// ClockSkew is the tolerated clock difference. | ClockSkew 是容忍的时钟差。
	ClockSkew time.Duration
	// MaxIssueAge rejects old requests. | MaxIssueAge 拒绝过旧请求。
	MaxIssueAge time.Duration
	// Now overrides the clock. | Now 替换时钟。
	Now func() time.Time
}

// ValidateAuthnRequest checks version, identifier, destination, issue time and SP metadata. |
// ValidateAuthnRequest 校验版本、标识、目标、签发时间与 SP 元数据。
func ValidateAuthnRequest(ctx context.Context, request *AuthnRequest, opts AuthnRequestValidationOptions) error {
	if request == nil {
		return errs.Detail(ErrInvalidRequest, "request is nil | 请求为空")
	}
	now := Now(opts.Now)
	skew := opts.ClockSkew
	if skew <= 0 {
		skew = 2 * time.Minute
	}
	if request.Version != Version {
		return errs.Detail(ErrInvalidRequest, "unsupported version %[1]q | 不支持的版本 %[1]q", request.Version)
	}
	if request.ID == "" {
		return errs.Detail(ErrInvalidRequest, "request ID is missing | 缺少请求 ID")
	}
	if err := validateProtocolInstant("request", request.IssueInstant, now, skew, opts.MaxIssueAge, ErrInvalidRequest); err != nil {
		return err
	}
	if request.Issuer == nil || request.Issuer.Value == "" {
		return errs.Detail(ErrInvalidIssuer, "request issuer is missing | 缺少请求签发方")
	}
	if opts.SSOURL != "" {
		if request.Destination == "" {
			return errs.Detail(ErrInvalidRecipient, "request destination is missing | 缺少请求目标")
		}
		if request.Destination != opts.SSOURL {
			return errs.Detail(ErrInvalidRecipient, "destination %[1]q | 目标 %[1]q", request.Destination)
		}
	} else if request.Destination != "" && opts.IDPEntityID != "" && request.Destination != opts.IDPEntityID {
		return errs.Detail(ErrInvalidRecipient, "destination %[1]q | 目标 %[1]q", request.Destination)
	}
	if opts.SPResolver != nil {
		metadata, err := opts.SPResolver.Resolve(ctx, request.Issuer.Value)
		if err != nil {
			return errs.Wrap(err, ErrInvalidIssuer)
		}
		registered := metadata.ACSURL(request.ProtocolBinding)
		// The response may only be delivered to an endpoint registered in SP metadata. Accepting a
		// request-supplied URL when metadata registers none would let a requester exfiltrate the
		// assertion. | 响应只能投递到 SP 元数据中注册的端点。元数据未注册时接受请求自带的 URL 会
		// 使请求方能够窃取断言。
		if request.AssertionConsumerServiceURL != "" && request.AssertionConsumerServiceURL != registered {
			return errs.Detail(ErrInvalidRecipient, "ACS URL %[1]q is not registered | ACS URL %[1]q 未注册", request.AssertionConsumerServiceURL)
		}
		if registered == "" {
			return errs.Detail(ErrInvalidRecipient, "ACS URL cannot be resolved | 无法解析 ACS URL")
		}
	}
	return nil
}

// StatusError returns a SAML status value for an error. | StatusError 返回错误的 SAML 状态值。
func StatusError(err error) string {
	if err == nil {
		return StatusSuccess
	}
	if errorsIs(err, ErrInvalidIssuer, ErrInvalidAudience, ErrInvalidRecipient) {
		return StatusRequester
	}
	return StatusResponder
}

// errorsIs reports whether err matches any target. | errorsIs 报告 err 是否匹配任一目标。
func errorsIs(err error, targets ...error) bool {
	for _, target := range targets {
		if target != nil && errors.Is(err, target) {
			return true
		}
	}
	return false
}
