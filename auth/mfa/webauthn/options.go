package webauthn

import (
	"math"
	"time"

	"github.com/shibingli/ydx/errs"
)

// UserVerificationRequirement is the userVerification option value. | UserVerificationRequirement 是 userVerification 选项值。
type UserVerificationRequirement string

// The user verification requirements defined by WebAuthn. | WebAuthn 定义的用户验证要求。
const (
	// UserVerificationRequired requires the UV flag. | UserVerificationRequired 要求 UV 标志。
	UserVerificationRequired UserVerificationRequirement = "required"
	// UserVerificationPreferred asks for UV but accepts its absence. | UserVerificationPreferred 请求 UV，但允许缺失。
	UserVerificationPreferred UserVerificationRequirement = "preferred"
	// UserVerificationDiscouraged does not ask for UV. | UserVerificationDiscouraged 不请求 UV。
	UserVerificationDiscouraged UserVerificationRequirement = "discouraged"
)

// ResidentKeyRequirement is the residentKey option value. | ResidentKeyRequirement 是 residentKey 选项值。
type ResidentKeyRequirement string

// The resident key requirements defined by WebAuthn. | WebAuthn 定义的常驻密钥要求。
const (
	// ResidentKeyRequired requires a discoverable credential. | ResidentKeyRequired 要求可发现凭据。
	ResidentKeyRequired ResidentKeyRequirement = "required"
	// ResidentKeyPreferred prefers a discoverable credential. | ResidentKeyPreferred 优先使用可发现凭据。
	ResidentKeyPreferred ResidentKeyRequirement = "preferred"
	// ResidentKeyDiscouraged does not ask for a discoverable credential. | ResidentKeyDiscouraged 不请求可发现凭据。
	ResidentKeyDiscouraged ResidentKeyRequirement = "discouraged"
)

// ConveyancePreference is the attestation option value. | ConveyancePreference 是 attestation 选项值。
type ConveyancePreference string

// The attestation conveyance preferences defined by WebAuthn. | WebAuthn 定义的认证声明传递偏好。
const (
	// ConveyanceNone asks the client not to disclose attestation information. | ConveyanceNone 请求客户端不披露认证声明信息。
	ConveyanceNone ConveyancePreference = "none"
	// ConveyanceIndirect allows the client to replace attestation information. | ConveyanceIndirect 允许客户端替换认证声明信息。
	ConveyanceIndirect ConveyancePreference = "indirect"
	// ConveyanceDirect asks for the authenticator attestation. | ConveyanceDirect 请求认证器认证声明。
	ConveyanceDirect ConveyancePreference = "direct"
	// ConveyanceEnterprise asks for enterprise attestation. | ConveyanceEnterprise 请求企业级认证声明。
	ConveyanceEnterprise ConveyancePreference = "enterprise"
)

// AuthenticatorAttachment is the authenticatorAttachment option value. | AuthenticatorAttachment 是 authenticatorAttachment 选项值。
type AuthenticatorAttachment string

// The authenticator attachment values defined by WebAuthn. | WebAuthn 定义的认证器连接方式。
const (
	// AuthenticatorPlatform selects a platform authenticator. | AuthenticatorPlatform 选择平台认证器。
	AuthenticatorPlatform AuthenticatorAttachment = "platform"
	// AuthenticatorCrossPlatform selects a roaming authenticator. | AuthenticatorCrossPlatform 选择漫游认证器。
	AuthenticatorCrossPlatform AuthenticatorAttachment = "cross-platform"
)

func validUserVerification(v UserVerificationRequirement) bool {
	switch v {
	case UserVerificationRequired, UserVerificationPreferred, UserVerificationDiscouraged:
		return true
	default:
		return false
	}
}

func validResidentKey(v ResidentKeyRequirement) bool {
	switch v {
	case "", ResidentKeyRequired, ResidentKeyPreferred, ResidentKeyDiscouraged:
		return true
	default:
		return false
	}
}

func validConveyance(v ConveyancePreference) bool {
	switch v {
	case ConveyanceNone, ConveyanceIndirect, ConveyanceDirect, ConveyanceEnterprise:
		return true
	default:
		return false
	}
}

func validAttachment(v AuthenticatorAttachment) bool {
	switch v {
	case "", AuthenticatorPlatform, AuthenticatorCrossPlatform:
		return true
	default:
		return false
	}
}

// CredentialParameter is one pubKeyCredParams entry. | CredentialParameter 是一个 pubKeyCredParams 条目。
type CredentialParameter struct {
	// Type is always "public-key". | Type 恒为 "public-key"。
	Type string `json:"type"`
	// Alg is a COSE algorithm identifier. | Alg 是 COSE 算法标识。
	Alg int `json:"alg"`
}

// RelyingPartyEntity is the rp member of creation options. | RelyingPartyEntity 是创建选项的 rp 成员。
type RelyingPartyEntity struct {
	// ID is the relying party identifier. | ID 是依赖方标识。
	ID string `json:"id"`
	// Name is the human-readable relying party name. | Name 是人类可读的依赖方名称。
	Name string `json:"name"`
}

// UserEntity is the user member of creation options. | UserEntity 是创建选项的 user 成员。
type UserEntity struct {
	// ID is the unpadded base64url user handle. | ID 是无填充 base64url 用户句柄。
	ID string `json:"id"`
	// Name is the login name shown by the authenticator. | Name 是认证器展示的登录名。
	Name string `json:"name"`
	// DisplayName is the human-readable display name. | DisplayName 是人类可读的展示名称。
	DisplayName string `json:"displayName"`
}

// CredentialDescriptor is an allowCredentials or excludeCredentials entry. | CredentialDescriptor 是 allowCredentials 或 excludeCredentials 条目。
type CredentialDescriptor struct {
	// Type is always "public-key". | Type 恒为 "public-key"。
	Type string `json:"type"`
	// ID is the unpadded base64url credential ID. | ID 是无填充 base64url 凭据 ID。
	ID string `json:"id"`
	// Transports lists authenticator transports. | Transports 列出认证器传输方式。
	Transports []string `json:"transports,omitempty"`
}

// AuthenticatorSelection is the authenticatorSelection member of creation options. | AuthenticatorSelection 是创建选项的 authenticatorSelection 成员。
type AuthenticatorSelection struct {
	// AuthenticatorAttachment restricts the authenticator attachment. | AuthenticatorAttachment 限制认证器连接方式。
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
	// ResidentKey is the residentKey requirement. | ResidentKey 是常驻密钥要求。
	ResidentKey string `json:"residentKey,omitempty"`
	// RequireResidentKey is the legacy requireResidentKey flag. | RequireResidentKey 是旧版 requireResidentKey 标志。
	RequireResidentKey bool `json:"requireResidentKey"`
	// UserVerification is the user verification requirement. | UserVerification 是用户验证要求。
	UserVerification string `json:"userVerification,omitempty"`
}

// RegistrationExtensions are the creation ceremony client extensions. | RegistrationExtensions 是注册流程的客户端扩展。
type RegistrationExtensions struct {
	// CredentialProtectionPolicy maps to credentialProtectionPolicy. | CredentialProtectionPolicy 对应 credentialProtectionPolicy。
	CredentialProtectionPolicy string `json:"credentialProtectionPolicy,omitempty"`
	// EnforceCredentialProtectionPolicy maps to enforceCredentialProtectionPolicy. | EnforceCredentialProtectionPolicy 对应 enforceCredentialProtectionPolicy。
	EnforceCredentialProtectionPolicy bool `json:"enforceCredentialProtectionPolicy,omitempty"`
	// CredProps requests the credProps extension. | CredProps 请求 credProps 扩展。
	CredProps bool `json:"credProps,omitempty"`
	// HMACCreateSecret requests the hmac-secret extension at creation. | HMACCreateSecret 在创建时请求 hmac-secret 扩展。
	HMACCreateSecret bool `json:"hmacCreateSecret,omitempty"`
	// UVM requests the uvm extension. | UVM 请求 uvm 扩展。
	UVM bool `json:"uvm,omitempty"`
}

// HMACGetSecretInput is the hmacGetSecret extension input. | HMACGetSecretInput 是 hmacGetSecret 扩展输入。
type HMACGetSecretInput struct {
	// Salt1 is an unpadded base64url salt. | Salt1 是无填充 base64url 盐值。
	Salt1 string `json:"salt1"`
	// Salt2 is an optional second unpadded base64url salt. | Salt2 是可选的无填充 base64url 盐值。
	Salt2 string `json:"salt2,omitempty"`
}

// AuthenticationExtensions are the authentication ceremony client extensions. | AuthenticationExtensions 是认证流程的客户端扩展。
type AuthenticationExtensions struct {
	// HMACGetSecret requests the hmac-secret extension at authentication. | HMACGetSecret 在认证时请求 hmac-secret 扩展。
	HMACGetSecret *HMACGetSecretInput `json:"hmacGetSecret,omitempty"`
	// UVM requests the uvm extension. | UVM 请求 uvm 扩展。
	UVM bool `json:"uvm,omitempty"`
}

// CredPropsResult is the credProps client extension output. | CredPropsResult 是 credProps 客户端扩展输出。
type CredPropsResult struct {
	// RK reports whether the created credential is discoverable. | RK 报告创建的凭据是否可发现。
	RK bool `json:"rk"`
}

// ClientExtensionResults is the clientExtensionResults member of a response. | ClientExtensionResults 是响应的 clientExtensionResults 成员。
type ClientExtensionResults struct {
	// CredProps carries the credProps result when requested. | CredProps 在请求时携带 credProps 结果。
	CredProps *CredPropsResult `json:"credProps,omitempty"`
	// HMACCreateSecret reports hmac-secret support at creation. | HMACCreateSecret 报告创建时的 hmac-secret 支持。
	HMACCreateSecret bool `json:"hmacCreateSecret,omitempty"`
}

// PublicKeyCredentialCreationOptions is the publicKey member of creation options. | PublicKeyCredentialCreationOptions 是创建选项的 publicKey 成员。
type PublicKeyCredentialCreationOptions struct {
	// Challenge is the unpadded base64url challenge. | Challenge 是无填充 base64url 挑战。
	Challenge string `json:"challenge"`
	// RP identifies the relying party. | RP 标识依赖方。
	RP RelyingPartyEntity `json:"rp"`
	// User identifies the account being registered. | User 标识正在注册的账号。
	User UserEntity `json:"user"`
	// PubKeyCredParams lists acceptable algorithms. | PubKeyCredParams 列出可接受的算法。
	PubKeyCredParams []CredentialParameter `json:"pubKeyCredParams"`
	// Timeout is the ceremony timeout in milliseconds. | Timeout 是流程超时（毫秒）。
	Timeout uint32 `json:"timeout,omitempty"`
	// ExcludeCredentials prevents duplicate enrollment. | ExcludeCredentials 防止重复登记。
	ExcludeCredentials []CredentialDescriptor `json:"excludeCredentials,omitempty"`
	// AuthenticatorSelection constrains the authenticator. | AuthenticatorSelection 约束认证器。
	AuthenticatorSelection *AuthenticatorSelection `json:"authenticatorSelection,omitempty"`
	// Attestation is the attestation conveyance preference. | Attestation 是认证声明传递偏好。
	Attestation string `json:"attestation,omitempty"`
	// Extensions requests creation extensions. | Extensions 请求创建扩展。
	Extensions *RegistrationExtensions `json:"extensions,omitempty"`
}

// CredentialCreationOptions is the argument of navigator.credentials.create. | CredentialCreationOptions 是 navigator.credentials.create 的参数。
type CredentialCreationOptions struct {
	// PublicKey is the publicKey member. | PublicKey 是 publicKey 成员。
	PublicKey PublicKeyCredentialCreationOptions `json:"publicKey"`
}

// PublicKeyCredentialRequestOptions is the publicKey member of request options. | PublicKeyCredentialRequestOptions 是请求选项的 publicKey 成员。
type PublicKeyCredentialRequestOptions struct {
	// Challenge is the unpadded base64url challenge. | Challenge 是无填充 base64url 挑战。
	Challenge string `json:"challenge"`
	// Timeout is the ceremony timeout in milliseconds. | Timeout 是流程超时（毫秒）。
	Timeout uint32 `json:"timeout,omitempty"`
	// RPID is the relying party identifier. | RPID 是依赖方标识。
	RPID string `json:"rpId,omitempty"`
	// AllowCredentials restricts the acceptable credentials. An empty list means discoverable credentials. | AllowCredentials 限制可接受的凭据；空列表表示可发现凭据。
	AllowCredentials []CredentialDescriptor `json:"allowCredentials,omitempty"`
	// UserVerification is the user verification requirement. | UserVerification 是用户验证要求。
	UserVerification string `json:"userVerification,omitempty"`
	// Extensions requests authentication extensions. | Extensions 请求认证扩展。
	Extensions *AuthenticationExtensions `json:"extensions,omitempty"`
}

// CredentialRequestOptions is the argument of navigator.credentials.get. | CredentialRequestOptions 是 navigator.credentials.get 的参数。
type CredentialRequestOptions struct {
	// PublicKey is the publicKey member. | PublicKey 是 publicKey 成员。
	PublicKey PublicKeyCredentialRequestOptions `json:"publicKey"`
}

// AuthenticatorAttestationResponse is the response member of a registration credential. | AuthenticatorAttestationResponse 是注册凭据的 response 成员。
type AuthenticatorAttestationResponse struct {
	// ClientDataJSON is the unpadded base64url client data JSON. | ClientDataJSON 是无填充 base64url 客户端数据 JSON。
	ClientDataJSON string `json:"clientDataJSON"`
	// AttestationObject is the unpadded base64url attestation object. | AttestationObject 是无填充 base64url 认证声明对象。
	AttestationObject string `json:"attestationObject"`
	// Transports lists the transports reported by the client. | Transports 列出客户端报告的传输方式。
	Transports []string `json:"transports,omitempty"`
}

// CredentialCreationResponse is the JSON form of a registration credential. | CredentialCreationResponse 是注册凭据的 JSON 形式。
type CredentialCreationResponse struct {
	// ID is the unpadded base64url credential ID. | ID 是无填充 base64url 凭据 ID。
	ID string `json:"id"`
	// RawID is the unpadded base64url credential ID. | RawID 是无填充 base64url 凭据 ID。
	RawID string `json:"rawId"`
	// Type must be "public-key". | Type 必须为 "public-key"。
	Type string `json:"type"`
	// Response carries the attestation response. | Response 携带认证声明响应。
	Response AuthenticatorAttestationResponse `json:"response"`
	// ClientExtensionResults carries client extension outputs. | ClientExtensionResults 携带客户端扩展输出。
	ClientExtensionResults ClientExtensionResults `json:"clientExtensionResults,omitempty"`
}

// AuthenticatorAssertionResponse is the response member of an authentication credential. | AuthenticatorAssertionResponse 是认证凭据的 response 成员。
type AuthenticatorAssertionResponse struct {
	// ClientDataJSON is the unpadded base64url client data JSON. | ClientDataJSON 是无填充 base64url 客户端数据 JSON。
	ClientDataJSON string `json:"clientDataJSON"`
	// AuthenticatorData is the unpadded base64url authenticator data. | AuthenticatorData 是无填充 base64url 认证器数据。
	AuthenticatorData string `json:"authenticatorData"`
	// Signature is the unpadded base64url signature. | Signature 是无填充 base64url 签名。
	Signature string `json:"signature"`
	// UserHandle is the unpadded base64url user handle for discoverable credentials. | UserHandle 是可发现凭据的无填充 base64url 用户句柄。
	UserHandle string `json:"userHandle,omitempty"`
}

// CredentialAssertionResponse is the JSON form of an authentication credential. | CredentialAssertionResponse 是认证凭据的 JSON 形式。
type CredentialAssertionResponse struct {
	// ID is the unpadded base64url credential ID. | ID 是无填充 base64url 凭据 ID。
	ID string `json:"id"`
	// RawID is the unpadded base64url credential ID. | RawID 是无填充 base64url 凭据 ID。
	RawID string `json:"rawId"`
	// Type must be "public-key". | Type 必须为 "public-key"。
	Type string `json:"type"`
	// Response carries the assertion response. | Response 携带断言响应。
	Response AuthenticatorAssertionResponse `json:"response"`
	// ClientExtensionResults carries client extension outputs. | ClientExtensionResults 携带客户端扩展输出。
	ClientExtensionResults ClientExtensionResults `json:"clientExtensionResults,omitempty"`
}

// RegistrationOptions tune BeginRegistration. | RegistrationOptions 调整 BeginRegistration。
type RegistrationOptions struct {
	// Name is the user-visible credential label stored with the new credential. | Name 是随新凭据保存的用户可见标签。
	Name string
	// AuthenticatorAttachment restricts the authenticator attachment. | AuthenticatorAttachment 限制认证器连接方式。
	AuthenticatorAttachment AuthenticatorAttachment
	// ResidentKey requests a discoverable credential. | ResidentKey 请求可发现凭据。
	ResidentKey ResidentKeyRequirement
	// RequireResidentKey is the legacy discoverable-credential switch. It overrides ResidentKey when non-nil. | RequireResidentKey 是旧版可发现凭据开关；非空时覆盖 ResidentKey。
	RequireResidentKey *bool
	// UserVerification overrides Config.UserVerification. | UserVerification 覆盖 Config.UserVerification。
	UserVerification UserVerificationRequirement
	// Attestation overrides Config.Attestation. | Attestation 覆盖 Config.Attestation。
	Attestation ConveyancePreference
	// Timeout overrides Config.Timeout. | Timeout 覆盖 Config.Timeout。
	Timeout time.Duration
	// Algorithms overrides Config.Algorithms. | Algorithms 覆盖 Config.Algorithms。
	Algorithms []int
	// ExcludeCredentials adds exclusion descriptors to the stored credentials. | ExcludeCredentials 在已存凭据之外追加排除描述符。
	ExcludeCredentials []CredentialDescriptor
	// Extensions requests creation extensions. | Extensions 请求创建扩展。
	Extensions *RegistrationExtensions
}

// LoginOptions tune BeginLogin. | LoginOptions 调整 BeginLogin。
type LoginOptions struct {
	// UserVerification overrides Config.UserVerification. | UserVerification 覆盖 Config.UserVerification。
	UserVerification UserVerificationRequirement
	// Timeout overrides Config.Timeout. | Timeout 覆盖 Config.Timeout。
	Timeout time.Duration
	// AllowCredentials overrides the descriptor list derived from the credential store. | AllowCredentials 覆盖由凭据存储派生的描述符列表。
	AllowCredentials []CredentialDescriptor
	// Extensions requests authentication extensions. | Extensions 请求认证扩展。
	Extensions *AuthenticationExtensions
}

// DiscoverableLoginOptions tune BeginDiscoverableLogin. | DiscoverableLoginOptions 调整 BeginDiscoverableLogin。
type DiscoverableLoginOptions struct {
	// UserVerification overrides Config.UserVerification. | UserVerification 覆盖 Config.UserVerification。
	UserVerification UserVerificationRequirement
	// Timeout overrides Config.Timeout. | Timeout 覆盖 Config.Timeout。
	Timeout time.Duration
	// Extensions requests authentication extensions. | Extensions 请求认证扩展。
	Extensions *AuthenticationExtensions
}

func timeoutMillis(d time.Duration) uint32 {
	if d <= 0 {
		return 0
	}
	ms := d / time.Millisecond
	if ms > math.MaxUint32 {
		return math.MaxUint32
	}
	if ms == 0 {
		return 1
	}
	return uint32(ms)
}

func validAlgorithms(algorithms []int) ([]int, error) {
	out := make([]int, 0, len(algorithms))
	seen := make(map[int]struct{}, len(algorithms))
	for _, alg := range algorithms {
		if _, ok := HashForAlgorithm(alg); !ok {
			return nil, errs.Detail(ErrUnsupportedAlgorithm, "algorithm %d | 算法 %d", alg, alg)
		}
		if _, ok := seen[alg]; ok {
			continue
		}
		seen[alg] = struct{}{}
		out = append(out, alg)
	}
	if len(out) == 0 {
		return nil, errs.Detail(ErrInvalidConfig, "no supported algorithm | 没有受支持的算法")
	}
	return out, nil
}

// DefaultAlgorithms returns the COSE algorithms offered by default. | DefaultAlgorithms 返回默认提供的 COSE 算法。
func DefaultAlgorithms() []int {
	return []int{AlgES256, AlgEdDSA, AlgRS256, AlgPS256, AlgES384, AlgRS384, AlgPS384, AlgES512, AlgRS512, AlgPS512}
}
