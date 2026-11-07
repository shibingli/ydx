package webauthn

import (
	"strings"
	"time"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
)

// Credential is a registered WebAuthn public-key credential. | Credential 是已注册的 WebAuthn 公钥凭据。
type Credential struct {
	// ID is the raw credential identifier. | ID 是原始凭据标识。
	ID []byte `json:"id"`
	// UserID is the owning account ID. | UserID 是所属账号 ID。
	UserID string `json:"userId"`
	// Username is the account login name when known. | Username 在已知时是账号登录名。
	Username string `json:"username,omitempty"`
	// UserDisplayName is the account display name when known. | UserDisplayName 在已知时是账号展示名称。
	UserDisplayName string `json:"userDisplayName,omitempty"`
	// UserHandle is the raw WebAuthn user handle. | UserHandle 是原始 WebAuthn 用户句柄。
	UserHandle []byte `json:"userHandle,omitempty"`
	// PublicKey is the credential public key. | PublicKey 是凭据公钥。
	PublicKey *COSEKey `json:"publicKey"`
	// SignCount is the latest authenticator signature counter. | SignCount 是最新的认证器签名计数器。
	SignCount uint32 `json:"signCount"`
	// AAGUID identifies the authenticator model. | AAGUID 标识认证器型号。
	AAGUID [16]byte `json:"aaguid"`
	// Transports lists transports reported at registration. | Transports 列出注册时报告的传输方式。
	Transports []string `json:"transports,omitempty"`
	// BackupEligible is the BE flag captured at registration. | BackupEligible 是注册时捕获的 BE 标志。
	BackupEligible bool `json:"backupEligible,omitempty"`
	// BackupState is the latest BS flag. | BackupState 是最新的 BS 标志。
	BackupState bool `json:"backupState,omitempty"`
	// Discoverable reports a discoverable (passkey) credential. | Discoverable 表示可发现（通行密钥）凭据。
	Discoverable bool `json:"discoverable,omitempty"`
	// Disabled excludes the credential from authentication. | Disabled 表示凭据不参与认证。
	Disabled bool `json:"disabled,omitempty"`
	// Name is a user-visible label. | Name 是用户可见标签。
	Name string `json:"name,omitempty"`
	// AttestationType records the verified attestation class. | AttestationType 记录已校验的认证声明类别。
	AttestationType AttestationType `json:"attestationType,omitempty"`
	// CreatedAt and LastUsedAt are UTC timestamps. | CreatedAt 与 LastUsedAt 是 UTC 时间戳。
	CreatedAt  time.Time `json:"createdAt"`
	LastUsedAt time.Time `json:"lastUsedAt,omitempty"`
}

// Clone returns a deep copy of c. | Clone 返回 c 的深拷贝。
func (c *Credential) Clone() *Credential {
	if c == nil {
		return nil
	}
	out := *c
	out.ID = append([]byte(nil), c.ID...)
	out.UserHandle = append([]byte(nil), c.UserHandle...)
	out.Transports = append([]string(nil), c.Transports...)
	out.PublicKey = cloneCOSEKey(c.PublicKey)
	return &out
}

// CredentialIDBase64 returns the unpadded base64url credential ID. | CredentialIDBase64 返回无填充 base64url 凭据 ID。
func (c *Credential) CredentialIDBase64() string {
	if c == nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(c.ID)
}

// Descriptor returns the allowCredentials or excludeCredentials form of the credential. | Descriptor 返回凭据的 allowCredentials 或 excludeCredentials 形式。
func (c *Credential) Descriptor() CredentialDescriptor {
	if c == nil {
		return CredentialDescriptor{}
	}
	return CredentialDescriptor{
		Type:       "public-key",
		ID:         base64.RawURLEncoding.EncodeToString(c.ID),
		Transports: append([]string(nil), c.Transports...),
	}
}

func cloneCOSEKey(key *COSEKey) *COSEKey {
	if key == nil {
		return nil
	}
	out := *key
	out.Kid = append([]byte(nil), key.Kid...)
	out.X = append([]byte(nil), key.X...)
	out.Y = append([]byte(nil), key.Y...)
	out.N = append([]byte(nil), key.N...)
	out.E = append([]byte(nil), key.E...)
	return &out
}

// validateCredential checks invariants required by every CredentialStore. | validateCredential 检查每个 CredentialStore 都必须满足的不变量。
func validateCredential(credential *Credential) error {
	if credential == nil {
		return errs.Detail(ErrInvalidCredential, "nil credential | 凭据为空")
	}
	if len(credential.ID) == 0 || len(credential.ID) > maxCredentialIDLength {
		return errs.Detail(ErrInvalidCredential, "credential ID length %d is outside 1..%d | 凭据 ID 长度 %d 超出 1..%d",
			len(credential.ID), maxCredentialIDLength, len(credential.ID), maxCredentialIDLength)
	}
	if strings.TrimSpace(credential.UserID) == "" {
		return errs.Detail(ErrInvalidCredential, "credential user ID is empty | 凭据用户 ID 为空")
	}
	if credential.PublicKey == nil {
		return errs.Detail(ErrInvalidCredential, "credential public key is nil | 凭据公钥为空")
	}
	if _, err := credential.PublicKey.PublicKey(); err != nil {
		return errs.WrapDetail(err, ErrInvalidCredential, "credential public key is invalid | 凭据公钥非法")
	}
	return nil
}

// decodeCredentialResponseID validates id/rawId and returns the raw credential ID. | decodeCredentialResponseID 校验 id/rawId 并返回原始凭据 ID。
func decodeCredentialResponseID(id, rawID string) ([]byte, error) {
	if id == "" && rawID == "" {
		return nil, errs.Detail(ErrInvalidRequest, "credential id and rawId are empty | 凭据 id 与 rawId 为空")
	}
	decodedID, err := decodeBase64URLField("id", id, true)
	if err != nil {
		return nil, err
	}
	decodedRawID, err := decodeBase64URLField("rawId", rawID, true)
	if err != nil {
		return nil, err
	}
	if !constantTimeEqual(decodedID, decodedRawID) {
		return nil, errs.Detail(ErrCredentialIDMismatch, "id and rawId differ | id 与 rawId 不一致")
	}
	if len(decodedID) == 0 || len(decodedID) > maxCredentialIDLength {
		return nil, errs.Detail(ErrInvalidRequest, "credential ID length %d is outside 1..%d | 凭据 ID 长度 %d 超出 1..%d",
			len(decodedID), maxCredentialIDLength, len(decodedID), maxCredentialIDLength)
	}
	return decodedID, nil
}

// decodeBase64URLField decodes an unpadded base64url response field. | decodeBase64URLField 解码无填充 base64url 响应字段。
func decodeBase64URLField(field, value string, required bool) ([]byte, error) {
	if value == "" {
		if required {
			return nil, errs.Detail(ErrInvalidRequest, "%s is empty | %s 为空", field, field)
		}
		return nil, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidRequest, "%s is not unpadded base64url | %s 不是无填充 base64url", field, field)
	}
	return decoded, nil
}

// normalizeTransports removes empty, duplicate and malformed transport tokens. | normalizeTransports 去除空、重复与非法传输令牌。
func normalizeTransports(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || len(value) > 32 {
			continue
		}
		valid := true
		for i := 0; i < len(value); i++ {
			c := value[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
		if len(out) == 8 {
			break
		}
	}
	return out
}

// normalizeDescriptors validates caller-supplied credential descriptors. | normalizeDescriptors 校验调用方提供的凭据描述符。
func normalizeDescriptors(descriptors []CredentialDescriptor) ([]CredentialDescriptor, [][]byte, error) {
	out := make([]CredentialDescriptor, 0, len(descriptors))
	ids := make([][]byte, 0, len(descriptors))
	seen := make(map[string]struct{}, len(descriptors))
	for _, descriptor := range descriptors {
		typ := strings.TrimSpace(descriptor.Type)
		if typ == "" {
			typ = "public-key"
		}
		if typ != "public-key" {
			return nil, nil, errs.Detail(ErrInvalidRequest, "unsupported credential type %q | 不支持的凭据类型 %q", typ, typ)
		}
		id, err := decodeBase64URLField("credential descriptor id", descriptor.ID, true)
		if err != nil {
			return nil, nil, err
		}
		if len(id) == 0 || len(id) > maxCredentialIDLength {
			return nil, nil, errs.Detail(ErrInvalidRequest, "credential descriptor ID length %d | 凭据描述符 ID 长度 %d", len(id), len(id))
		}
		key := string(id)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, CredentialDescriptor{
			Type:       "public-key",
			ID:         base64.RawURLEncoding.EncodeToString(id),
			Transports: normalizeTransports(descriptor.Transports),
		})
		ids = append(ids, id)
	}
	return out, ids, nil
}

// descriptorIDsEqual reports whether id is present in ids. | descriptorIDsEqual 报告 id 是否存在于 ids。
func descriptorIDsEqual(ids [][]byte, id []byte) bool {
	for _, candidate := range ids {
		if constantTimeEqual(candidate, id) {
			return true
		}
	}
	return false
}
