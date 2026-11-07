package webauthn

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"

	"github.com/shibingli/ydx/errs"
)

// Authenticator data layout constants. | 认证器数据布局常量。
const (
	// authenticatorDataMinLen is the size without attested credential data or extensions. | authenticatorDataMinLen 是不含认证凭据数据与扩展时的长度。
	authenticatorDataMinLen = 37
	// maxCredentialIDLength is the WebAuthn upper bound for a credential ID. | maxCredentialIDLength 是 WebAuthn 凭据 ID 的上限。
	maxCredentialIDLength = 1023
)

// Flags are the authenticator data flag bits defined by WebAuthn. | Flags 是 WebAuthn 定义的认证器数据标志位。
type Flags uint8

// The WebAuthn authenticator data flags. | WebAuthn 认证器数据标志。
const (
	// FlagUserPresent is bit 0 (UP). | FlagUserPresent 是第 0 位（UP）。
	FlagUserPresent Flags = 0x01
	// FlagUserVerified is bit 2 (UV). | FlagUserVerified 是第 2 位（UV）。
	FlagUserVerified Flags = 0x04
	// FlagBackupEligible is bit 3 (BE). | FlagBackupEligible 是第 3 位（BE）。
	FlagBackupEligible Flags = 0x08
	// FlagBackupState is bit 4 (BS). | FlagBackupState 是第 4 位（BS）。
	FlagBackupState Flags = 0x10
	// FlagAttestedCredentialData is bit 6 (AT). | FlagAttestedCredentialData 是第 6 位（AT）。
	FlagAttestedCredentialData Flags = 0x40
	// FlagExtensionData is bit 7 (ED). | FlagExtensionData 是第 7 位（ED）。
	FlagExtensionData Flags = 0x80
)

// UserPresent reports the UP flag. | UserPresent 报告 UP 标志。
func (f Flags) UserPresent() bool { return f&FlagUserPresent != 0 }

// UserVerified reports the UV flag. | UserVerified 报告 UV 标志。
func (f Flags) UserVerified() bool { return f&FlagUserVerified != 0 }

// BackupEligible reports the BE flag. | BackupEligible 报告 BE 标志。
func (f Flags) BackupEligible() bool { return f&FlagBackupEligible != 0 }

// BackupState reports the BS flag. | BackupState 报告 BS 标志。
func (f Flags) BackupState() bool { return f&FlagBackupState != 0 }

// AttestedCredentialData reports the AT flag. | AttestedCredentialData 报告 AT 标志。
func (f Flags) AttestedCredentialData() bool { return f&FlagAttestedCredentialData != 0 }

// ExtensionsPresent reports the ED flag. | ExtensionsPresent 报告 ED 标志。
func (f Flags) ExtensionsPresent() bool { return f&FlagExtensionData != 0 }

// AuthenticatorData is the parsed WebAuthn authenticator data structure. | AuthenticatorData 是解析后的 WebAuthn 认证器数据结构。
type AuthenticatorData struct {
	// RPIDHash is the SHA-256 hash of the relying party identifier. | RPIDHash 是依赖方标识的 SHA-256 哈希。
	RPIDHash [32]byte
	// Flags holds the authenticator flags. | Flags 保存认证器标志。
	Flags Flags
	// SignCount is the authenticator signature counter. | SignCount 是认证器签名计数器。
	SignCount uint32
	// AAGUID identifies the authenticator model when AT is set. | AAGUID 在设置 AT 时标识认证器型号。
	AAGUID [16]byte
	// CredentialID is the raw credential identifier when AT is set. | CredentialID 在设置 AT 时保存原始凭据标识。
	CredentialID []byte
	// CredentialPublicKey is the parsed COSE public key when AT is set. | CredentialPublicKey 在设置 AT 时保存解析后的 COSE 公钥。
	CredentialPublicKey *COSEKey
	// CredentialPublicKeyRaw is the exact CBOR bytes of CredentialPublicKey. | CredentialPublicKeyRaw 是 CredentialPublicKey 的原始 CBOR 字节。
	CredentialPublicKeyRaw []byte
	// Extensions is the decoded extension map when ED is set. | Extensions 在设置 ED 时保存解码后的扩展映射。
	Extensions *Value
	// Raw is the complete authenticator data. | Raw 是完整的认证器数据。
	Raw []byte
}

// ParseAuthenticatorData parses and validates WebAuthn authenticator data. | ParseAuthenticatorData 解析并校验 WebAuthn 认证器数据。
//
// The function enforces the minimum length, the credential ID bounds, the BS implies BE rule,
// extension map shape and the absence of trailing bytes. | 该函数强制检查最小长度、凭据 ID 边界、
// BS 蕴含 BE 规则、扩展映射形态以及不存在尾随字节。
func ParseAuthenticatorData(data []byte) (*AuthenticatorData, error) {
	if len(data) < authenticatorDataMinLen {
		return nil, errs.Detail(ErrInvalidAuthenticatorData, "length %d is below the minimum %d | 长度 %d 小于最小值 %d",
			len(data), authenticatorDataMinLen, len(data), authenticatorDataMinLen)
	}
	a := &AuthenticatorData{
		Flags:     Flags(data[32]),
		SignCount: binary.BigEndian.Uint32(data[33:37]),
		Raw:       append([]byte(nil), data...),
	}
	copy(a.RPIDHash[:], data[:32])
	if a.Flags.BackupState() && !a.Flags.BackupEligible() {
		return nil, errs.Detail(ErrInvalidAuthenticatorData, "BS is set without BE | 设置 BS 但未设置 BE")
	}
	offset := authenticatorDataMinLen
	if a.Flags.AttestedCredentialData() {
		if len(data) < offset+18 {
			return nil, errs.Detail(ErrInvalidAuthenticatorData, "truncated attested credential data | 认证凭据数据被截断")
		}
		copy(a.AAGUID[:], data[offset:offset+16])
		offset += 16
		idLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if idLen == 0 || idLen > maxCredentialIDLength {
			return nil, errs.Detail(ErrInvalidAuthenticatorData, "credential ID length %d is outside 1..%d | 凭据 ID 长度 %d 超出 1..%d",
				idLen, maxCredentialIDLength, idLen, maxCredentialIDLength)
		}
		if len(data) < offset+idLen {
			return nil, errs.Detail(ErrInvalidAuthenticatorData, "truncated credential ID | 凭据 ID 被截断")
		}
		a.CredentialID = append([]byte(nil), data[offset:offset+idLen]...)
		offset += idLen
		keyValue, consumed, err := DecodeFirst(data[offset:])
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidAuthenticatorData, "credential public key is not valid CBOR | 凭据公钥不是合法 CBOR")
		}
		key, err := ParseCOSEKeyValue(keyValue)
		if err != nil {
			return nil, err
		}
		a.CredentialPublicKey = key
		a.CredentialPublicKeyRaw = append([]byte(nil), data[offset:offset+consumed]...)
		offset += consumed
	}
	if a.Flags.ExtensionsPresent() {
		extValue, consumed, err := DecodeFirst(data[offset:])
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidAuthenticatorData, "extensions are not valid CBOR | 扩展不是合法 CBOR")
		}
		if extValue.Kind != KindMap {
			return nil, errs.Detail(ErrInvalidAuthenticatorData, "extensions are not a map | 扩展不是映射")
		}
		a.Extensions = extValue
		offset += consumed
	}
	if offset != len(data) {
		return nil, errs.Detail(ErrInvalidAuthenticatorData, "%d trailing bytes | %d 个尾随字节", len(data)-offset, len(data)-offset)
	}
	return a, nil
}

// VerifyRPIDHash checks the RP ID hash with a constant-time comparison. | VerifyRPIDHash 以常量时间比较 RP ID 哈希。
func (a *AuthenticatorData) VerifyRPIDHash(rpID string) error {
	if a == nil {
		return errs.Detail(ErrInvalidAuthenticatorData, "nil authenticator data | 空认证器数据")
	}
	sum := sha256.Sum256([]byte(rpID))
	if !constantTimeEqual(a.RPIDHash[:], sum[:]) {
		return errs.Detail(ErrRPIDMismatch, "authenticator data was produced for another RP ID | 认证器数据由其他 RP ID 生成")
	}
	return nil
}

// AAGUIDIsZero reports whether the AAGUID is all zero. | AAGUIDIsZero 报告 AAGUID 是否全为零。
func (a *AuthenticatorData) AAGUIDIsZero() bool {
	if a == nil {
		return true
	}
	var zero [16]byte
	return constantTimeEqual(a.AAGUID[:], zero[:])
}

// Extension returns an extension value by name. | Extension 按名称返回扩展值。
func (a *AuthenticatorData) Extension(name string) (*Value, bool) {
	if a == nil || a.Extensions == nil {
		return nil, false
	}
	return a.Extensions.MapGetText(name)
}

// ExtensionBool returns a boolean extension value. | ExtensionBool 返回布尔扩展值。
func (a *AuthenticatorData) ExtensionBool(name string) (bool, bool) {
	v, ok := a.Extension(name)
	if !ok || v.Kind != KindSimple {
		return false, false
	}
	switch v.Simple {
	case 20:
		return false, true
	case 21:
		return true, true
	default:
		return false, false
	}
}

// ExtensionString returns a text extension value. | ExtensionString 返回文本扩展值。
func (a *AuthenticatorData) ExtensionString(name string) (string, bool) {
	v, ok := a.Extension(name)
	if !ok || v.Kind != KindText {
		return "", false
	}
	return v.Text, true
}

// ExtensionNames returns the sorted names of the present extensions. | ExtensionNames 返回当前扩展的名称列表。
func (a *AuthenticatorData) ExtensionNames() []string {
	if a == nil || a.Extensions == nil {
		return nil
	}
	names := make([]string, 0, len(a.Extensions.Pairs))
	for i := range a.Extensions.Pairs {
		if a.Extensions.Pairs[i].Key.Kind == KindText {
			names = append(names, a.Extensions.Pairs[i].Key.Text)
		}
	}
	sort.Strings(names)
	return names
}

// CredentialProtection returns the credProtect extension value. | CredentialProtection 返回 credProtect 扩展值。
func (a *AuthenticatorData) CredentialProtection() (string, bool) {
	value, ok := a.ExtensionString("credProtect")
	if !ok {
		return "", false
	}
	switch value {
	case "userVerificationOptional", "userVerificationOptionalWithCredentialIDList", "userVerificationRequired":
		return value, true
	default:
		return "", false
	}
}
