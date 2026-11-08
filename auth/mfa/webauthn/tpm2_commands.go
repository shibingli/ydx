package webauthn

import (
	"context"

	"github.com/shibingli/ydx/errs"
)

// TPMReadPublicResult is the TPM2_ReadPublic response. | TPMReadPublicResult 是 TPM2_ReadPublic 响应。
type TPMReadPublicResult struct {
	// Public is the object public area. | Public 是对象公钥区域。
	Public TPM2BPublic
	// Name is the object Name returned by the TPM. | Name 是 TPM 返回的对象 Name。
	Name TPM2BName
	// QualifiedName is the qualified Name; it may be empty. | QualifiedName 是限定 Name；可能为空。
	QualifiedName TPM2BName
}

// ReadPublic executes TPM2_ReadPublic for a persistent or transient object handle. | ReadPublic 对持久或
// 临时对象句柄执行 TPM2_ReadPublic。
//
// The response Name is recomputed from the returned public area and rejected with ErrTPMStructure when
// it differs, so callers never accept a Name that does not bind the public area. | 响应中的 Name 会用返回
// 的公钥区域重新计算，不一致时以 ErrTPMStructure 拒绝，因此调用方不会接受未绑定公钥区域的 Name。
func ReadPublic(ctx context.Context, device TPM, handle uint32) (*TPMReadPublicResult, error) {
	command := &TPM2Command{Tag: TPMSTNoSessions, CommandCode: TPMCCReadPublic, Handles: []uint32{handle}}
	response, err := TPM2Call(ctx, device, command)
	if err != nil {
		return nil, err
	}
	r := &tpm2Reader{data: response.Parameters}
	public, consumed, err := ParseTPM2BPublic(r.data[r.off:])
	if err != nil {
		return nil, err
	}
	r.off += consumed
	nameRaw, err := r.sized(maxTPMNameSize)
	if err != nil {
		return nil, err
	}
	name := TPM2BName{Name: append([]byte(nil), nameRaw...)}
	if err := name.Validate(); err != nil {
		return nil, err
	}
	qualifiedRaw, err := r.sized(maxTPMNameSize)
	if err != nil {
		return nil, err
	}
	qualified := TPM2BName{}
	if len(qualifiedRaw) > 0 {
		qualified.Name = append([]byte(nil), qualifiedRaw...)
		if err := qualified.Validate(); err != nil {
			return nil, err
		}
	}
	if !r.done() {
		return nil, errs.Detail(ErrTPMStructure, "TPM2_ReadPublic response has %d trailing bytes | TPM2_ReadPublic 响应有 %d 个多余字节",
			r.remaining(), r.remaining())
	}
	computed, err := public.Name()
	if err != nil {
		return nil, err
	}
	if !constantTimeEqual(computed, name.Name) {
		return nil, errs.Detail(ErrTPMStructure, "TPM2_ReadPublic Name does not match the public area | TPM2_ReadPublic Name 与公钥区域不一致")
	}
	return &TPMReadPublicResult{Public: public, Name: name, QualifiedName: qualified}, nil
}

// FlushContext executes TPM2_FlushContext. | FlushContext 执行 TPM2_FlushContext。
func FlushContext(ctx context.Context, device TPM, handle uint32) error {
	command := &TPM2Command{Tag: TPMSTNoSessions, CommandCode: TPMCCFlushContext, Handles: []uint32{handle}}
	response, err := TPM2Call(ctx, device, command)
	if err != nil {
		return err
	}
	if len(response.Parameters) != 0 {
		return errs.Detail(ErrTPMStructure, "TPM2_FlushContext response has %d parameters | TPM2_FlushContext 响应有 %d 个参数",
			len(response.Parameters), len(response.Parameters))
	}
	return nil
}

// TPMTaggedProperty is a TPMS_TAGGED_PROPERTY. | TPMTaggedProperty 是 TPMS_TAGGED_PROPERTY。
type TPMTaggedProperty struct {
	// Property is the TPM_PT property identifier. | Property 是 TPM_PT 属性标识。
	Property uint32
	// Value is the property value. | Value 是属性值。
	Value uint32
}

// TPMGetCapabilityResult is the TPM2_GetCapability response for handle and property capabilities. |
// TPMGetCapabilityResult 是 TPM2_GetCapability 针对句柄与属性能力查询的响应。
type TPMGetCapabilityResult struct {
	// MoreData reports whether more capability data is available. | MoreData 报告是否还有更多能力数据。
	MoreData bool
	// Handles holds TPMCapHandles results. | Handles 保存 TPMCapHandles 结果。
	Handles []uint32
	// Properties holds TPMCapTPMProperties results. | Properties 保存 TPMCapTPMProperties 结果。
	Properties []TPMTaggedProperty
}

// GetCapability executes TPM2_GetCapability for handle or TPM property capabilities. | GetCapability
// 对句柄或 TPM 属性能力执行 TPM2_GetCapability。
//
// capability is TPMCapHandles or TPMCapTPMProperties; other capability families are rejected with
// ErrNotSupported because the subsystem does not consume them. | capability 为 TPMCapHandles 或
// TPMCapTPMProperties；其他能力族以 ErrNotSupported 拒绝，因为本子系统不消费它们。
func GetCapability(ctx context.Context, device TPM, capability, property, count uint32) (*TPMGetCapabilityResult, error) {
	parameters := make([]byte, 0, 12)
	parameters = tpm2AppendU32(parameters, capability)
	parameters = tpm2AppendU32(parameters, property)
	parameters = tpm2AppendU32(parameters, count)
	command := &TPM2Command{Tag: TPMSTNoSessions, CommandCode: TPMCCGetCapability, Parameters: parameters}
	response, err := TPM2Call(ctx, device, command)
	if err != nil {
		return nil, err
	}
	r := &tpm2Reader{data: response.Parameters}
	more, err := r.u8()
	if err != nil {
		return nil, err
	}
	if more > 1 {
		return nil, errs.Detail(ErrTPMStructure, "TPM2_GetCapability moreData byte is %d | TPM2_GetCapability moreData 字节为 %d", more, more)
	}
	returnedCapability, err := r.u32()
	if err != nil {
		return nil, err
	}
	if returnedCapability != capability {
		return nil, errs.Detail(ErrTPMStructure, "TPM2_GetCapability returned capability %#08x, requested %#08x | TPM2_GetCapability 返回能力 %#08x，请求 %#08x",
			returnedCapability, capability, returnedCapability, capability)
	}
	result := &TPMGetCapabilityResult{MoreData: more == 1}
	entryCount, err := r.u32()
	if err != nil {
		return nil, err
	}
	switch capability {
	case TPMCapHandles:
		if uint64(entryCount) > uint64(r.remaining()/4) {
			return nil, errs.Detail(ErrTPMStructure, "TPM handle count %d exceeds the response size | TPM 句柄数 %d 超过响应大小",
				entryCount, entryCount)
		}
		result.Handles = make([]uint32, 0, entryCount)
		for index := uint32(0); index < entryCount; index++ {
			handle, err := r.u32()
			if err != nil {
				return nil, err
			}
			result.Handles = append(result.Handles, handle)
		}
	case TPMCapTPMProperties:
		if uint64(entryCount) > uint64(r.remaining()/8) {
			return nil, errs.Detail(ErrTPMStructure, "TPM property count %d exceeds the response size | TPM 属性数 %d 超过响应大小",
				entryCount, entryCount)
		}
		result.Properties = make([]TPMTaggedProperty, 0, entryCount)
		for index := uint32(0); index < entryCount; index++ {
			name, err := r.u32()
			if err != nil {
				return nil, err
			}
			value, err := r.u32()
			if err != nil {
				return nil, err
			}
			result.Properties = append(result.Properties, TPMTaggedProperty{Property: name, Value: value})
		}
	default:
		return nil, errs.Detail(ErrNotSupported, "TPM2_GetCapability capability %#08x is not parsed | 未解析 TPM2_GetCapability 能力 %#08x",
			capability, capability)
	}
	if !r.done() {
		return nil, errs.Detail(ErrTPMStructure, "TPM2_GetCapability response has %d trailing bytes | TPM2_GetCapability 响应有 %d 个多余字节",
			r.remaining(), r.remaining())
	}
	return result, nil
}

// MakeCredentialCommand executes TPM2_MakeCredential on device for keyHandle. | MakeCredentialCommand
// 对 keyHandle 在 device 上执行 TPM2_MakeCredential。
//
// The TPM protects credential for the object named by akName; the returned blob and secret are
// consumed by ActivateCredentialCommand. credential must not exceed the largest supported digest. |
// TPM 为 akName 命名的对象保护 credential；返回的 blob 与 secret 由 ActivateCredentialCommand 消费。
// credential 不得超过支持的最大摘要长度。
func MakeCredentialCommand(ctx context.Context, device TPM, keyHandle uint32, credential []byte, akName TPM2BName) (*TPMMakeCredentialResult, error) {
	if len(credential) > 64 {
		return nil, errs.Detail(ErrTPMStructure, "TPM2_MakeCredential credential is %d bytes, limit is 64 | TPM2_MakeCredential 凭据为 %d 字节，上限为 64",
			len(credential), len(credential))
	}
	if err := akName.Validate(); err != nil {
		return nil, err
	}
	nameRaw, err := akName.Marshal()
	if err != nil {
		return nil, err
	}
	parameters, err := tpm2AppendSized(nil, credential)
	if err != nil {
		return nil, err
	}
	parameters = append(parameters, nameRaw...)
	command := &TPM2Command{
		Tag:         TPMSTNoSessions,
		CommandCode: TPMCCMakeCredential,
		Handles:     []uint32{keyHandle},
		Parameters:  parameters,
	}
	response, err := TPM2Call(ctx, device, command)
	if err != nil {
		return nil, err
	}
	r := &tpm2Reader{data: response.Parameters}
	blob, err := r.sized(MaxTPM2BUFFERSize)
	if err != nil {
		return nil, err
	}
	secret, err := r.sized(MaxTPM2BUFFERSize)
	if err != nil {
		return nil, err
	}
	if !r.done() {
		return nil, errs.Detail(ErrTPMStructure, "TPM2_MakeCredential response has %d trailing bytes | TPM2_MakeCredential 响应有 %d 个多余字节",
			r.remaining(), r.remaining())
	}
	return &TPMMakeCredentialResult{
		CredentialBlob: TPM2BIDObject{Buffer: append([]byte(nil), blob...)},
		Secret:         TPM2BEncryptedSecret{Buffer: append([]byte(nil), secret...)},
	}, nil
}

// ActivateCredentialCommand executes TPM2_ActivateCredential on device and returns certInfo. |
// ActivateCredentialCommand 在 device 上执行 TPM2_ActivateCredential 并返回 certInfo。
// activateHandle is the loaded attestation key and keyHandle the loaded endorsement key. Both are
// authorized with an empty password, which is valid only when their authorization values are empty.
// The returned TPM2B_ATTEST is parsed by VerifyActivationCertInfo. | activateHandle 是已加载的认证密钥，
// keyHandle 是已加载的背书密钥。两者都以空密码授权，仅当其授权值为空时有效。返回的 TPM2B_ATTEST 由
// VerifyActivationCertInfo 解析。
func ActivateCredentialCommand(ctx context.Context, device TPM, activateHandle, keyHandle uint32, blob TPM2BIDObject, secret TPM2BEncryptedSecret) (TPM2BAttest, error) {
	parameters, err := blob.AppendTo(nil)
	if err != nil {
		return TPM2BAttest{}, err
	}
	parameters, err = secret.AppendTo(parameters)
	if err != nil {
		return TPM2BAttest{}, err
	}
	command := &TPM2Command{
		Tag:         TPMSTSessions,
		CommandCode: TPMCCActivateCredential,
		Handles:     []uint32{activateHandle, keyHandle},
		Auth:        []TPMSAuthCommand{tpm2PasswordAuth(), tpm2PasswordAuth()},
		Parameters:  parameters,
	}
	response, err := TPM2Call(ctx, device, command)
	if err != nil {
		return TPM2BAttest{}, err
	}
	r := &tpm2Reader{data: response.Parameters}
	size, err := r.u16()
	if err != nil {
		return TPM2BAttest{}, err
	}
	attest, err := r.bytes(int(size))
	if err != nil {
		return TPM2BAttest{}, err
	}
	if !r.done() {
		return TPM2BAttest{}, errs.Detail(ErrTPMStructure, "TPM2_ActivateCredential response has %d trailing bytes | TPM2_ActivateCredential 响应有 %d 个多余字节",
			r.remaining(), r.remaining())
	}
	return TPM2BAttest{Buffer: append([]byte(nil), attest...)}, nil
}
