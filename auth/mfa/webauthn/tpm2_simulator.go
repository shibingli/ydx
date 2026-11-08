package webauthn

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"sort"
	"sync"

	"github.com/shibingli/ydx/errs"
)

// softwareTPMPersistentEK is the handle of the simulated persistent endorsement key. | softwareTPMPersistentEK
// 是模拟的持久背书密钥句柄。
const softwareTPMPersistentEK uint32 = 0x81000001

// softwareTPMTransientAK is the handle of the simulated transient attestation key. |
// softwareTPMTransientAK 是模拟的临时认证密钥句柄。
const softwareTPMTransientAK uint32 = 0x80000000

// softwareTPMFirmwareVersion is the simulated TPM firmware version property. | softwareTPMFirmwareVersion
// 是模拟的 TPM 固件版本属性。
const softwareTPMFirmwareVersion uint32 = 0x00010000

// softwareTPMManufacturer is the simulated TPM manufacturer property ("YDX\x00"). |
// softwareTPMManufacturer 是模拟的 TPM 制造商属性（"YDX\x00"）。
const softwareTPMManufacturer uint32 = 0x59445800

// simulatorObject is an object loaded in the simulated TPM. | simulatorObject 是模拟 TPM 中加载的对象。
type simulatorObject struct {
	// public is the object public area. | public 是对象公钥区域。
	public TPMTPublic
	// raw is the exact marshaled public area. | raw 是精确编码的公钥区域。
	raw []byte
	// name is the object Name. | name 是对象 Name。
	name []byte
	// private is the object private key; it may be nil. | private 是对象私钥；可能为空。
	private crypto.PrivateKey
}

// softwareTPM is an in-process TPM 2.0 simulator used by tests. | softwareTPM 是测试使用的进程内
// TPM 2.0 模拟器。
//
// It implements TPM and the command subset required by endorsement-key credential activation:
// TPM2_ReadPublic, TPM2_MakeCredential, TPM2_ActivateCredential, TPM2_FlushContext and
// TPM2_GetCapability. Only password sessions with empty authorization values are accepted. The
// simulator is intentionally unexported and never used by production paths. | 它实现 TPM 接口以及背书
// 密钥凭据激活所需的命令子集：TPM2_ReadPublic、TPM2_MakeCredential、TPM2_ActivateCredential、
// TPM2_FlushContext 与 TPM2_GetCapability。仅接受空授权值的密码会话。模拟器刻意保持未导出，且绝不
// 用于生产路径。
type softwareTPM struct {
	mu      sync.Mutex
	objects map[uint32]*simulatorObject
	ek      uint32
	ak      uint32
	clock   uint64
	closed  bool
}

// newSoftwareTPM creates a simulated TPM with an RSA-2048 or ECC P-256 endorsement key and an ECDSA
// P-256 attestation key. | newSoftwareTPM 创建模拟 TPM，带 RSA-2048 或 ECC P-256 背书密钥以及 ECDSA
// P-256 认证密钥。
func newSoftwareTPM(ekType uint16) (*softwareTPM, error) {
	ekObject, err := newSimulatorEK(ekType)
	if err != nil {
		return nil, err
	}
	akObject, err := newSimulatorAK()
	if err != nil {
		return nil, err
	}
	return &softwareTPM{
		objects: map[uint32]*simulatorObject{
			softwareTPMPersistentEK: ekObject,
			softwareTPMTransientAK:  akObject,
		},
		ek: softwareTPMPersistentEK,
		ak: softwareTPMTransientAK,
	}, nil
}

// newSimulatorEK generates and describes an endorsement key. | newSimulatorEK 生成并描述背书密钥。
func newSimulatorEK(ekType uint16) (*simulatorObject, error) {
	public := TPMTPublic{
		Type:             ekType,
		NameAlg:          TPMAlgSHA256,
		ObjectAttributes: TPMAFixedTPM | TPMAFixedParent | TPMASensitiveDataOrigin | TPMAUserWithAuth | TPMAAdminWithPolicy | TPMANoDA | TPMARestricted | TPMADecrypt,
		Symmetric:        TPMSymDefObject{Algorithm: TPMAlgNULL},
		RSAScheme:        TPMTRSAScheme{Scheme: TPMAlgNULL},
		ECCScheme:        TPMTECCScheme{Scheme: TPMAlgNULL},
		KDF:              TPMTKDFScheme{Scheme: TPMAlgNULL},
	}
	var private crypto.PrivateKey
	switch ekType {
	case TPMAlgRSA:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrEKActivation, "simulated RSA endorsement key generation failed | 模拟 RSA 背书密钥生成失败")
		}
		public.KeyBits = 2048
		public.Exponent = tpmDefaultExponent
		public.RSAModulus = key.N.Bytes()
		private = key
	case TPMAlgECC:
		key, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrEKActivation, "simulated ECC endorsement key generation failed | 模拟 ECC 背书密钥生成失败")
		}
		point := key.PublicKey().Bytes()
		public.CurveID = TPMEccNISTP256
		public.ECCPoint = TPMSEccPoint{X: point[1:33], Y: point[33:]}
		private = key
	default:
		return nil, errs.Detail(ErrUnsupportedKey, "simulated endorsement key type %#04x | 模拟背书密钥类型 %#04x", ekType, ekType)
	}
	return newSimulatorObject(public, private)
}

// newSimulatorAK generates and describes an ECDSA P-256 attestation key. | newSimulatorAK 生成并描述
// ECDSA P-256 认证密钥。
func newSimulatorAK() (*simulatorObject, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrEKActivation, "simulated attestation key generation failed | 模拟认证密钥生成失败")
	}
	public := TPMTPublic{
		Type:             TPMAlgECC,
		NameAlg:          TPMAlgSHA256,
		ObjectAttributes: TPMAFixedTPM | TPMAFixedParent | TPMASensitiveDataOrigin | TPMAUserWithAuth | TPMASign,
		Symmetric:        TPMSymDefObject{Algorithm: TPMAlgNULL},
		ECCScheme:        TPMTECCScheme{Scheme: TPMAlgECDSA, HashAlg: TPMAlgSHA256},
		KDF:              TPMTKDFScheme{Scheme: TPMAlgNULL},
		CurveID:          TPMEccNISTP256,
		ECCPoint: TPMSEccPoint{
			X: key.X.FillBytes(make([]byte, 32)),
			Y: key.Y.FillBytes(make([]byte, 32)),
		},
	}
	return newSimulatorObject(public, key)
}

// newSimulatorObject validates a public area and derives its Name. | newSimulatorObject 校验公钥区域并
// 派生其 Name。
func newSimulatorObject(public TPMTPublic, private crypto.PrivateKey) (*simulatorObject, error) {
	if err := public.Validate(); err != nil {
		return nil, err
	}
	raw, err := public.Marshal()
	if err != nil {
		return nil, err
	}
	name, err := public.Name(raw)
	if err != nil {
		return nil, err
	}
	return &simulatorObject{public: public, raw: raw, name: name, private: private}, nil
}

// EKHandle returns the simulated endorsement key handle. | EKHandle 返回模拟背书密钥句柄。
func (s *softwareTPM) EKHandle() uint32 { return softwareTPMPersistentEK }

// AKHandle returns the simulated attestation key handle. | AKHandle 返回模拟认证密钥句柄。
func (s *softwareTPM) AKHandle() uint32 { return softwareTPMTransientAK }

// EKPublic returns the simulated endorsement key public area. | EKPublic 返回模拟背书密钥公钥区域。
func (s *softwareTPM) EKPublic() TPMTPublic {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.objects[softwareTPMPersistentEK].public
}

// AKPublic returns the simulated attestation key public area. | AKPublic 返回模拟认证密钥公钥区域。
func (s *softwareTPM) AKPublic() TPMTPublic {
	s.mu.Lock()
	defer s.mu.Unlock()
	object := s.objects[softwareTPMTransientAK]
	if object == nil {
		return TPMTPublic{}
	}
	return object.public
}

// AKSigner returns the simulated attestation private key for attestation fixtures. |
// AKSigner 返回用于认证声明测试夹具的模拟认证私钥。
func (s *softwareTPM) AKSigner() crypto.Signer {
	s.mu.Lock()
	defer s.mu.Unlock()
	object := s.objects[softwareTPMTransientAK]
	if object == nil {
		return nil
	}
	signer, _ := object.private.(crypto.Signer)
	return signer
}

// AKName returns the simulated attestation key Name. | AKName 返回模拟认证密钥 Name。
func (s *softwareTPM) AKName() TPM2BName {
	s.mu.Lock()
	defer s.mu.Unlock()
	object := s.objects[softwareTPMTransientAK]
	if object == nil {
		return TPM2BName{}
	}
	return TPM2BName{Name: append([]byte(nil), object.name...)}
}

// Execute implements TPM. | Execute 实现 TPM。
func (s *softwareTPM) Execute(ctx context.Context, command []byte) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, tpmContextError(ctx, err)
	}
	parsed, err := ParseTPM2Command(command)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, tpmClosedError()
	}
	switch parsed.CommandCode {
	case TPMCCReadPublic:
		return s.readPublic(parsed)
	case TPMCCFlushContext:
		return s.flushContext(parsed)
	case TPMCCGetCapability:
		return s.getCapability(parsed)
	case TPMCCMakeCredential:
		return s.makeCredential(parsed)
	case TPMCCActivateCredential:
		return s.activateCredential(parsed)
	default:
		return simulatorErrorResponse(TPMRCCommandCode), nil
	}
}

// Close implements TPM. | Close 实现 TPM。
func (s *softwareTPM) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.objects = map[uint32]*simulatorObject{}
	return nil
}

// readPublic handles TPM2_ReadPublic. | readPublic 处理 TPM2_ReadPublic。
func (s *softwareTPM) readPublic(command *TPM2Command) ([]byte, error) {
	object := s.objects[command.Handles[0]]
	if object == nil {
		return simulatorErrorResponse(TPMRCHandle), nil
	}
	parameters, err := tpm2AppendSized(nil, object.raw)
	if err != nil {
		return nil, err
	}
	parameters, err = tpm2AppendSized(parameters, object.name)
	if err != nil {
		return nil, err
	}
	parameters, err = tpm2AppendSized(parameters, object.name)
	if err != nil {
		return nil, err
	}
	return simulatorSuccessResponse(command, parameters), nil
}

// flushContext handles TPM2_FlushContext. | flushContext 处理 TPM2_FlushContext。
func (s *softwareTPM) flushContext(command *TPM2Command) ([]byte, error) {
	handle := command.Handles[0]
	if handle == softwareTPMPersistentEK {
		return simulatorErrorResponse(TPMRCHandle), nil
	}
	if s.objects[handle] == nil {
		return simulatorErrorResponse(TPMRCHandle), nil
	}
	delete(s.objects, handle)
	return simulatorSuccessResponse(command, nil), nil
}

// getCapability handles TPM2_GetCapability. | getCapability 处理 TPM2_GetCapability。
func (s *softwareTPM) getCapability(command *TPM2Command) ([]byte, error) {
	r := &tpm2Reader{data: command.Parameters}
	capability, err := r.u32()
	if err != nil {
		return simulatorErrorResponse(TPMRCSize), nil
	}
	property, err := r.u32()
	if err != nil {
		return simulatorErrorResponse(TPMRCSize), nil
	}
	count, err := r.u32()
	if err != nil {
		return simulatorErrorResponse(TPMRCSize), nil
	}
	if !r.done() || count == 0 {
		return simulatorErrorResponse(TPMRCSize), nil
	}
	if count > 64 {
		count = 64
	}
	parameters := make([]byte, 0, 64)
	switch capability {
	case TPMCapHandles:
		handles := make([]uint32, 0, len(s.objects))
		for handle := range s.objects {
			if handle >= property {
				handles = append(handles, handle)
			}
		}
		sort.Slice(handles, func(i, j int) bool { return handles[i] < handles[j] })
		more := len(handles) > int(count)
		if more {
			handles = handles[:count]
		}
		parameters = append(parameters, simulatorMoreData(more))
		parameters = tpm2AppendU32(parameters, capability)
		parameters = tpm2AppendU32(parameters, uint32(len(handles)))
		for _, handle := range handles {
			parameters = tpm2AppendU32(parameters, handle)
		}
	case TPMCapTPMProperties:
		type entry struct {
			property uint32
			value    uint32
		}
		all := []entry{
			{TPMPropertyManufacturer, softwareTPMManufacturer},
			{TPMPropertyFirmwareVersion1, softwareTPMFirmwareVersion},
		}
		filtered := make([]entry, 0, len(all))
		for _, item := range all {
			if item.property >= property {
				filtered = append(filtered, item)
			}
		}
		more := len(filtered) > int(count)
		if more {
			filtered = filtered[:count]
		}
		parameters = append(parameters, simulatorMoreData(more))
		parameters = tpm2AppendU32(parameters, capability)
		parameters = tpm2AppendU32(parameters, uint32(len(filtered)))
		for _, item := range filtered {
			parameters = tpm2AppendU32(parameters, item.property)
			parameters = tpm2AppendU32(parameters, item.value)
		}
	default:
		return simulatorErrorResponse(TPMRCValue), nil
	}
	return simulatorSuccessResponse(command, parameters), nil
}

// makeCredential handles TPM2_MakeCredential. | makeCredential 处理 TPM2_MakeCredential。
func (s *softwareTPM) makeCredential(command *TPM2Command) ([]byte, error) {
	object := s.objects[command.Handles[0]]
	if object == nil {
		return simulatorErrorResponse(TPMRCHandle), nil
	}
	r := &tpm2Reader{data: command.Parameters}
	credential, err := r.sized(64)
	if err != nil {
		return simulatorErrorResponse(TPMRCSize), nil
	}
	akNameRaw, err := r.sized(maxTPMNameSize)
	if err != nil {
		return simulatorErrorResponse(TPMRCSize), nil
	}
	if !r.done() {
		return simulatorErrorResponse(TPMRCSize), nil
	}
	akName := TPM2BName{Name: akNameRaw}
	if err := akName.Validate(); err != nil {
		return simulatorErrorResponse(TPMRCValue), nil
	}
	result, err := MakeCredential(&object.public, akName, credential)
	if err != nil {
		return simulatorErrorFrom(err), nil
	}
	parameters, err := result.CredentialBlob.AppendTo(nil)
	if err != nil {
		return nil, err
	}
	parameters, err = result.Secret.AppendTo(parameters)
	if err != nil {
		return nil, err
	}
	return simulatorSuccessResponse(command, parameters), nil
}

// activateCredential handles TPM2_ActivateCredential. | activateCredential 处理
// TPM2_ActivateCredential。
func (s *softwareTPM) activateCredential(command *TPM2Command) ([]byte, error) {
	if command.Tag != TPMSTSessions || len(command.Auth) != 2 {
		return simulatorErrorResponse(TPMRCAuthMissing), nil
	}
	for _, auth := range command.Auth {
		if auth.SessionHandle != TPMRSPassword || len(auth.Nonce) != 0 || auth.SessionAttributes != 0 || len(auth.HMAC) != 0 {
			return simulatorErrorResponse(TPMRCAuthType), nil
		}
	}
	akObject := s.objects[command.Handles[0]]
	ekObject := s.objects[command.Handles[1]]
	if akObject == nil || ekObject == nil {
		return simulatorErrorResponse(TPMRCHandle), nil
	}
	if len(ekObject.public.RSAModulus) == 0 && len(ekObject.public.ECCPoint.X) == 0 {
		return simulatorErrorResponse(TPMRCType), nil
	}
	r := &tpm2Reader{data: command.Parameters}
	blobRaw, err := r.sized(MaxTPM2BUFFERSize)
	if err != nil {
		return simulatorErrorResponse(TPMRCSize), nil
	}
	secretRaw, err := r.sized(MaxTPM2BUFFERSize)
	if err != nil {
		return simulatorErrorResponse(TPMRCSize), nil
	}
	if !r.done() {
		return simulatorErrorResponse(TPMRCSize), nil
	}
	credential, err := ActivateCredential(
		&ekObject.public,
		ekObject.private,
		TPM2BName{Name: akObject.name},
		TPM2BIDObject{Buffer: blobRaw},
		TPM2BEncryptedSecret{Buffer: secretRaw},
	)
	if err != nil {
		return simulatorErrorFrom(err), nil
	}
	s.clock++
	attest := TPMSAttest{
		Magic:           TPMGeneratedValue,
		Type:            TPMStAttestCertify,
		ExtraData:       credential,
		ClockInfo:       TPMSClockInfo{Clock: s.clock, Safe: 1},
		FirmwareVersion: uint64(softwareTPMFirmwareVersion),
		Name:            append([]byte(nil), akObject.name...),
		QualifiedName:   append([]byte(nil), akObject.name...),
	}
	encoded, err := attest.Marshal()
	if err != nil {
		return nil, err
	}
	parameters, err := tpm2AppendSized(nil, encoded)
	if err != nil {
		return nil, err
	}
	return simulatorSuccessResponse(command, parameters), nil
}

// simulatorSuccessResponse builds a success response matching the command tag. | simulatorSuccessResponse
// 构建与命令标签匹配的成功响应。
func simulatorSuccessResponse(command *TPM2Command, parameters []byte) []byte {
	if command.Tag == TPMSTNoSessions {
		size := 10 + len(parameters)
		out := make([]byte, 0, size)
		out = tpm2AppendU16(out, TPMSTNoSessions)
		out = tpm2AppendU32(out, uint32(size))
		out = tpm2AppendU32(out, TPMRCSuccess)
		return append(out, parameters...)
	}
	authSize := 0
	for range command.Auth {
		authSize += 5
	}
	size := 10 + 4 + len(parameters) + authSize
	out := make([]byte, 0, size)
	out = tpm2AppendU16(out, TPMSTSessions)
	out = tpm2AppendU32(out, uint32(size))
	out = tpm2AppendU32(out, TPMRCSuccess)
	out = tpm2AppendU32(out, uint32(len(parameters)))
	out = append(out, parameters...)
	for range command.Auth {
		out = tpm2AppendU16(out, 0)
		out = append(out, 0)
		out = tpm2AppendU16(out, 0)
	}
	return out
}

// simulatorErrorResponse builds a TPM error response. | simulatorErrorResponse 构建 TPM 错误响应。
func simulatorErrorResponse(code uint32) []byte {
	out := make([]byte, 0, 10)
	out = tpm2AppendU16(out, TPMSTNoSessions)
	out = tpm2AppendU32(out, 10)
	out = tpm2AppendU32(out, code)
	return out
}

// simulatorErrorFrom maps a software credential error to the closest TPM response code. |
// simulatorErrorFrom 把软件凭据错误映射为最接近的 TPM 响应码。
func simulatorErrorFrom(err error) []byte {
	switch {
	case err == nil:
		return simulatorErrorResponse(TPMRCSuccess)
	case isTPMStructureError(err):
		return simulatorErrorResponse(TPMRCSize)
	default:
		return simulatorErrorResponse(TPMRCIntegrity)
	}
}

// simulatorMoreData encodes the TPMI_YES_NO byte. | simulatorMoreData 编码 TPMI_YES_NO 字节。
func simulatorMoreData(more bool) byte {
	if more {
		return 1
	}
	return 0
}

// isTPMStructureError reports whether err carries ErrTPMStructure. | isTPMStructureError 报告 err 是否
// 携带 ErrTPMStructure。
func isTPMStructureError(err error) bool {
	return errors.Is(err, ErrTPMStructure)
}
