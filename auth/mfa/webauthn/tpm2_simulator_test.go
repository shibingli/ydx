package webauthn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
)

// testSoftwareTPMCredential derives a per-scenario credential value. | testSoftwareTPMCredential 派生
// 每个场景的凭据值。
func testSoftwareTPMCredential(label string) []byte {
	digest := sha256.Sum256([]byte(label))
	return digest[:]
}

// TestSoftwareTPMActivation checks the complete simulator activation path for RSA and ECC EKs. |
// TestSoftwareTPMActivation 校验 RSA 与 ECC 背书密钥的完整模拟器激活路径。
func TestSoftwareTPMActivation(t *testing.T) {
	cases := []struct {
		name   string
		ekType uint16
	}{
		{name: "rsa", ekType: TPMAlgRSA},
		{name: "ecc", ekType: TPMAlgECC},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			simulator, err := newSoftwareTPM(testCase.ekType)
			if err != nil {
				t.Fatalf("newSoftwareTPM(%#04x) error = %v", testCase.ekType, err)
			}
			defer func() {
				if err := simulator.Close(); err != nil {
					t.Fatalf("Close error = %v", err)
				}
			}()
			ctx := t.Context()

			read, err := ReadPublic(ctx, simulator, simulator.EKHandle())
			if err != nil {
				t.Fatalf("ReadPublic error = %v", err)
			}
			if read.Public.Public.Type != testCase.ekType {
				t.Fatalf("EK type = %#04x, want %#04x", read.Public.Public.Type, testCase.ekType)
			}
			computed, err := read.Public.Name()
			if err != nil {
				t.Fatalf("public Name error = %v", err)
			}
			if !bytes.Equal(read.Name.Name, computed) {
				t.Fatalf("ReadPublic Name = %x, computed %x", read.Name.Name, computed)
			}
			if !bytes.Equal(read.QualifiedName.Name, computed) {
				t.Fatalf("qualified Name = %x, computed %x", read.QualifiedName.Name, computed)
			}
			if err := simulator.AKName().Validate(); err != nil {
				t.Fatalf("AKName error = %v", err)
			}
			if !read.Public.Public.IsRestrictedDecrypt() {
				t.Fatal("simulated EK is not a restricted decrypt key")
			}

			credential := testSoftwareTPMCredential("activation-" + testCase.name)
			made, err := MakeCredentialCommand(ctx, simulator, simulator.EKHandle(), credential, simulator.AKName())
			if err != nil {
				t.Fatalf("MakeCredentialCommand error = %v", err)
			}
			if len(made.CredentialBlob.Buffer) == 0 || len(made.Secret.Buffer) == 0 {
				t.Fatalf("MakeCredentialCommand returned empty blob %d or secret %d",
					len(made.CredentialBlob.Buffer), len(made.Secret.Buffer))
			}
			if testCase.ekType == TPMAlgRSA && len(made.Secret.Buffer) != 256 {
				t.Fatalf("RSA secret is %d bytes, want 256", len(made.Secret.Buffer))
			}

			certInfo, err := ActivateCredentialCommand(ctx, simulator, simulator.AKHandle(), simulator.EKHandle(), made.CredentialBlob, made.Secret)
			if err != nil {
				t.Fatalf("ActivateCredentialCommand error = %v", err)
			}
			if err := VerifyActivationCertInfo(certInfo, credential, simulator.AKName()); err != nil {
				t.Fatalf("VerifyActivationCertInfo error = %v", err)
			}
			attest, err := ParseTPMSAttest(certInfo.Buffer)
			if err != nil {
				t.Fatalf("ParseTPMSAttest error = %v", err)
			}
			if attest.Type != TPMStAttestCertify || attest.Magic != TPMGeneratedValue {
				t.Fatalf("certInfo attest = %+v", attest)
			}
			if attest.ClockInfo.Safe != 1 || attest.ClockInfo.Clock == 0 {
				t.Fatalf("certInfo clock info = %+v", attest.ClockInfo)
			}
			if !bytes.Equal(attest.ExtraData, credential) {
				t.Fatalf("certInfo extraData = %x, want %x", attest.ExtraData, credential)
			}
			if err := VerifyActivationCertInfo(certInfo, testSoftwareTPMCredential("other"), simulator.AKName()); !errors.Is(err, ErrEKActivation) {
				t.Fatalf("wrong credential verify error = %v, want ErrEKActivation", err)
			}

			second, err := ActivateCredentialCommand(ctx, simulator, simulator.AKHandle(), simulator.EKHandle(), made.CredentialBlob, made.Secret)
			if err != nil {
				t.Fatalf("second ActivateCredentialCommand error = %v", err)
			}
			secondAttest, err := ParseTPMSAttest(second.Buffer)
			if err != nil {
				t.Fatalf("second ParseTPMSAttest error = %v", err)
			}
			if secondAttest.ClockInfo.Clock <= attest.ClockInfo.Clock {
				t.Fatalf("second clock %d is not after %d", secondAttest.ClockInfo.Clock, attest.ClockInfo.Clock)
			}
		})
	}
}

// TestSoftwareTPMCapabilities checks handle and property capability responses. |
// TestSoftwareTPMCapabilities 校验句柄与属性能力响应。
func TestSoftwareTPMCapabilities(t *testing.T) {
	simulator, err := newSoftwareTPM(TPMAlgRSA)
	if err != nil {
		t.Fatalf("newSoftwareTPM error = %v", err)
	}
	defer simulator.Close()
	ctx := t.Context()

	handles, err := GetCapability(ctx, simulator, TPMCapHandles, 0x80000000, 8)
	if err != nil {
		t.Fatalf("GetCapability(handles) error = %v", err)
	}
	if handles.MoreData {
		t.Fatal("handle capability unexpectedly has more data")
	}
	if len(handles.Handles) != 2 || handles.Handles[0] != simulator.AKHandle() || handles.Handles[1] != simulator.EKHandle() {
		t.Fatalf("handles = %x", handles.Handles)
	}
	persistent, err := GetCapability(ctx, simulator, TPMCapHandles, simulator.EKHandle(), 8)
	if err != nil {
		t.Fatalf("GetCapability(persistent) error = %v", err)
	}
	if len(persistent.Handles) != 1 || persistent.Handles[0] != simulator.EKHandle() {
		t.Fatalf("persistent handles = %x", persistent.Handles)
	}
	limited, err := GetCapability(ctx, simulator, TPMCapHandles, 0x80000000, 1)
	if err != nil {
		t.Fatalf("GetCapability(limited) error = %v", err)
	}
	if !limited.MoreData || len(limited.Handles) != 1 {
		t.Fatalf("limited capability = %+v", limited)
	}

	properties, err := GetCapability(ctx, simulator, TPMCapTPMProperties, TPMPropertyManufacturer, 8)
	if err != nil {
		t.Fatalf("GetCapability(properties) error = %v", err)
	}
	if len(properties.Properties) != 2 {
		t.Fatalf("properties = %+v", properties.Properties)
	}
	if properties.Properties[0] != (TPMTaggedProperty{Property: TPMPropertyManufacturer, Value: softwareTPMManufacturer}) {
		t.Fatalf("manufacturer property = %+v", properties.Properties[0])
	}
	if properties.Properties[1] != (TPMTaggedProperty{Property: TPMPropertyFirmwareVersion1, Value: softwareTPMFirmwareVersion}) {
		t.Fatalf("firmware property = %+v", properties.Properties[1])
	}
	empty, err := GetCapability(ctx, simulator, TPMCapTPMProperties, TPMPropertyFirmwareVersion1+1, 8)
	if err != nil {
		t.Fatalf("GetCapability(empty properties) error = %v", err)
	}
	if len(empty.Properties) != 0 || empty.MoreData {
		t.Fatalf("empty properties = %+v", empty)
	}

	var tpmErr *TPMError
	if _, err := GetCapability(ctx, simulator, 0x7, 0, 8); !errors.As(err, &tpmErr) || tpmErr.Code != TPMRCValue {
		t.Fatalf("unknown capability error = %v", err)
	}
}

// TestSoftwareTPMFlushAndClose checks FlushContext and Close semantics. |
// TestSoftwareTPMFlushAndClose 校验证 FlushContext 与 Close 语义。
func TestSoftwareTPMFlushAndClose(t *testing.T) {
	simulator, err := newSoftwareTPM(TPMAlgRSA)
	if err != nil {
		t.Fatalf("newSoftwareTPM error = %v", err)
	}
	ctx := t.Context()

	if err := FlushContext(ctx, simulator, simulator.EKHandle()); err == nil {
		t.Fatal("persistent EK flush was accepted")
	}
	if err := FlushContext(ctx, simulator, simulator.AKHandle()); err != nil {
		t.Fatalf("FlushContext(AK) error = %v", err)
	}
	if _, err := ReadPublic(ctx, simulator, simulator.AKHandle()); !errors.Is(err, ErrTPMCommand) {
		t.Fatalf("ReadPublic(flushed AK) error = %v, want ErrTPMCommand", err)
	}
	if err := FlushContext(ctx, simulator, simulator.AKHandle()); !errors.Is(err, ErrTPMCommand) {
		t.Fatalf("second FlushContext error = %v, want ErrTPMCommand", err)
	}

	credential := testSoftwareTPMCredential("closed")
	made, err := MakeCredentialCommand(ctx, simulator, simulator.EKHandle(), credential, testAKName(t, 21))
	if err != nil {
		t.Fatalf("MakeCredentialCommand error = %v", err)
	}
	if err := simulator.Close(); err != nil {
		t.Fatalf("Close error = %v", err)
	}
	if err := simulator.Close(); err != nil {
		t.Fatalf("second Close error = %v", err)
	}
	if _, err := ActivateCredentialCommand(ctx, simulator, simulator.AKHandle(), simulator.EKHandle(), made.CredentialBlob, made.Secret); !errors.Is(err, ErrTPMTransport) {
		t.Fatalf("Execute after Close error = %v, want ErrTPMTransport", err)
	}
	if _, err := ReadPublic(ctx, simulator, simulator.EKHandle()); !errors.Is(err, ErrTPMTransport) {
		t.Fatalf("ReadPublic after Close error = %v, want ErrTPMTransport", err)
	}
}

// TestSoftwareTPMRejectsInvalidCommands checks framing, authorization and parameter errors. |
// TestSoftwareTPMRejectsInvalidCommands 校验框架、授权与参数错误。
func TestSoftwareTPMRejectsInvalidCommands(t *testing.T) {
	simulator, err := newSoftwareTPM(TPMAlgECC)
	if err != nil {
		t.Fatalf("newSoftwareTPM error = %v", err)
	}
	defer simulator.Close()
	ctx := t.Context()

	if _, err := simulator.Execute(ctx, []byte{0x80, 0x01, 0x00}); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("truncated Execute error = %v, want ErrTPMStructure", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := simulator.Execute(canceled, nil); !errors.Is(err, ErrTPMTransport) {
		t.Fatalf("canceled Execute error = %v, want ErrTPMTransport", err)
	}
	if _, err := GetCapability(ctx, simulator, TPMCapHandles, 0, 0); !errors.Is(err, ErrTPMCommand) {
		t.Fatalf("GetCapability with zero count error = %v, want ErrTPMCommand", err)
	}

	credential := testSoftwareTPMCredential("bad-auth")
	command := &TPM2Command{
		Tag:         TPMSTSessions,
		CommandCode: TPMCCActivateCredential,
		Handles:     []uint32{simulator.AKHandle(), simulator.EKHandle()},
		Auth: []TPMSAuthCommand{
			{SessionHandle: TPMRSPassword, HMAC: []byte{0x01}},
			tpm2PasswordAuth(),
		},
		Parameters: []byte{0x00, 0x00, 0x00, 0x00},
	}
	var tpmErr *TPMError
	if _, err := TPM2Call(ctx, simulator, command); !errors.As(err, &tpmErr) || tpmErr.Code != TPMRCAuthType {
		t.Fatalf("bad session auth error = %v", err)
	}

	if _, err := MakeCredentialCommand(ctx, simulator, simulator.EKHandle(), nil, testAKName(t, 22)); err != nil {
		t.Fatalf("empty credential MakeCredentialCommand error = %v", err)
	}
	if _, err := MakeCredentialCommand(ctx, simulator, simulator.EKHandle(), make([]byte, 65), testAKName(t, 22)); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("oversized credential error = %v, want ErrTPMStructure", err)
	}
	if _, err := MakeCredentialCommand(ctx, simulator, simulator.EKHandle(), credential, TPM2BName{}); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("invalid AK Name error = %v, want ErrTPMStructure", err)
	}
	if _, err := MakeCredentialCommand(ctx, simulator, 0x80000009, credential, testAKName(t, 22)); !errors.Is(err, ErrTPMCommand) {
		t.Fatalf("unknown EK handle error = %v, want ErrTPMCommand", err)
	}
	missing := &TPM2Command{
		Tag:         TPMSTSessions,
		CommandCode: TPMCCActivateCredential,
		Handles:     []uint32{simulator.AKHandle(), simulator.EKHandle()},
		Auth:        []TPMSAuthCommand{tpm2PasswordAuth()},
		Parameters:  []byte{0x00, 0x00, 0x00, 0x00},
	}
	if _, err := TPM2Call(ctx, simulator, missing); !errors.As(err, &tpmErr) || tpmErr.Code != TPMRCAuthMissing {
		t.Fatalf("ActivateCredential with one auth error = %v", err)
	}
	noSessions := &TPM2Command{
		Tag:         TPMSTNoSessions,
		CommandCode: TPMCCActivateCredential,
		Handles:     []uint32{simulator.AKHandle(), simulator.EKHandle()},
		Parameters:  []byte{0x00, 0x00, 0x00, 0x00},
	}
	if _, err := TPM2Call(ctx, simulator, noSessions); !errors.As(err, &tpmErr) || tpmErr.Code != TPMRCAuthMissing {
		t.Fatalf("ActivateCredential without sessions error = %v", err)
	}
}

// TestSoftwareTPMConcurrentActivation checks that concurrent command exchanges are serialized. |
// TestSoftwareTPMConcurrentActivation 校验并发命令交换被串行化。
func TestSoftwareTPMConcurrentActivation(t *testing.T) {
	simulator, err := newSoftwareTPM(TPMAlgRSA)
	if err != nil {
		t.Fatalf("newSoftwareTPM error = %v", err)
	}
	defer simulator.Close()

	const workers = 8
	const rounds = 3
	type concurrentFailure struct {
		worker int
		round  int
		err    error
	}
	var wait sync.WaitGroup
	failures := make(chan concurrentFailure, workers)
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			for round := 0; round < rounds; round++ {
				credential := testSoftwareTPMCredential(string([]byte{byte(worker), byte(round)}))
				made, err := MakeCredentialCommand(context.Background(), simulator, simulator.EKHandle(), credential, simulator.AKName())
				if err != nil {
					failures <- concurrentFailure{worker: worker, round: round, err: err}
					return
				}
				certInfo, err := ActivateCredentialCommand(context.Background(), simulator, simulator.AKHandle(), simulator.EKHandle(), made.CredentialBlob, made.Secret)
				if err != nil {
					failures <- concurrentFailure{worker: worker, round: round, err: err}
					return
				}
				if err := VerifyActivationCertInfo(certInfo, credential, simulator.AKName()); err != nil {
					failures <- concurrentFailure{worker: worker, round: round, err: err}
					return
				}
			}
		}(worker)
	}
	wait.Wait()
	close(failures)
	for failure := range failures {
		t.Errorf("worker %d round %d: %v", failure.worker, failure.round, failure.err)
	}
}

// TestNewSoftwareTPMRejectsUnknownType checks unsupported EK types. | TestNewSoftwareTPMRejectsUnknownType
// 校验不支持的背书密钥类型。
func TestNewSoftwareTPMRejectsUnknownType(t *testing.T) {
	if _, err := newSoftwareTPM(0x1234); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("unknown EK type error = %v, want ErrUnsupportedKey", err)
	}
}
