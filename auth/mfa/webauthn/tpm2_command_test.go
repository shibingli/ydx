package webauthn

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// testTPMResponseBytes builds a response image for codec tests. | testTPMResponseBytes 为编解码测试构建
// 响应镜像。
func testTPMResponseBytes(tag uint16, code uint32, parameters []byte, authCount int) []byte {
	if code != TPMRCSuccess {
		out := tpm2AppendU16(nil, TPMSTNoSessions)
		out = tpm2AppendU32(out, 10)
		return tpm2AppendU32(out, code)
	}
	if tag == TPMSTNoSessions {
		out := tpm2AppendU16(nil, tag)
		out = tpm2AppendU32(out, uint32(10+len(parameters)))
		out = tpm2AppendU32(out, code)
		return append(out, parameters...)
	}
	authSize := authCount * 5
	out := tpm2AppendU16(nil, tag)
	out = tpm2AppendU32(out, uint32(10+4+len(parameters)+authSize))
	out = tpm2AppendU32(out, code)
	out = tpm2AppendU32(out, uint32(len(parameters)))
	out = append(out, parameters...)
	for index := 0; index < authCount; index++ {
		out = tpm2AppendU16(out, 0)
		out = append(out, 0)
		out = tpm2AppendU16(out, 0)
	}
	return out
}

// TestTPM2CommandRoundTrip checks NO_SESSIONS and SESSIONS command encoding. |
// TestTPM2CommandRoundTrip 校验 NO_SESSIONS 与 SESSIONS 命令编码。
func TestTPM2CommandRoundTrip(t *testing.T) {
	read := &TPM2Command{
		Tag:         TPMSTNoSessions,
		CommandCode: TPMCCReadPublic,
		Handles:     []uint32{softwareTPMPersistentEK},
	}
	encoded, err := read.Marshal()
	if err != nil {
		t.Fatalf("ReadPublic Marshal error = %v", err)
	}
	if len(encoded) != 14 || encoded[0] != 0x80 || encoded[1] != 0x01 {
		t.Fatalf("ReadPublic encoding = %x", encoded)
	}
	parsed, err := ParseTPM2Command(encoded)
	if err != nil {
		t.Fatalf("ParseTPM2Command error = %v", err)
	}
	if parsed.Tag != read.Tag || parsed.CommandCode != read.CommandCode || len(parsed.Handles) != 1 ||
		parsed.Handles[0] != read.Handles[0] || len(parsed.Auth) != 0 || len(parsed.Parameters) != 0 {
		t.Fatalf("parsed command = %+v", parsed)
	}

	activate := &TPM2Command{
		Tag:         TPMSTSessions,
		CommandCode: TPMCCActivateCredential,
		Handles:     []uint32{softwareTPMTransientAK, softwareTPMPersistentEK},
		Auth:        []TPMSAuthCommand{tpm2PasswordAuth(), tpm2PasswordAuth()},
		Parameters:  []byte{0x00, 0x01, 0xAA},
	}
	encoded, err = activate.Marshal()
	if err != nil {
		t.Fatalf("ActivateCredential Marshal error = %v", err)
	}
	parsed, err = ParseTPM2Command(encoded)
	if err != nil {
		t.Fatalf("ParseTPM2Command error = %v", err)
	}
	if len(parsed.Handles) != 2 || parsed.Handles[0] != softwareTPMTransientAK || parsed.Handles[1] != softwareTPMPersistentEK {
		t.Fatalf("parsed handles = %x", parsed.Handles)
	}
	if len(parsed.Auth) != 2 || parsed.Auth[0].SessionHandle != TPMRSPassword || parsed.Auth[1].SessionHandle != TPMRSPassword {
		t.Fatalf("parsed auth = %+v", parsed.Auth)
	}
	if !bytes.Equal(parsed.Parameters, activate.Parameters) {
		t.Fatalf("parsed parameters = %x, want %x", parsed.Parameters, activate.Parameters)
	}
}

// TestTPM2CommandRejectsInvalidInput checks structural command validation. |
// TestTPM2CommandRejectsInvalidInput 校验命令结构校验。
func TestTPM2CommandRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name    string
		command TPM2Command
		want    error
	}{
		{name: "unknown code", command: TPM2Command{Tag: TPMSTNoSessions, CommandCode: 0x9999}, want: ErrNotSupported},
		{name: "wrong handles", command: TPM2Command{Tag: TPMSTNoSessions, CommandCode: TPMCCReadPublic}, want: ErrTPMStructure},
		{name: "auth without sessions", command: TPM2Command{
			Tag: TPMSTNoSessions, CommandCode: TPMCCReadPublic, Handles: []uint32{1},
			Auth: []TPMSAuthCommand{tpm2PasswordAuth()},
		}, want: ErrTPMStructure},
		{name: "sessions without auth", command: TPM2Command{
			Tag: TPMSTSessions, CommandCode: TPMCCReadPublic, Handles: []uint32{1},
		}, want: ErrTPMStructure},
		{name: "bad tag", command: TPM2Command{Tag: 0x8003, CommandCode: TPMCCReadPublic, Handles: []uint32{1}}, want: ErrTPMStructure},
	}
	for _, testCase := range cases {
		if _, err := testCase.command.Marshal(); !errors.Is(err, testCase.want) {
			t.Fatalf("%s Marshal error = %v, want %v", testCase.name, err, testCase.want)
		}
	}
	if _, err := ParseTPM2Command([]byte{0x80, 0x01, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x01, 0x73, 0x00, 0x00, 0x00, 0x01}); err != nil {
		t.Fatalf("minimal ReadPublic parse error = %v", err)
	}
	badSize := []byte{0x80, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x01, 0x73, 0x00, 0x00, 0x00, 0x01}
	if _, err := ParseTPM2Command(badSize); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("bad declared size error = %v, want ErrTPMStructure", err)
	}
}

// TestTPM2ResponseParse checks success, session and error responses. | TestTPM2ResponseParse 校验成功、
// 会话与错误响应。
func TestTPM2ResponseParse(t *testing.T) {
	parameters := []byte{0x00, 0x01, 0x02}
	response, err := ParseTPM2Response(testTPMResponseBytes(TPMSTNoSessions, TPMRCSuccess, parameters, 0))
	if err != nil {
		t.Fatalf("NO_SESSIONS parse error = %v", err)
	}
	if !bytes.Equal(response.Parameters, parameters) || len(response.Auth) != 0 {
		t.Fatalf("parsed response = %+v", response)
	}

	response, err = ParseTPM2Response(testTPMResponseBytes(TPMSTSessions, TPMRCSuccess, parameters, 2))
	if err != nil {
		t.Fatalf("SESSIONS parse error = %v", err)
	}
	if !bytes.Equal(response.Parameters, parameters) || len(response.Auth) != 2 {
		t.Fatalf("parsed session response = %+v", response)
	}

	response, err = ParseTPM2Response(testTPMResponseBytes(TPMSTNoSessions, TPMRCSize, nil, 0))
	if err != nil {
		t.Fatalf("error response parse error = %v", err)
	}
	if response.ResponseCode != TPMRCSize {
		t.Fatalf("error response code = %#x", response.ResponseCode)
	}
	if _, err := ParseTPM2Response(testTPMResponseBytes(TPMSTNoSessions, TPMRCSize, nil, 0)[:10]); err != nil {
		t.Fatalf("exact error response parse error = %v", err)
	}
	if _, err := ParseTPM2Response([]byte{0x80, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00}); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("short response error = %v, want ErrTPMStructure", err)
	}
}

// TestTPMResponseCodeNames checks format-zero, format-one and warning code classification. |
// TestTPMResponseCodeNames 校验格式零、格式一与警告码分类。
func TestTPMResponseCodeNames(t *testing.T) {
	if got := TPMResponseCodeName(TPMRCSuccess); got != "TPM_RC_SUCCESS" {
		t.Fatalf("success name = %q", got)
	}
	if got := TPMResponseCodeName(TPMRCValue | 0x40 | 0x100); got != "TPM_RC_VALUE" {
		t.Fatalf("format-one name = %q", got)
	}
	if got := TPMResponseCodeName(0x901); got != "TPM_RC_CONTEXT_GAP" {
		t.Fatalf("warning name = %q", got)
	}
	if got := TPMResponseCodeName(0xDEADBEEF); got != "TPM_RC_UNKNOWN_0xDEADBEEF" {
		t.Fatalf("unknown name = %q", got)
	}
	err := &TPMError{Code: TPMRCBadAuth}
	if !errors.Is(err, ErrTPMCommand) {
		t.Fatal("TPMError does not unwrap to ErrTPMCommand")
	}
	if err.Error() == "" {
		t.Fatal("TPMError message is empty")
	}
}

// TestTPM2CallErrors checks nil devices, error responses and malformed replies. |
// TestTPM2CallErrors 校验空设备、错误响应与非法回复。
func TestTPM2CallErrors(t *testing.T) {
	if _, err := TPM2Call(t.Context(), nil, &TPM2Command{}); !errors.Is(err, ErrTPMUnavailable) {
		t.Fatalf("nil device error = %v, want ErrTPMUnavailable", err)
	}
	device := &testTPMDevice{response: testTPMResponseBytes(TPMSTNoSessions, TPMRCBadAuth, nil, 0)}
	response, err := TPM2Call(t.Context(), device, &TPM2Command{
		Tag: TPMSTNoSessions, CommandCode: TPMCCReadPublic, Handles: []uint32{1},
	})
	var tpmErr *TPMError
	if !errors.As(err, &tpmErr) || !errors.Is(err, ErrTPMCommand) {
		t.Fatalf("TPM2Call error = %v, want *TPMError", err)
	}
	if tpmErr.Code != TPMRCBadAuth || response == nil {
		t.Fatalf("TPM2Call returned code %#x response %+v", tpmErr.Code, response)
	}
	device = &testTPMDevice{response: []byte{1, 2, 3}}
	if _, err := TPM2Call(t.Context(), device, &TPM2Command{
		Tag: TPMSTNoSessions, CommandCode: TPMCCReadPublic, Handles: []uint32{1},
	}); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("malformed response error = %v, want ErrTPMStructure", err)
	}
}

// testTPMDevice returns a fixed response. | testTPMDevice 返回固定响应。
type testTPMDevice struct {
	response []byte
}

// Execute implements TPM. | Execute 实现 TPM。
func (d *testTPMDevice) Execute(context.Context, []byte) ([]byte, error) {
	return d.response, nil
}

// Close implements TPM. | Close 实现 TPM。
func (d *testTPMDevice) Close() error { return nil }
