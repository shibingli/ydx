package kerberos

import (
	"bytes"
	"errors"
	"testing"
)

// TestNegTokenInitRoundTrip verifies NegTokenInit encoding and decoding. |
// TestNegTokenInitRoundTrip 校验 NegTokenInit 编码与解码。
func TestNegTokenInitRoundTrip(t *testing.T) {
	init := negTokenInit{
		mechTypes:   [][]uint32{gssOIDKerberosV5, gssOIDMSLegacyKerberos},
		mechToken:   []byte{0x01, 0x02, 0x03},
		mechListMIC: []byte{0x04, 0x05},
	}
	encoded := appendNegTokenInit(init)
	if len(encoded) == 0 || encoded[0] != 0xA0 {
		t.Fatalf("encoded token starts with %x, want 0xA0", encoded)
	}
	decoded, err := parseNegTokenInit(encoded)
	if err != nil {
		t.Fatalf("parseNegTokenInit: %v", err)
	}
	if len(decoded.mechTypes) != 2 || !equalOID(decoded.mechTypes[0], gssOIDKerberosV5) || !equalOID(decoded.mechTypes[1], gssOIDMSLegacyKerberos) {
		t.Fatalf("mechanisms = %v", decoded.mechTypes)
	}
	if !bytes.Equal(decoded.mechToken, init.mechToken) || !bytes.Equal(decoded.mechListMIC, init.mechListMIC) {
		t.Fatalf("tokens = %x / %x", decoded.mechToken, decoded.mechListMIC)
	}
	wantDER := appendMechTypeList(nil, init.mechTypes)
	if !bytes.Equal(decoded.mechListDER, wantDER) {
		t.Fatalf("mechListDER = %x, want %x", decoded.mechListDER, wantDER)
	}
	if !isSPNEGOToken(encoded) {
		t.Fatal("isSPNEGOToken(encoded) = false")
	}
	if isSPNEGOToken(nil) || isSPNEGOToken([]byte{0x60}) {
		t.Fatal("isSPNEGOToken accepted a non-SPNEGO token")
	}
	// A token without optional fields must decode to empty token fields. |
	// 无可选字段的令牌必须解码为空令牌字段。
	minimal, err := parseNegTokenInit(appendNegTokenInit(negTokenInit{mechTypes: [][]uint32{gssOIDKerberosV5}}))
	if err != nil {
		t.Fatalf("minimal parse: %v", err)
	}
	if len(minimal.mechToken) != 0 || len(minimal.mechListMIC) != 0 {
		t.Fatalf("minimal optional fields = %x / %x", minimal.mechToken, minimal.mechListMIC)
	}
}

// TestNegTokenInitErrors covers malformed NegTokenInit values. | TestNegTokenInitErrors
// 覆盖畸形 NegTokenInit 值。
func TestNegTokenInitErrors(t *testing.T) {
	valid := appendNegTokenInit(negTokenInit{mechTypes: [][]uint32{gssOIDKerberosV5}, mechToken: []byte{1}})
	noMechs := derAppendContext(nil, 0, derAppendSequence(nil))
	emptyMechs := derAppendContext(nil, 0, derAppendSequence(nil, derAppendSequence(nil)))
	duplicate := derAppendContext(nil, 0, derAppendSequence(nil,
		derAppendContext(nil, 0, derAppendSequence(nil, derAppendOID(nil, gssOIDKerberosV5))),
		derAppendContext(nil, 0, derAppendSequence(nil, derAppendOID(nil, gssOIDKerberosV5))),
	))
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"truncated", valid[:len(valid)-2]},
		{"wrong outer tag", append([]byte{0xA1}, valid[1:]...)},
		{"no mechanism list", noMechs},
		{"empty mechanism list", emptyMechs},
		{"duplicate field", duplicate},
		{"unknown field", derAppendContext(nil, 0, derAppendSequence(nil,
			derAppendContext(nil, 0, derAppendSequence(nil, derAppendOID(nil, gssOIDKerberosV5))),
			derAppendContext(nil, 4, derAppendOctetString(nil, []byte{1})),
		))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseNegTokenInit(test.data); !negotiationError(err) {
				t.Fatalf("parseNegTokenInit error = %v, want ErrSPNEGO or ErrASN1", err)
			}
		})
	}
}

// TestNegTokenRespRoundTrip verifies NegTokenResp encoding and decoding. |
// TestNegTokenRespRoundTrip 校验 NegTokenResp 编码与解码。
func TestNegTokenRespRoundTrip(t *testing.T) {
	state := negStateRequestMIC
	resp := negTokenResp{
		state:         &state,
		supportedMech: gssOIDKerberosV5,
		responseToken: []byte{0xAA, 0xBB},
		mechListMIC:   []byte{0xCC},
	}
	encoded := appendNegTokenResp(resp)
	if len(encoded) == 0 || encoded[0] != 0xA1 {
		t.Fatalf("encoded token starts with %x, want 0xA1", encoded)
	}
	decoded, err := parseNegTokenResp(encoded)
	if err != nil {
		t.Fatalf("parseNegTokenResp: %v", err)
	}
	if decoded.state == nil || *decoded.state != negStateRequestMIC {
		t.Fatalf("state = %v", decoded.state)
	}
	if !equalOID(decoded.supportedMech, gssOIDKerberosV5) {
		t.Fatalf("supportedMech = %v", decoded.supportedMech)
	}
	if !bytes.Equal(decoded.responseToken, resp.responseToken) || !bytes.Equal(decoded.mechListMIC, resp.mechListMIC) {
		t.Fatalf("tokens = %x / %x", decoded.responseToken, decoded.mechListMIC)
	}
	empty, err := parseNegTokenResp(appendNegTokenResp(negTokenResp{}))
	if err != nil {
		t.Fatalf("empty parse: %v", err)
	}
	if empty.state != nil || len(empty.supportedMech) != 0 || len(empty.responseToken) != 0 {
		t.Fatalf("empty response = %+v", empty)
	}
}

// TestNegTokenRespErrors covers malformed NegTokenResp values. | TestNegTokenRespErrors
// 覆盖畸形 NegTokenResp 值。
func TestNegTokenRespErrors(t *testing.T) {
	valid := appendNegTokenResp(negTokenResp{responseToken: []byte{1}})
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"truncated", valid[:len(valid)-1]},
		{"wrong outer tag", append([]byte{0xA0}, valid[1:]...)},
		{"invalid state", derAppendContext(nil, 1, derAppendSequence(nil,
			derAppendContext(nil, 0, derAppendEnumerated(nil, 9))))},
		{"duplicate state", derAppendContext(nil, 1, derAppendSequence(nil,
			derAppendContext(nil, 0, derAppendEnumerated(nil, 0)),
			derAppendContext(nil, 0, derAppendEnumerated(nil, 1))))},
		{"unknown field", derAppendContext(nil, 1, derAppendSequence(nil,
			derAppendContext(nil, 5, derAppendOctetString(nil, []byte{1}))))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseNegTokenResp(test.data); !negotiationError(err) {
				t.Fatalf("parseNegTokenResp error = %v, want ErrSPNEGO or ErrASN1", err)
			}
		})
	}
}

// TestMechTypeListRejectsEmpty verifies an empty mechanism list is rejected. |
// TestMechTypeListRejectsEmpty 校验空机制列表会被拒绝。
func TestMechTypeListRejectsEmpty(t *testing.T) {
	if _, err := parseMechTypeList(nil); !errors.Is(err, ErrSPNEGO) {
		t.Fatalf("parseMechTypeList(nil) error = %v, want ErrSPNEGO", err)
	}
	if _, err := parseMechTypeList([]byte{0x06, 0x00}); !negotiationError(err) {
		t.Fatalf("parseMechTypeList(invalid OID) error = %v, want ErrSPNEGO or ErrASN1", err)
	}
}

// negotiationError reports whether err is an SPNEGO or DER decoding failure. |
// negotiationError 报告 err 是否为 SPNEGO 或 DER 解码失败。
func negotiationError(err error) bool {
	return errors.Is(err, ErrSPNEGO) || errors.Is(err, ErrASN1)
}
