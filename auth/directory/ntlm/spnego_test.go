package ntlm

import (
	"bytes"
	"errors"
	"testing"
)

// testTLV builds one DER value for fixtures and fails the test on error. |
// testTLV 为夹具构建一个 DER 值，出错时使测试失败。
func testTLV(t *testing.T, tag byte, value []byte) []byte {
	t.Helper()
	encoded, err := derTLV(tag, value)
	if err != nil {
		t.Fatalf("derTLV(0x%02x): %v", tag, err)
	}
	return encoded
}

// testSeq builds a DER constructed value from children. | testSeq 从子值构建 DER
// 构造值。
func testSeq(t *testing.T, tag byte, children ...[]byte) []byte {
	t.Helper()
	var content []byte
	for _, child := range children {
		content = append(content, child...)
	}
	return testTLV(t, tag, content)
}

func TestSPNEGONegotiateInitRoundTrip(t *testing.T) {
	mechanisms := []struct {
		name  string
		token []byte
	}{
		{name: "short", token: []byte("NTLMSSP-Type1")},
		{name: "long", token: bytes.Repeat([]byte{0x5a}, 300)},
		{name: "empty", token: nil},
	}
	for _, test := range mechanisms {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := EncodeSPNEGONegotiateInit(test.token)
			if err != nil {
				t.Fatalf("EncodeSPNEGONegotiateInit: %v", err)
			}
			parsed, err := ParseSPNEGOToken(encoded)
			if err != nil {
				t.Fatalf("ParseSPNEGOToken: %v", err)
			}
			if parsed.HasNegState {
				t.Fatalf("unexpected negState")
			}
			if !parsed.SupportsNTLM() {
				t.Fatalf("token does not advertise NTLM")
			}
			if len(parsed.MechTypes) != 1 || !bytes.Equal(parsed.MechTypes[0], ntlmMechOID) {
				t.Fatalf("mechTypes = %x", parsed.MechTypes)
			}
			if !bytes.Equal(parsed.MechToken, test.token) {
				t.Fatalf("mechToken = %x, want %x", parsed.MechToken, test.token)
			}
			if parsed.ResponseToken != nil {
				t.Fatalf("unexpected responseToken")
			}
			if !bytes.Equal(parsed.Token(), test.token) {
				t.Fatalf("Token = %x", parsed.Token())
			}
			if len(parsed.MechListMIC) != 0 {
				t.Fatalf("unexpected mechListMIC")
			}
		})
	}
}

func TestSPNEGOResponseRoundTrip(t *testing.T) {
	token := []byte("NTLMSSP-Type3")
	encoded, err := EncodeSPNEGOResponse(token)
	if err != nil {
		t.Fatalf("EncodeSPNEGOResponse: %v", err)
	}
	parsed, err := ParseSPNEGOToken(encoded)
	if err != nil {
		t.Fatalf("ParseSPNEGOToken: %v", err)
	}
	if !bytes.Equal(parsed.ResponseToken, token) {
		t.Fatalf("responseToken = %x", parsed.ResponseToken)
	}
	if !bytes.Equal(parsed.Token(), token) {
		t.Fatalf("Token = %x", parsed.Token())
	}
	if !parsed.SupportsNTLM() {
		t.Fatalf("token without mech list should be permissive")
	}
	if parsed.HasNegState {
		t.Fatalf("unexpected negState")
	}
}

func TestSPNEGOWrappedResponse(t *testing.T) {
	response, err := EncodeSPNEGOResponse([]byte("Type2"))
	if err != nil {
		t.Fatalf("EncodeSPNEGOResponse: %v", err)
	}
	wrapped := testSeq(t, 0x60, testTLV(t, 0x06, spnegoMechOID), response)
	parsed, err := ParseSPNEGOToken(wrapped)
	if err != nil {
		t.Fatalf("ParseSPNEGOToken: %v", err)
	}
	if !bytes.Equal(parsed.ResponseToken, []byte("Type2")) {
		t.Fatalf("responseToken = %x", parsed.ResponseToken)
	}
}

func TestSPNEGOServerNegTokenInit(t *testing.T) {
	mechTypes := testSeq(t, 0x30, testTLV(t, 0x06, ntlmMechOID))
	init := testSeq(t, 0x30,
		testSeq(t, 0xA0, mechTypes),
		testSeq(t, 0xA1, testTLV(t, 0x03, []byte{0})),
		testSeq(t, 0xA2, testTLV(t, 0x04, []byte("Type2"))),
		testSeq(t, 0xA3, testTLV(t, 0x04, []byte("mic"))),
	)
	tests := []struct {
		name string
		data []byte
	}{
		{name: "wrapped choice", data: testSeq(t, 0x60, testTLV(t, 0x06, spnegoMechOID), testSeq(t, 0xA0, init))},
		{name: "bare choice", data: testSeq(t, 0xA0, init)},
		{name: "bare sequence", data: init},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := ParseSPNEGOToken(test.data)
			if err != nil {
				t.Fatalf("ParseSPNEGOToken: %v", err)
			}
			if !bytes.Equal(parsed.MechToken, []byte("Type2")) {
				t.Fatalf("mechToken = %x", parsed.MechToken)
			}
			if !bytes.Equal(parsed.Token(), []byte("Type2")) {
				t.Fatalf("Token = %x", parsed.Token())
			}
			if len(parsed.MechTypes) != 1 || !parsed.SupportsNTLM() {
				t.Fatalf("mechTypes = %x", parsed.MechTypes)
			}
			if !bytes.Equal(parsed.MechListMIC, []byte("mic")) {
				t.Fatalf("mechListMIC = %x", parsed.MechListMIC)
			}
		})
	}
}

func TestSPNEGONegState(t *testing.T) {
	states := []struct {
		value NegState
		name  string
	}{
		{NegStateAcceptCompleted, "accept-completed"},
		{NegStateAcceptIncomplete, "accept-incomplete"},
		{NegStateReject, "reject"},
		{NegStateRequestMIC, "request-mic"},
	}
	for _, state := range states {
		t.Run(state.name, func(t *testing.T) {
			response := testSeq(t, 0xA1, testSeq(t, 0x30,
				testSeq(t, 0xA0, testTLV(t, 0x0A, []byte{byte(state.value)})),
				testSeq(t, 0xA1, testTLV(t, 0x06, ntlmMechOID)),
				testSeq(t, 0xA2, testTLV(t, 0x04, []byte("token"))),
			))
			parsed, err := ParseSPNEGOToken(response)
			if err != nil {
				t.Fatalf("ParseSPNEGOToken: %v", err)
			}
			if !parsed.HasNegState || parsed.NegState != state.value {
				t.Fatalf("negState = %v, %v", parsed.NegState, parsed.HasNegState)
			}
			if parsed.NegState.String() != state.name {
				t.Fatalf("String = %q, want %q", parsed.NegState.String(), state.name)
			}
			if !bytes.Equal(parsed.SupportedMech, ntlmMechOID) {
				t.Fatalf("supportedMech = %x", parsed.SupportedMech)
			}
			if !bytes.Equal(parsed.ResponseToken, []byte("token")) {
				t.Fatalf("responseToken = %x", parsed.ResponseToken)
			}
		})
	}
	raw := testSeq(t, 0x30,
		testSeq(t, 0xA0, testTLV(t, 0x0A, []byte{byte(NegStateAcceptIncomplete)})),
		testSeq(t, 0xA2, testTLV(t, 0x04, []byte("token"))),
	)
	parsed, err := ParseSPNEGOToken(raw)
	if err != nil {
		t.Fatalf("ParseSPNEGOToken raw: %v", err)
	}
	if !parsed.HasNegState || parsed.NegState != NegStateAcceptIncomplete {
		t.Fatalf("raw negState = %v, %v", parsed.NegState, parsed.HasNegState)
	}
	if !bytes.Equal(parsed.ResponseToken, []byte("token")) {
		t.Fatalf("raw responseToken = %x", parsed.ResponseToken)
	}
}

func TestNegStateStringUnknown(t *testing.T) {
	if got := NegState(9).String(); got != "unknown" {
		t.Fatalf("String = %q", got)
	}
}

func TestSupportsNTLM(t *testing.T) {
	kerberos := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}
	if (&SPNEGOToken{SupportedMech: kerberos}).SupportsNTLM() {
		t.Fatalf("Kerberos supportedMech accepted")
	}
	if (&SPNEGOToken{MechTypes: [][]byte{kerberos}}).SupportsNTLM() {
		t.Fatalf("Kerberos mechTypes accepted")
	}
	if !(&SPNEGOToken{}).SupportsNTLM() {
		t.Fatalf("empty token should be permissive")
	}
	if !(&SPNEGOToken{MechTypes: [][]byte{kerberos, ntlmMechOID}}).SupportsNTLM() {
		t.Fatalf("NTLM among mechTypes rejected")
	}
}

func TestParseSPNEGOMalformed(t *testing.T) {
	validMechTypes := testSeq(t, 0xA0, testSeq(t, 0x30, testTLV(t, 0x06, ntlmMechOID)))
	validInit := testSeq(t, 0xA0, testSeq(t, 0x30, validMechTypes, testSeq(t, 0xA2, testTLV(t, 0x04, []byte("t")))))
	tests := []struct {
		name string
		data []byte
	}{
		{name: "empty", data: nil},
		{name: "one byte", data: []byte{0x30}},
		{name: "trailing after initial", data: append(append([]byte(nil), validInit...), 0x00)},
		{name: "unexpected outer tag", data: testTLV(t, 0x61, nil)},
		{name: "initial without OID tag", data: testSeq(t, 0x60, testTLV(t, 0x04, []byte{1}))},
		{name: "wrong SPNEGO OID", data: testSeq(t, 0x60, testTLV(t, 0x06, []byte{0x2a, 0x03}))},
		{name: "initial without inner token", data: testSeq(t, 0x60, testTLV(t, 0x06, spnegoMechOID))},
		{name: "initial inner unexpected", data: testSeq(t, 0x60, testTLV(t, 0x06, spnegoMechOID), testTLV(t, 0x04, []byte{1}))},
		{name: "initial inner trailing", data: testSeq(t, 0x60, testTLV(t, 0x06, spnegoMechOID), validInit, testTLV(t, 0x00, nil))},
		{name: "indefinite length", data: []byte{0x30, 0x80}},
		{name: "high tag", data: []byte{0x1f, 0x00}},
		{name: "nonminimal short length", data: []byte{0x30, 0x81, 0x05, 1, 2, 3, 4, 5}},
		{name: "leading zero length", data: []byte{0x30, 0x82, 0x00, 0x80}},
		{name: "long length count", data: []byte{0x30, 0x85, 0, 0, 0, 0, 1}},
		{name: "truncated long length", data: []byte{0x30, 0x82, 0x01}},
		{name: "length exceeds input", data: []byte{0x30, 0x05, 1, 2}},
		{name: "wrapper not sequence", data: testSeq(t, 0xA1, testTLV(t, 0x04, []byte{1}))},
		{name: "wrapper trailing", data: testSeq(t, 0xA1, testSeq(t, 0x30), testTLV(t, 0x04, nil))},
		{name: "duplicate token field", data: testSeq(t, 0xA1, testSeq(t, 0x30,
			testSeq(t, 0xA2, testTLV(t, 0x04, []byte{1})),
			testSeq(t, 0xA2, testTLV(t, 0x04, []byte{2})),
		))},
		{name: "mechTypes not sequence", data: testSeq(t, 0xA0, testSeq(t, 0x30, testSeq(t, 0xA0, testTLV(t, 0x04, []byte{1}))))},
		{name: "mechTypes empty", data: testSeq(t, 0xA0, testSeq(t, 0x30, testSeq(t, 0xA0, testSeq(t, 0x30))))},
		{name: "mechTypes entry not OID", data: testSeq(t, 0xA0, testSeq(t, 0x30, testSeq(t, 0xA0, testSeq(t, 0x30, testSeq(t, 0x30)))))},
		{name: "NegTokenInit missing mechTypes", data: testSeq(t, 0xA0, testSeq(t, 0x30))},
		{name: "reqFlags not bit string", data: testSeq(t, 0xA0, testSeq(t, 0x30,
			validMechTypes,
			testSeq(t, 0xA1, testTLV(t, 0x04, []byte{1})),
		))},
		{name: "supportedMech not OID", data: testSeq(t, 0xA1, testSeq(t, 0x30, testSeq(t, 0xA1, testTLV(t, 0x04, []byte{1}))))},
		{name: "supportedMech empty", data: testSeq(t, 0xA1, testSeq(t, 0x30, testSeq(t, 0xA1, testTLV(t, 0x06, nil))))},
		{name: "negState not enumerated", data: testSeq(t, 0xA1, testSeq(t, 0x30, testSeq(t, 0xA0, testTLV(t, 0x04, []byte{0}))))},
		{name: "negState invalid", data: testSeq(t, 0xA1, testSeq(t, 0x30, testSeq(t, 0xA0, testTLV(t, 0x0A, []byte{4}))))},
		{name: "negState length", data: testSeq(t, 0xA1, testSeq(t, 0x30, testSeq(t, 0xA0, testTLV(t, 0x0A, []byte{0, 1}))))},
		{name: "token not octet string", data: testSeq(t, 0xA1, testSeq(t, 0x30, testSeq(t, 0xA2, testTLV(t, 0x06, []byte{1}))))},
		{name: "mechListMIC not octet string", data: testSeq(t, 0xA1, testSeq(t, 0x30, testSeq(t, 0xA3, testTLV(t, 0x06, []byte{1}))))},
		{name: "unknown field", data: testSeq(t, 0x30, testTLV(t, 0xA4, nil))},
		{name: "context field holds two values", data: testSeq(t, 0x30, testSeq(t, 0xA2, testTLV(t, 0x04, []byte{1}), testTLV(t, 0x04, []byte{2})))},
		{name: "raw A0 unexpected", data: testSeq(t, 0x30, testSeq(t, 0xA0, testTLV(t, 0x04, []byte{1})))},
		{name: "raw A1 unexpected", data: testSeq(t, 0x30, testSeq(t, 0xA1, testTLV(t, 0x04, []byte{1})))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseSPNEGOToken(test.data); !errors.Is(err, ErrSPNEGO) {
				t.Fatalf("error = %v, want ErrSPNEGO", err)
			}
		})
	}
}

func TestDERLength(t *testing.T) {
	cases := []struct {
		length int
		want   []byte
	}{
		{0, []byte{0x00}},
		{127, []byte{0x7f}},
		{128, []byte{0x81, 0x80}},
		{300, []byte{0x82, 0x01, 0x2c}},
	}
	for _, test := range cases {
		got, err := derLength(test.length)
		if err != nil {
			t.Fatalf("derLength(%d): %v", test.length, err)
		}
		if !bytes.Equal(got, test.want) {
			t.Fatalf("derLength(%d) = %x, want %x", test.length, got, test.want)
		}
	}
	if _, err := derLength(-1); !errors.Is(err, ErrSPNEGO) {
		t.Fatalf("negative length error = %v", err)
	}
}

func TestDERBuilderErrorPropagation(t *testing.T) {
	builder := &derBuilder{err: ErrSPNEGO}
	if builder.tlv(0x04, nil) != nil {
		t.Fatalf("tlv returned data after error")
	}
	if builder.seq(0x30, []byte{1}) != nil {
		t.Fatalf("seq returned data after error")
	}
	built := (&derBuilder{}).seq(0x30, []byte{1, 2})
	if !bytes.Equal(built, []byte{0x30, 0x02, 1, 2}) {
		t.Fatalf("seq = %x", built)
	}
}
