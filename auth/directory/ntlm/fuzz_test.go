package ntlm

import (
	"testing"
	"time"
)

// FuzzDecodeNegotiate ensures arbitrary input cannot panic the Type 1 parser. |
// FuzzDecodeNegotiate 确保任意输入都不会使 Type 1 解析器 panic。
func FuzzDecodeNegotiate(f *testing.F) {
	seed := &NegotiateMessage{
		Flags:       baseClientFlags | FlagExtendedSessionSecurity,
		Domain:      "Domain",
		Workstation: "WORKSTATION",
	}
	encoded, err := seed.Encode()
	if err != nil {
		f.Fatalf("NegotiateMessage.Encode: %v", err)
	}
	f.Add(encoded)
	f.Add([]byte(Signature))
	f.Add([]byte(nil))
	f.Fuzz(func(t *testing.T, data []byte) {
		message, err := DecodeNegotiate(data)
		if err == nil && message == nil {
			t.Fatalf("nil message without error")
		}
	})
}

// FuzzDecodeChallenge ensures arbitrary input cannot panic the Type 2 parser. |
// FuzzDecodeChallenge 确保任意输入都不会使 Type 2 解析器 panic。
func FuzzDecodeChallenge(f *testing.F) {
	seed := &ChallengeMessage{
		Flags:           clientServerFlags(),
		ServerChallenge: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		TargetName:      "Domain",
		TargetInfo: TargetInfo{
			{Type: AVNbDomainName, Value: encodeString("Domain", true)},
			{Type: AVTimestamp, Value: make([]byte, 8)},
		},
	}
	encoded, err := seed.Encode()
	if err != nil {
		f.Fatalf("ChallengeMessage.Encode: %v", err)
	}
	f.Add(encoded)
	f.Add([]byte(Signature))
	f.Add([]byte(nil))
	f.Fuzz(func(t *testing.T, data []byte) {
		message, err := DecodeChallenge(data)
		if err == nil && message == nil {
			t.Fatalf("nil message without error")
		}
	})
}

// FuzzDecodeAuthenticate ensures arbitrary input cannot panic the Type 3
// parser. | FuzzDecodeAuthenticate 确保任意输入都不会使 Type 3 解析器 panic。
func FuzzDecodeAuthenticate(f *testing.F) {
	seed := &AuthenticateMessage{
		LMResponse:  []byte{1, 2, 3},
		NTResponse:  []byte{4, 5, 6, 7},
		Domain:      "Domain",
		Username:    "User",
		Workstation: "WORKSTATION",
		SessionKey:  []byte{8, 9},
		Flags:       baseClientFlags,
		Version:     &Version{Major: 10, Revision: 0x0f},
		MIC:         make([]byte, micSize),
	}
	encoded, err := seed.Encode()
	if err != nil {
		f.Fatalf("AuthenticateMessage.Encode: %v", err)
	}
	f.Add(encoded)
	f.Add([]byte(Signature))
	f.Add([]byte(nil))
	f.Fuzz(func(t *testing.T, data []byte) {
		message, err := DecodeAuthenticate(data)
		if err == nil && message == nil {
			t.Fatalf("nil message without error")
		}
	})
}

// FuzzParseTargetInfo ensures arbitrary input cannot panic the AV pair parser. |
// FuzzParseTargetInfo 确保任意输入都不会使 AV 对解析器 panic。
func FuzzParseTargetInfo(f *testing.F) {
	seed := TargetInfo{
		{Type: AVNbDomainName, Value: encodeString("Domain", true)},
		{Type: AVFlags, Value: make([]byte, 4)},
	}
	encoded, err := seed.Encode()
	if err != nil {
		f.Fatalf("TargetInfo.Encode: %v", err)
	}
	f.Add(encoded)
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte(nil))
	f.Fuzz(func(t *testing.T, data []byte) {
		info, err := ParseTargetInfo(data)
		if err == nil && info == nil {
			t.Fatalf("nil target info without error")
		}
	})
}

// FuzzParseSPNEGOToken ensures arbitrary input cannot panic the SPNEGO parser. |
// FuzzParseSPNEGOToken 确保任意输入都不会使 SPNEGO 解析器 panic。
func FuzzParseSPNEGOToken(f *testing.F) {
	initial, err := EncodeSPNEGONegotiateInit([]byte("NTLMSSP-Type1"))
	if err != nil {
		f.Fatalf("EncodeSPNEGONegotiateInit: %v", err)
	}
	response, err := EncodeSPNEGOResponse([]byte("NTLMSSP-Type3"))
	if err != nil {
		f.Fatalf("EncodeSPNEGOResponse: %v", err)
	}
	f.Add(initial)
	f.Add(response)
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte(nil))
	f.Fuzz(func(t *testing.T, data []byte) {
		token, err := ParseSPNEGOToken(data)
		if err == nil && token == nil {
			t.Fatalf("nil token without error")
		}
	})
}

// FuzzSplitUsername ensures arbitrary login forms cannot panic normalization. |
// FuzzSplitUsername 确保任意登录形式都不会使规范化 panic。
func FuzzSplitUsername(f *testing.F) {
	f.Add(`DOMAIN\user`, "Domain")
	f.Add("user@example.com", "")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, login, domain string) {
		userDomain, userName, err := SplitUsername(login, domain)
		if err != nil {
			return
		}
		if userName == "" {
			t.Fatalf("empty user name without error")
		}
		_ = userDomain
	})
}

// FuzzComputeNTLMv2Response ensures arbitrary lengths cannot panic response
// computation. | FuzzComputeNTLMv2Response 确保任意长度都不会使响应计算 panic。
func FuzzComputeNTLMv2Response(f *testing.F) {
	f.Add(NTLMv2Hash("Password", "User", "Domain"), []byte("01234567"), []byte("abcdefgh"), []byte{0, 0, 0, 0})
	f.Add([]byte(nil), []byte(nil), []byte(nil), []byte(nil))
	f.Fuzz(func(t *testing.T, key, serverChallenge, clientChallenge, targetInfo []byte) {
		response, err := ComputeNTLMv2Response(key, serverChallenge, clientChallenge, time.Unix(1, 2).UTC(), targetInfo)
		if err == nil && response == nil {
			t.Fatalf("nil response without error")
		}
	})
}
