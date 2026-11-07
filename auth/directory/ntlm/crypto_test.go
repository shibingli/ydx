package ntlm

import (
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

// mustHex decodes a hexadecimal test vector. | mustHex 解码十六进制测试向量。
func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", value, err)
	}
	return decoded
}

func TestNTLMv2HashVectors(t *testing.T) {
	tests := []struct {
		name     string
		password string
		username string
		domain   string
		want     string
	}{
		{name: "official", password: "Password", username: "User", domain: "Domain", want: "0c868a403bfd7a93a3001ef22ef02e3f"},
		{name: "empty password", password: "", username: "User", domain: "Domain", want: "7b88e8919e1e3aea963ac347f278b1c9"},
		{name: "upn", password: "Password", username: "user@example.com", domain: "", want: "d4c2989383688978f4f28caba3de66ed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := NTLMv2Hash(test.password, test.username, test.domain)
			if hex.EncodeToString(got) != test.want {
				t.Fatalf("NTLMv2Hash = %x, want %s", got, test.want)
			}
		})
	}
}

func TestComputeNTLMv2OfficialVector(t *testing.T) {
	responseKey := NTLMv2Hash("Password", "User", "Domain")
	serverChallenge := mustHex(t, "0123456789abcdef")
	clientChallenge := mustHex(t, "aaaaaaaaaaaaaaaa")
	targetInfo := mustHex(t, "02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000")
	timestamp := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	response, err := ComputeNTLMv2Response(responseKey, serverChallenge, clientChallenge, timestamp, targetInfo)
	if err != nil {
		t.Fatalf("ComputeNTLMv2Response: %v", err)
	}
	if got := hex.EncodeToString(response.NTProofStr); got != "68cd0ab851e51c96aabc927bebef6a1c" {
		t.Fatalf("NTProofStr = %s", got)
	}
	wantNT := "68cd0ab851e51c96aabc927bebef6a1c" +
		"01010000000000000000000000000000" +
		"aaaaaaaaaaaaaaaa" +
		"00000000" +
		"02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000" +
		"00000000"
	if got := hex.EncodeToString(response.NTResponse); got != wantNT {
		t.Fatalf("NTResponse = %s, want %s", got, wantNT)
	}
	if got := hex.EncodeToString(response.LMv2Response); got != "86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa" {
		t.Fatalf("LMv2Response = %s", got)
	}
	if got := hex.EncodeToString(response.SessionBaseKey); got != "8de40ccadbc14a82f15cb0ad0de95ca3" {
		t.Fatalf("SessionBaseKey = %s", got)
	}
}

func TestComputeNTLMv2ResponseValidation(t *testing.T) {
	key := NTLMv2Hash("Password", "User", "Domain")
	challenge := mustHex(t, "0123456789abcdef")
	clientChallenge := mustHex(t, "aaaaaaaaaaaaaaaa")
	tests := []struct {
		name            string
		responseKey     []byte
		serverChallenge []byte
		clientChal      []byte
		targetInfo      []byte
		want            error
	}{
		{name: "short key", responseKey: key[:15], serverChallenge: challenge, clientChal: clientChallenge, want: ErrCredentials},
		{name: "long key", responseKey: append(append([]byte(nil), key...), 0), serverChallenge: challenge, clientChal: clientChallenge, want: ErrCredentials},
		{name: "short server challenge", responseKey: key, serverChallenge: challenge[:7], clientChal: clientChallenge, want: ErrChallenge},
		{name: "long server challenge", responseKey: key, serverChallenge: append(append([]byte(nil), challenge...), 0), clientChal: clientChallenge, want: ErrChallenge},
		{name: "short client challenge", responseKey: key, serverChallenge: challenge, clientChal: clientChallenge[:7], want: ErrCredentials},
		{name: "long client challenge", responseKey: key, serverChallenge: challenge, clientChal: append(append([]byte(nil), clientChallenge...), 0), want: ErrCredentials},
		{name: "oversized target info", responseKey: key, serverChallenge: challenge, clientChal: clientChallenge, targetInfo: make([]byte, 0xffff-47), want: ErrTargetInfo},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ComputeNTLMv2Response(test.responseKey, test.serverChallenge, test.clientChal, time.Time{}, test.targetInfo)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestChannelBindingHashVector(t *testing.T) {
	endpointHash := make([]byte, 32)
	for index := range endpointHash {
		endpointHash[index] = 1
	}
	binding, err := ChannelBindingHash(endpointHash)
	if err != nil {
		t.Fatalf("ChannelBindingHash: %v", err)
	}
	if got := hex.EncodeToString(binding); got != "50dd10ed32b9118b208a6d27e64be77f" {
		t.Fatalf("ChannelBindingHash = %s", got)
	}
	if _, err := ChannelBindingHash(nil); !errors.Is(err, ErrChannelBindings) {
		t.Fatalf("empty endpoint hash error = %v, want ErrChannelBindings", err)
	}
}
