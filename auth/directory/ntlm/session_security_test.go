package ntlm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"
	"sync"
	"testing"
)

// testSessionKey is the fixed MS-NLMP signing and sealing test session key. |
// testSessionKey 是固定的 MS-NLMP 签名与密封测试会话密钥。
const testSessionKeyHex = "0102030405060708090a0b0c0d0e0f00"

// testSigningFlags selects extended session security, 128-bit keys, key
// exchange and signing. | testSigningFlags 选择扩展会话安全、128 位密钥、密钥交换与签名。
func testSigningFlags() NegotiateFlags {
	return FlagExtendedSessionSecurity | Flag128 | FlagKeyExchange | FlagSign
}

// testSealingFlags selects extended session security, key exchange, signing and
// sealing plus the requested key width. | testSealingFlags 选择扩展会话安全、密钥交换、
// 签名与密封，并加上所需的密钥宽度。
func testSealingFlags(width NegotiateFlags) NegotiateFlags {
	return FlagExtendedSessionSecurity | FlagKeyExchange | FlagSign | FlagSeal | width
}

// testSecurityPair builds a client and server security session from the same
// exported session key. | testSecurityPair 从同一导出会话密钥构建客户端与服务端安全会话。
func testSecurityPair(t *testing.T, key []byte, flags NegotiateFlags) (*SecuritySession, *SecuritySession) {
	t.Helper()
	client, err := NewSecuritySession(RoleClient, key, flags)
	if err != nil {
		t.Fatalf("NewSecuritySession(RoleClient): %v", err)
	}
	server, err := NewSecuritySession(RoleServer, key, flags)
	if err != nil {
		t.Fatalf("NewSecuritySession(RoleServer): %v", err)
	}
	return client, server
}

// testHexLower encodes data as lowercase hexadecimal for comparisons. |
// testHexLower 以小写十六进制编码数据以便比较。
func testHexLower(data []byte) string {
	const digits = "0123456789abcdef"
	encoded := make([]byte, len(data)*2)
	for index, value := range data {
		encoded[index*2] = digits[value>>4]
		encoded[index*2+1] = digits[value&0x0f]
	}
	return string(encoded)
}

func TestDeriveSessionKeysKnownVectors(t *testing.T) {
	key := mustHex(t, testSessionKeyHex)
	keys, err := DeriveSessionKeys(key, testSigningFlags())
	if err != nil {
		t.Fatalf("DeriveSessionKeys: %v", err)
	}
	defer keys.Wipe()
	vectors := []struct {
		name string
		got  []byte
		want string
	}{
		{name: "client signing", got: keys.ClientSigningKey, want: "f7f97a82ec390f9c903dac4f6aceb132"},
		{name: "server signing", got: keys.ServerSigningKey, want: "58e9bd42cc6499d2a299d3c1bfdee9f2"},
		{name: "client sealing", got: keys.ClientSealingKey, want: "2785f595293f3e2813439d73a223810d"},
		{name: "server sealing", got: keys.ServerSealingKey, want: "fc05d67ad391940df1ffddaa37810071"},
	}
	for _, vector := range vectors {
		if got := testHexLower(vector.got); got != vector.want {
			t.Fatalf("%s key = %s, want %s", vector.name, got, vector.want)
		}
	}
}

func TestDeriveSessionKeysKeyWidth(t *testing.T) {
	key := mustHex(t, testSessionKeyHex)
	keys128, err := DeriveSessionKeys(key, testSigningFlags())
	if err != nil {
		t.Fatalf("DeriveSessionKeys(128): %v", err)
	}
	defer keys128.Wipe()
	keys56, err := DeriveSessionKeys(key, testSigningFlags()&^Flag128|Flag56)
	if err != nil {
		t.Fatalf("DeriveSessionKeys(56): %v", err)
	}
	defer keys56.Wipe()
	keys40, err := DeriveSessionKeys(key, testSigningFlags()&^Flag128)
	if err != nil {
		t.Fatalf("DeriveSessionKeys(40): %v", err)
	}
	defer keys40.Wipe()
	for _, pair := range [][2]*SessionKeys{{keys128, keys56}, {keys128, keys40}, {keys56, keys40}} {
		if !bytes.Equal(pair[0].ClientSigningKey, pair[1].ClientSigningKey) {
			t.Fatalf("client signing key depends on the key width")
		}
		if !bytes.Equal(pair[0].ServerSigningKey, pair[1].ServerSigningKey) {
			t.Fatalf("server signing key depends on the key width")
		}
		if bytes.Equal(pair[0].ClientSealingKey, pair[1].ClientSealingKey) {
			t.Fatalf("client sealing key ignores the key width")
		}
		if bytes.Equal(pair[0].ServerSealingKey, pair[1].ServerSealingKey) {
			t.Fatalf("server sealing key ignores the key width")
		}
	}
}

func TestDeriveSessionKeysValidation(t *testing.T) {
	if _, err := DeriveSessionKeys([]byte{1, 2, 3}, testSigningFlags()); !errors.Is(err, ErrSessionSecurity) {
		t.Fatalf("short key error = %v, want ErrSessionSecurity", err)
	}
	if _, err := DeriveSessionKeys(mustHex(t, testSessionKeyHex), FlagKeyExchange|FlagSign); !errors.Is(err, ErrSessionSecurity) {
		t.Fatalf("missing extended session security error = %v, want ErrSessionSecurity", err)
	}
}

func TestSessionKeyExchangeKnownVector(t *testing.T) {
	sessionBaseKey := mustHex(t, "8de40ccadbc14a82f15cb0ad0de95ca3")
	randomSessionKey := mustHex(t, testSessionKeyHex)
	encrypted, err := rc4SessionKey(sessionBaseKey, randomSessionKey)
	if err != nil {
		t.Fatalf("rc4SessionKey(encrypt): %v", err)
	}
	if got := testHexLower(encrypted); got != "918d84051f9a2bcdc89142b053928a6b" {
		t.Fatalf("encrypted session key = %s", got)
	}
	decrypted, err := rc4SessionKey(sessionBaseKey, encrypted)
	if err != nil {
		t.Fatalf("rc4SessionKey(decrypt): %v", err)
	}
	if !bytes.Equal(decrypted, randomSessionKey) {
		t.Fatalf("decrypted session key = %x", decrypted)
	}
}

func TestSecuritySessionSignKnownVector(t *testing.T) {
	client, err := NewSecuritySession(RoleClient, mustHex(t, testSessionKeyHex), testSigningFlags())
	if err != nil {
		t.Fatalf("NewSecuritySession: %v", err)
	}
	defer client.Close()
	signature, err := client.Sign([]byte("jCIFS"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got := testHexLower(signature); got != "01000000e37f97f2544f4d7e00000000" {
		t.Fatalf("signature = %s", got)
	}
}

func TestSecuritySessionSealKnownVectors(t *testing.T) {
	tests := []struct {
		name  string
		flags NegotiateFlags
		want  string
	}{
		{
			name:  "128-bit",
			flags: testSealingFlags(Flag128),
			want:  "833ce8b636010000003f38d2e35a371ff300000000",
		},
		{
			name:  "56-bit",
			flags: testSealingFlags(Flag56),
			want:  "cc0fa554d301000000444df7707cbadbca00000000",
		},
		{
			name:  "40-bit",
			flags: testSealingFlags(0),
			want:  "cf0eb0a93901000000884b14809e53bfe700000000",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewSecuritySession(RoleClient, mustHex(t, testSessionKeyHex), test.flags)
			if err != nil {
				t.Fatalf("NewSecuritySession: %v", err)
			}
			defer client.Close()
			sealed, err := client.Seal([]byte("jCIFS"))
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			if got := testHexLower(sealed); got != test.want {
				t.Fatalf("sealed = %s, want %s", got, test.want)
			}
		})
	}
}

func TestSecuritySessionBidirectionalSign(t *testing.T) {
	client, server := testSecurityPair(t, mustHex(t, testSessionKeyHex), testSigningFlags())
	defer client.Close()
	defer server.Close()
	messages := [][]byte{[]byte("first"), []byte("second"), []byte("third")}
	for _, message := range messages {
		signature, err := client.Sign(message)
		if err != nil {
			t.Fatalf("client Sign: %v", err)
		}
		if err := server.Verify(message, signature); err != nil {
			t.Fatalf("server Verify: %v", err)
		}
		signature, err = server.Sign(message)
		if err != nil {
			t.Fatalf("server Sign: %v", err)
		}
		if err := client.Verify(message, signature); err != nil {
			t.Fatalf("client Verify: %v", err)
		}
	}
}

func TestSecuritySessionBidirectionalSeal(t *testing.T) {
	for _, keyExchange := range []bool{true, false} {
		name := "without key exchange"
		if keyExchange {
			name = "with key exchange"
		}
		t.Run(name, func(t *testing.T) {
			flags := testSealingFlags(Flag128)
			if !keyExchange {
				flags &^= FlagKeyExchange
			}
			client, server := testSecurityPair(t, mustHex(t, testSessionKeyHex), flags)
			defer client.Close()
			defer server.Close()
			for _, plaintext := range [][]byte{[]byte("client payload"), {0x00}, bytes.Repeat([]byte{0xaa}, 100)} {
				sealed, err := client.Seal(plaintext)
				if err != nil {
					t.Fatalf("client Seal: %v", err)
				}
				if bytes.Equal(sealed[:len(plaintext)], plaintext) {
					t.Fatalf("sealed payload is plaintext")
				}
				opened, err := server.Unseal(sealed)
				if err != nil {
					t.Fatalf("server Unseal: %v", err)
				}
				if !bytes.Equal(opened, plaintext) {
					t.Fatalf("opened = %x, want %x", opened, plaintext)
				}
				sealed, err = server.Seal(plaintext)
				if err != nil {
					t.Fatalf("server Seal: %v", err)
				}
				opened, err = client.Unseal(sealed)
				if err != nil {
					t.Fatalf("client Unseal: %v", err)
				}
				if !bytes.Equal(opened, plaintext) {
					t.Fatalf("opened = %x, want %x", opened, plaintext)
				}
			}
		})
	}
}

func TestSecuritySessionTamperedSignature(t *testing.T) {
	client, server := testSecurityPair(t, mustHex(t, testSessionKeyHex), testSigningFlags())
	defer client.Close()
	message := []byte("tamper me")
	signature, err := client.Sign(message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	signature[4] ^= 0x80
	if err := server.Verify(message, signature); !errors.Is(err, ErrSignature) {
		t.Fatalf("Verify error = %v, want ErrSignature", err)
	}
	if !server.Closed() {
		t.Fatalf("server session did not fail closed")
	}
	if server.keys != nil || server.sendCipher != nil || server.recvCipher != nil {
		t.Fatalf("server session retains key material after fail closed")
	}
	if err := server.Verify(message, signature); !errors.Is(err, ErrSessionSecurity) {
		t.Fatalf("Verify after fail closed error = %v, want ErrSessionSecurity", err)
	}
}

func TestSecuritySessionTamperedCiphertext(t *testing.T) {
	client, server := testSecurityPair(t, mustHex(t, testSessionKeyHex), testSealingFlags(Flag128))
	defer client.Close()
	sealed, err := client.Seal([]byte("sealed payload"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	sealed[0] ^= 0x01
	if _, err := server.Unseal(sealed); !errors.Is(err, ErrSignature) {
		t.Fatalf("Unseal error = %v, want ErrSignature", err)
	}
	if !server.Closed() {
		t.Fatalf("server session did not fail closed")
	}
}

func TestSecuritySessionSequence(t *testing.T) {
	client, server := testSecurityPair(t, mustHex(t, testSessionKeyHex), testSigningFlags())
	defer client.Close()
	first, err := client.Sign([]byte("one"))
	if err != nil {
		t.Fatalf("Sign(one): %v", err)
	}
	second, err := client.Sign([]byte("two"))
	if err != nil {
		t.Fatalf("Sign(two): %v", err)
	}
	if binary.LittleEndian.Uint32(first[12:16]) != 0 || binary.LittleEndian.Uint32(second[12:16]) != 1 {
		t.Fatalf("unexpected sequence numbers %d and %d", binary.LittleEndian.Uint32(first[12:16]), binary.LittleEndian.Uint32(second[12:16]))
	}
	if err := server.Verify([]byte("two"), second); !errors.Is(err, ErrSequence) {
		t.Fatalf("out-of-order Verify error = %v, want ErrSequence", err)
	}
	if !server.Closed() {
		t.Fatalf("server session did not fail closed on an out-of-order message")
	}
	if err := server.Verify([]byte("one"), first); !errors.Is(err, ErrSessionSecurity) {
		t.Fatalf("Verify after out-of-order error = %v, want ErrSessionSecurity", err)
	}
}

func TestSecuritySessionReplay(t *testing.T) {
	client, server := testSecurityPair(t, mustHex(t, testSessionKeyHex), testSigningFlags())
	defer client.Close()
	signature, err := client.Sign([]byte("replay"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := server.Verify([]byte("replay"), signature); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	if err := server.Verify([]byte("replay"), signature); !errors.Is(err, ErrSequence) {
		t.Fatalf("replayed Verify error = %v, want ErrSequence", err)
	}
}

func TestSecuritySessionSignatureValidation(t *testing.T) {
	client, server := testSecurityPair(t, mustHex(t, testSessionKeyHex), testSigningFlags())
	defer client.Close()
	if err := server.Verify([]byte("short"), make([]byte, 15)); !errors.Is(err, ErrSignature) {
		t.Fatalf("short signature error = %v, want ErrSignature", err)
	}
	client2, server2 := testSecurityPair(t, mustHex(t, testSessionKeyHex), testSigningFlags())
	defer client2.Close()
	signature, err := client2.Sign([]byte("version"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	signature[0] = 2
	if err := server2.Verify([]byte("version"), signature); !errors.Is(err, ErrSignature) {
		t.Fatalf("version error = %v, want ErrSignature", err)
	}
}

func TestSecuritySessionNotNegotiated(t *testing.T) {
	key := mustHex(t, testSessionKeyHex)
	session, err := NewSecuritySession(RoleClient, key, FlagExtendedSessionSecurity|FlagKeyExchange|FlagSign)
	if err != nil {
		t.Fatalf("NewSecuritySession: %v", err)
	}
	defer session.Close()
	if _, err := session.Seal([]byte("x")); !errors.Is(err, ErrSealingNotNegotiated) {
		t.Fatalf("Seal error = %v, want ErrSealingNotNegotiated", err)
	}
	if _, err := session.Unseal(make([]byte, messageSignatureSize)); !errors.Is(err, ErrSealingNotNegotiated) {
		t.Fatalf("Unseal error = %v, want ErrSealingNotNegotiated", err)
	}
}

func TestNewSecuritySessionValidation(t *testing.T) {
	key := mustHex(t, testSessionKeyHex)
	if _, err := NewSecuritySession(Role(99), key, testSigningFlags()); !errors.Is(err, ErrSessionSecurity) {
		t.Fatalf("invalid role error = %v, want ErrSessionSecurity", err)
	}
	if _, err := NewSecuritySession(RoleClient, key, FlagExtendedSessionSecurity); !errors.Is(err, ErrSessionSecurity) {
		t.Fatalf("no signing error = %v, want ErrSessionSecurity", err)
	}
	if _, err := NewSecuritySession(RoleClient, key, FlagExtendedSessionSecurity|FlagSeal); !errors.Is(err, ErrSessionSecurity) {
		t.Fatalf("seal without sign error = %v, want ErrSessionSecurity", err)
	}
	if _, err := NewSecuritySession(RoleClient, key[:15], testSigningFlags()); !errors.Is(err, ErrSessionSecurity) {
		t.Fatalf("short key error = %v, want ErrSessionSecurity", err)
	}
	if _, err := NewSecuritySession(RoleClient, key, FlagExtendedSessionSecurity|FlagSign); err != nil {
		t.Fatalf("signing-only session: %v", err)
	}
}

func TestSecuritySessionCloseIdempotent(t *testing.T) {
	session, err := NewSecuritySession(RoleClient, mustHex(t, testSessionKeyHex), testSealingFlags(Flag128))
	if err != nil {
		t.Fatalf("NewSecuritySession: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if !session.Closed() {
		t.Fatalf("session is not closed")
	}
	if session.keys != nil || session.sendCipher != nil || session.recvCipher != nil {
		t.Fatalf("session retains key material after Close")
	}
	if _, err := session.Sign([]byte("x")); !errors.Is(err, ErrSessionSecurity) {
		t.Fatalf("Sign after Close error = %v, want ErrSessionSecurity", err)
	}
	if _, err := session.Seal([]byte("x")); !errors.Is(err, ErrSessionSecurity) {
		t.Fatalf("Seal after Close error = %v, want ErrSessionSecurity", err)
	}
}

func TestSecuritySessionConcurrentSign(t *testing.T) {
	client, server := testSecurityPair(t, mustHex(t, testSessionKeyHex), testSigningFlags())
	defer client.Close()
	defer server.Close()
	const count = 32
	type signedMessage struct {
		message   []byte
		signature []byte
	}
	results := make([]signedMessage, count)
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			message := []byte("concurrent signed message")
			signature, err := client.Sign(message)
			if err != nil {
				t.Errorf("Sign: %v", err)
				return
			}
			results[index] = signedMessage{message: message, signature: signature}
		}(index)
	}
	wait.Wait()
	if t.Failed() {
		return
	}
	sort.Slice(results, func(i, j int) bool {
		return binary.LittleEndian.Uint32(results[i].signature[12:16]) < binary.LittleEndian.Uint32(results[j].signature[12:16])
	})
	for _, result := range results {
		if err := server.Verify(result.message, result.signature); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	}
}

func TestSecuritySessionConcurrentSeal(t *testing.T) {
	client, server := testSecurityPair(t, mustHex(t, testSessionKeyHex), testSealingFlags(Flag128))
	defer client.Close()
	defer server.Close()
	const count = 32
	sealedMessages := make([][]byte, count)
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			sealed, err := client.Seal([]byte("concurrent sealed message"))
			if err != nil {
				t.Errorf("Seal: %v", err)
				return
			}
			sealedMessages[index] = sealed
		}(index)
	}
	wait.Wait()
	if t.Failed() {
		return
	}
	sort.Slice(sealedMessages, func(i, j int) bool {
		left := sealedMessages[i]
		right := sealedMessages[j]
		return binary.LittleEndian.Uint32(left[len(left)-4:]) < binary.LittleEndian.Uint32(right[len(right)-4:])
	})
	for _, sealed := range sealedMessages {
		opened, err := server.Unseal(sealed)
		if err != nil {
			t.Fatalf("Unseal: %v", err)
		}
		if !bytes.Equal(opened, []byte("concurrent sealed message")) {
			t.Fatalf("opened = %q", opened)
		}
	}
}
