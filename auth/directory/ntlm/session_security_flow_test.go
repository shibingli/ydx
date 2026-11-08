package ntlm

import (
	"bytes"
	"errors"
	"testing"
)

// testSessionSecurityRandomKey returns the deterministic exported session key
// used by the flow tests. | testSessionSecurityRandomKey 返回流程测试使用的确定性导出
// 会话密钥。
func testSessionSecurityRandomKey() []byte {
	return []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}
}

// testSessionSecurityClientConfig returns a client configuration that requests
// signing, sealing and key exchange. | testSessionSecurityClientConfig 返回请求签名、
// 密封与密钥交换的客户端配置。
func testSessionSecurityClientConfig() Config {
	config := clientConfig()
	config.Sign = true
	config.Seal = true
	config.KeyExchange = true
	config.RandomSessionKey = testSessionSecurityRandomKey()
	return config
}

// testSessionSecurityAcceptorConfig returns an acceptor configuration that
// requires signing, sealing and key exchange. | testSessionSecurityAcceptorConfig
// 返回要求签名、密封与密钥交换的接受方配置。
func testSessionSecurityAcceptorConfig() AcceptorConfig {
	config := testAcceptorConfig()
	config.Sign = true
	config.Seal = true
	config.KeyExchange = true
	return config
}

// testSessionSecurityRawExchange runs a raw NTLM exchange and verifies the final
// message. | testSessionSecurityRawExchange 执行裸 NTLM 交换并校验最终消息。
func testSessionSecurityRawExchange(t *testing.T, clientConfig Config, acceptorConfig AcceptorConfig) (*Client, *Acceptor, *AcceptResult) {
	t.Helper()
	acceptorConfig.AllowRawNTLM = true
	client := clientCreate(t, clientConfig)
	acceptor := testNewAcceptor(t, acceptorConfig)
	type1, err := client.Negotiate()
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	type2, err := acceptor.AcceptInitial(type1)
	if err != nil {
		t.Fatalf("AcceptInitial: %v", err)
	}
	type3, err := client.Authenticate(type2)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	result, finalToken, err := acceptor.AcceptFinal(type3)
	if err != nil {
		t.Fatalf("AcceptFinal: %v", err)
	}
	if finalToken != nil {
		t.Fatalf("raw NTLM returned a final SPNEGO token")
	}
	return client, acceptor, result
}

// testSessionSecurityRawType3 runs a raw NTLM negotiation without accepting the
// Type 3 message. | testSessionSecurityRawType3 执行裸 NTLM 协商但不接受 Type 3 消息。
func testSessionSecurityRawType3(t *testing.T, clientConfig Config, acceptorConfig AcceptorConfig) (*Acceptor, []byte) {
	t.Helper()
	acceptorConfig.AllowRawNTLM = true
	acceptor := testNewAcceptor(t, acceptorConfig)
	client := clientCreate(t, clientConfig)
	defer client.Close()
	type1, err := client.Negotiate()
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	type2, err := acceptor.AcceptInitial(type1)
	if err != nil {
		t.Fatalf("AcceptInitial: %v", err)
	}
	type3, err := client.Authenticate(type2)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	return acceptor, type3
}

func TestClientAcceptorSessionSecurityRaw(t *testing.T) {
	client, acceptor, result := testSessionSecurityRawExchange(t, testSessionSecurityClientConfig(), testSessionSecurityAcceptorConfig())
	defer client.Close()
	defer acceptor.Close()
	for _, flag := range []NegotiateFlags{FlagSign, FlagSeal, FlagKeyExchange, FlagExtendedSessionSecurity} {
		if !result.Flags.Has(flag) {
			t.Fatalf("negotiated flags %#x lack %#x", result.Flags, flag)
		}
	}
	want := testSessionSecurityRandomKey()
	for name, key := range map[string][]byte{
		"result":   result.ExportedSessionKey,
		"client":   mustSessionKey(t, client),
		"acceptor": mustSessionKey(t, acceptor),
	} {
		if !bytes.Equal(key, want) {
			t.Fatalf("%s exported session key = %x, want %x", name, key, want)
		}
	}
	if bytes.Equal(result.ExportedSessionKey, result.SessionBaseKey) {
		t.Fatalf("key exchange did not change the exported session key")
	}
	clientSecurity, err := client.SecuritySession()
	if err != nil {
		t.Fatalf("client SecuritySession: %v", err)
	}
	acceptorSecurity, err := acceptor.SecuritySession()
	if err != nil {
		t.Fatalf("acceptor SecuritySession: %v", err)
	}
	if clientSecurity.Role() != RoleClient || acceptorSecurity.Role() != RoleServer {
		t.Fatalf("security session roles = %s and %s", clientSecurity.Role(), acceptorSecurity.Role())
	}

	clientSealed, err := client.Seal([]byte("client to server"))
	if err != nil {
		t.Fatalf("client Seal: %v", err)
	}
	opened, err := acceptor.Unseal(clientSealed)
	if err != nil {
		t.Fatalf("acceptor Unseal: %v", err)
	}
	if string(opened) != "client to server" {
		t.Fatalf("opened = %q", opened)
	}
	serverSealed, err := acceptor.Seal([]byte("server to client"))
	if err != nil {
		t.Fatalf("acceptor Seal: %v", err)
	}
	opened, err = client.Unseal(serverSealed)
	if err != nil {
		t.Fatalf("client Unseal: %v", err)
	}
	if string(opened) != "server to client" {
		t.Fatalf("opened = %q", opened)
	}

	clientSignature, err := client.Sign([]byte("client signed"))
	if err != nil {
		t.Fatalf("client Sign: %v", err)
	}
	if err := acceptor.Verify([]byte("client signed"), clientSignature); err != nil {
		t.Fatalf("acceptor Verify: %v", err)
	}
	serverSignature, err := acceptor.Sign([]byte("server signed"))
	if err != nil {
		t.Fatalf("acceptor Sign: %v", err)
	}
	if err := client.Verify([]byte("server signed"), serverSignature); err != nil {
		t.Fatalf("client Verify: %v", err)
	}
}

func mustSessionKey(t *testing.T, endpoint interface {
	ExportedSessionKey() ([]byte, error)
}) []byte {
	t.Helper()
	key, err := endpoint.ExportedSessionKey()
	if err != nil {
		t.Fatalf("ExportedSessionKey: %v", err)
	}
	return key
}

func TestClientSigningOnly(t *testing.T) {
	clientConfig := clientConfig()
	clientConfig.Sign = true
	acceptorConfig := testAcceptorConfig()
	acceptorConfig.Sign = true
	client, acceptor, result := testSessionSecurityRawExchange(t, clientConfig, acceptorConfig)
	defer client.Close()
	defer acceptor.Close()
	if !result.Flags.Has(FlagSign) || result.Flags.Has(FlagSeal) {
		t.Fatalf("negotiated flags = %#x", result.Flags)
	}
	signature, err := client.Sign([]byte("signed only"))
	if err != nil {
		t.Fatalf("client Sign: %v", err)
	}
	if err := acceptor.Verify([]byte("signed only"), signature); err != nil {
		t.Fatalf("acceptor Verify: %v", err)
	}
	if _, err := client.Seal([]byte("x")); !errors.Is(err, ErrSealingNotNegotiated) {
		t.Fatalf("client Seal error = %v, want ErrSealingNotNegotiated", err)
	}
	if _, err := acceptor.Seal([]byte("x")); !errors.Is(err, ErrSealingNotNegotiated) {
		t.Fatalf("acceptor Seal error = %v, want ErrSealingNotNegotiated", err)
	}
}

func TestClientAcceptorKeyExchangeWithoutSigning(t *testing.T) {
	clientConfig := clientConfig()
	clientConfig.KeyExchange = true
	clientConfig.RandomSessionKey = testSessionSecurityRandomKey()
	acceptorConfig := testAcceptorConfig()
	acceptorConfig.KeyExchange = true
	client, acceptor, result := testSessionSecurityRawExchange(t, clientConfig, acceptorConfig)
	defer client.Close()
	defer acceptor.Close()
	if result.Flags.Has(FlagSign) || result.Flags.Has(FlagSeal) {
		t.Fatalf("negotiated flags = %#x", result.Flags)
	}
	if !bytes.Equal(result.ExportedSessionKey, testSessionSecurityRandomKey()) {
		t.Fatalf("result exported session key = %x", result.ExportedSessionKey)
	}
	if !bytes.Equal(mustSessionKey(t, client), testSessionSecurityRandomKey()) {
		t.Fatalf("client exported session key = %x", mustSessionKey(t, client))
	}
	if !bytes.Equal(mustSessionKey(t, acceptor), testSessionSecurityRandomKey()) {
		t.Fatalf("acceptor exported session key = %x", mustSessionKey(t, acceptor))
	}
	if _, err := client.SecuritySession(); !errors.Is(err, ErrSessionSecurity) {
		t.Fatalf("client SecuritySession error = %v, want ErrSessionSecurity", err)
	}
	if _, err := acceptor.SecuritySession(); !errors.Is(err, ErrSessionSecurity) {
		t.Fatalf("acceptor SecuritySession error = %v, want ErrSessionSecurity", err)
	}
}

func TestClientKeyExchangeType3SessionKey(t *testing.T) {
	clientConfig := testSessionSecurityClientConfig()
	acceptorConfig := testSessionSecurityAcceptorConfig()
	acceptorConfig.AllowRawNTLM = true
	client := clientCreate(t, clientConfig)
	acceptor := testNewAcceptor(t, acceptorConfig)
	defer client.Close()
	defer acceptor.Close()
	type1, err := client.Negotiate()
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	type2, err := acceptor.AcceptInitial(type1)
	if err != nil {
		t.Fatalf("AcceptInitial: %v", err)
	}
	type3, err := client.Authenticate(type2)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	message, err := DecodeAuthenticate(type3)
	if err != nil {
		t.Fatalf("DecodeAuthenticate: %v", err)
	}
	if len(message.SessionKey) != sessionKeySize {
		t.Fatalf("Type 3 session key is %d bytes, want %d", len(message.SessionKey), sessionKeySize)
	}
	result, _, err := acceptor.AcceptFinal(type3)
	if err != nil {
		t.Fatalf("AcceptFinal: %v", err)
	}
	expected, err := rc4SessionKey(result.SessionBaseKey, testSessionSecurityRandomKey())
	if err != nil {
		t.Fatalf("rc4SessionKey: %v", err)
	}
	if !bytes.Equal(message.SessionKey, expected) {
		t.Fatalf("Type 3 session key = %x, want %x", message.SessionKey, expected)
	}
	if !bytes.Equal(result.ExportedSessionKey, testSessionSecurityRandomKey()) {
		t.Fatalf("exported session key = %x", result.ExportedSessionKey)
	}
}

func TestClientAcceptorSessionSecurityWithoutKeyExchange(t *testing.T) {
	clientConfig := testSessionSecurityClientConfig()
	clientConfig.KeyExchange = false
	clientConfig.RandomSessionKey = nil
	acceptorConfig := testSessionSecurityAcceptorConfig()
	acceptorConfig.KeyExchange = false
	client, acceptor, result := testSessionSecurityRawExchange(t, clientConfig, acceptorConfig)
	defer client.Close()
	defer acceptor.Close()
	if result.Flags.Has(FlagKeyExchange) {
		t.Fatalf("key exchange was negotiated")
	}
	if !bytes.Equal(result.ExportedSessionKey, result.SessionBaseKey) {
		t.Fatalf("exported session key differs from the session base key")
	}
	if !bytes.Equal(mustSessionKey(t, client), result.SessionBaseKey) {
		t.Fatalf("client exported session key differs from the session base key")
	}
	if !bytes.Equal(mustSessionKey(t, acceptor), result.SessionBaseKey) {
		t.Fatalf("acceptor exported session key differs from the session base key")
	}
	sealed, err := client.Seal([]byte("no key exchange"))
	if err != nil {
		t.Fatalf("client Seal: %v", err)
	}
	opened, err := acceptor.Unseal(sealed)
	if err != nil {
		t.Fatalf("acceptor Unseal: %v", err)
	}
	if string(opened) != "no key exchange" {
		t.Fatalf("opened = %q", opened)
	}
}

func TestClientSessionSecurityNotNegotiated(t *testing.T) {
	t.Run("server declines signing", func(t *testing.T) {
		client := clientCreate(t, testSessionSecurityClientConfig())
		defer client.Close()
		if _, err := client.Negotiate(); err != nil {
			t.Fatalf("Negotiate: %v", err)
		}
		challenge := clientChallengeBytes(t, clientServerFlags(), [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, clientDomainTargetInfo())
		if _, err := client.Authenticate(challenge); !errors.Is(err, ErrSigningNotNegotiated) {
			t.Fatalf("Authenticate error = %v, want ErrSigningNotNegotiated", err)
		}
	})
	t.Run("signing not requested", func(t *testing.T) {
		client, _, _ := testSessionSecurityRawExchange(t, clientConfig(), testAcceptorConfig())
		defer client.Close()
		if _, err := client.SecuritySession(); !errors.Is(err, ErrSessionSecurity) {
			t.Fatalf("SecuritySession error = %v, want ErrSessionSecurity", err)
		}
		if _, err := client.Sign([]byte("x")); !errors.Is(err, ErrSigningNotNegotiated) {
			t.Fatalf("Sign error = %v, want ErrSigningNotNegotiated", err)
		}
		if _, err := client.Seal([]byte("x")); !errors.Is(err, ErrSealingNotNegotiated) {
			t.Fatalf("Seal error = %v, want ErrSealingNotNegotiated", err)
		}
		if err := client.Verify([]byte("x"), make([]byte, messageSignatureSize)); !errors.Is(err, ErrSigningNotNegotiated) {
			t.Fatalf("Verify error = %v, want ErrSigningNotNegotiated", err)
		}
		if _, err := client.Unseal(make([]byte, messageSignatureSize)); !errors.Is(err, ErrSealingNotNegotiated) {
			t.Fatalf("Unseal error = %v, want ErrSealingNotNegotiated", err)
		}
		if key, err := client.ExportedSessionKey(); err != nil || len(key) != sessionKeySize {
			t.Fatalf("ExportedSessionKey = %x, %v", key, err)
		}
	})
	t.Run("before authentication", func(t *testing.T) {
		client := clientCreate(t, testSessionSecurityClientConfig())
		defer client.Close()
		if _, err := client.Sign([]byte("x")); !errors.Is(err, ErrClientState) {
			t.Fatalf("Sign error = %v, want ErrClientState", err)
		}
		if _, err := client.SecuritySession(); !errors.Is(err, ErrClientState) {
			t.Fatalf("SecuritySession error = %v, want ErrClientState", err)
		}
		if _, err := client.ExportedSessionKey(); !errors.Is(err, ErrClientState) {
			t.Fatalf("ExportedSessionKey error = %v, want ErrClientState", err)
		}
	})
}

func TestAcceptorSessionSecurityNotNegotiated(t *testing.T) {
	t.Run("client declines signing", func(t *testing.T) {
		clientConfig := clientConfig()
		acceptorConfig := testSessionSecurityAcceptorConfig()
		acceptor, type3 := testSessionSecurityRawType3(t, clientConfig, acceptorConfig)
		if _, _, err := acceptor.AcceptFinal(type3); !errors.Is(err, ErrSigningNotNegotiated) {
			t.Fatalf("AcceptFinal error = %v, want ErrSigningNotNegotiated", err)
		}
	})
	t.Run("client declines key exchange", func(t *testing.T) {
		acceptorConfig := testAcceptorConfig()
		acceptorConfig.KeyExchange = true
		acceptor, type3 := testSessionSecurityRawType3(t, clientConfig(), acceptorConfig)
		if _, _, err := acceptor.AcceptFinal(type3); !errors.Is(err, ErrSessionSecurity) {
			t.Fatalf("AcceptFinal error = %v, want ErrSessionSecurity", err)
		}
	})
	t.Run("signing not requested", func(t *testing.T) {
		_, acceptor, _ := testSessionSecurityRawExchange(t, clientConfig(), testAcceptorConfig())
		defer acceptor.Close()
		if _, err := acceptor.SecuritySession(); !errors.Is(err, ErrSessionSecurity) {
			t.Fatalf("SecuritySession error = %v, want ErrSessionSecurity", err)
		}
		if _, err := acceptor.Sign([]byte("x")); !errors.Is(err, ErrSigningNotNegotiated) {
			t.Fatalf("Sign error = %v, want ErrSigningNotNegotiated", err)
		}
		if _, err := acceptor.Seal([]byte("x")); !errors.Is(err, ErrSealingNotNegotiated) {
			t.Fatalf("Seal error = %v, want ErrSealingNotNegotiated", err)
		}
	})
	t.Run("sealing requires signing", func(t *testing.T) {
		config := testAcceptorConfig()
		config.Seal = true
		if _, err := NewAcceptor(config); !errors.Is(err, ErrAcceptorConfig) {
			t.Fatalf("NewAcceptor error = %v, want ErrAcceptorConfig", err)
		}
	})
	t.Run("signing requires extended session security", func(t *testing.T) {
		config := testAcceptorConfig()
		config.Sign = true
		config.Flags = FlagUnicode | FlagNTLM | FlagTargetInfo
		if _, err := NewAcceptor(config); !errors.Is(err, ErrAcceptorConfig) {
			t.Fatalf("NewAcceptor error = %v, want ErrAcceptorConfig", err)
		}
	})
}

func TestAcceptorType3SessionKeyValidation(t *testing.T) {
	t.Run("key exchange with short session key", func(t *testing.T) {
		acceptor, type3 := testSessionSecurityRawType3(t, testSessionSecurityClientConfig(), testSessionSecurityAcceptorConfig())
		message, err := DecodeAuthenticate(type3)
		if err != nil {
			t.Fatalf("DecodeAuthenticate: %v", err)
		}
		message.SessionKey = message.SessionKey[:len(message.SessionKey)-1]
		mutated, err := message.Encode()
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		if _, _, err := acceptor.AcceptFinal(mutated); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("AcceptFinal error = %v, want ErrAuthentication", err)
		}
	})
	t.Run("key exchange without session key", func(t *testing.T) {
		acceptor, type3 := testSessionSecurityRawType3(t, testSessionSecurityClientConfig(), testSessionSecurityAcceptorConfig())
		message, err := DecodeAuthenticate(type3)
		if err != nil {
			t.Fatalf("DecodeAuthenticate: %v", err)
		}
		message.SessionKey = nil
		mutated, err := message.Encode()
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		if _, _, err := acceptor.AcceptFinal(mutated); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("AcceptFinal error = %v, want ErrAuthentication", err)
		}
	})
	t.Run("session key ignored without key exchange", func(t *testing.T) {
		clientConfig := testSessionSecurityClientConfig()
		clientConfig.KeyExchange = false
		clientConfig.RandomSessionKey = nil
		acceptorConfig := testSessionSecurityAcceptorConfig()
		acceptorConfig.KeyExchange = false
		acceptor, type3 := testSessionSecurityRawType3(t, clientConfig, acceptorConfig)
		message, err := DecodeAuthenticate(type3)
		if err != nil {
			t.Fatalf("DecodeAuthenticate: %v", err)
		}
		message.SessionKey = testSessionSecurityRandomKey()
		mutated, err := message.Encode()
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		result, _, err := acceptor.AcceptFinal(mutated)
		if err != nil {
			t.Fatalf("AcceptFinal: %v", err)
		}
		if !bytes.Equal(result.ExportedSessionKey, result.SessionBaseKey) {
			t.Fatalf("exported session key %x differs from SessionBaseKey %x", result.ExportedSessionKey, result.SessionBaseKey)
		}
	})
}

func TestSPNEGOSessionSecurityRoundTrip(t *testing.T) {
	acceptor := testNewAcceptor(t, testSessionSecurityAcceptorConfig())
	client, err := NewSPNEGOClient(testSessionSecurityClientConfig())
	if err != nil {
		t.Fatalf("NewSPNEGOClient: %v", err)
	}
	defer client.Close()
	defer acceptor.Close()
	initial, err := client.InitialToken()
	if err != nil {
		t.Fatalf("InitialToken: %v", err)
	}
	challengeToken, err := acceptor.AcceptInitial(initial)
	if err != nil {
		t.Fatalf("AcceptInitial: %v", err)
	}
	finalToken, err := client.AcceptToken(challengeToken)
	if err != nil {
		t.Fatalf("client AcceptToken: %v", err)
	}
	result, serverFinal, err := acceptor.AcceptFinal(finalToken)
	if err != nil {
		t.Fatalf("AcceptFinal: %v", err)
	}
	if serverFinal == nil {
		if err := client.Complete(); err != nil {
			t.Fatalf("Complete: %v", err)
		}
	} else if _, err := client.AcceptToken(serverFinal); err != nil {
		t.Fatalf("client AcceptToken(server final): %v", err)
	}
	if !bytes.Equal(result.ExportedSessionKey, testSessionSecurityRandomKey()) {
		t.Fatalf("result exported session key = %x", result.ExportedSessionKey)
	}
	if !bytes.Equal(mustSessionKey(t, client), testSessionSecurityRandomKey()) {
		t.Fatalf("client exported session key = %x", mustSessionKey(t, client))
	}
	sealed, err := client.Seal([]byte("spnego client to server"))
	if err != nil {
		t.Fatalf("client Seal: %v", err)
	}
	opened, err := acceptor.Unseal(sealed)
	if err != nil {
		t.Fatalf("acceptor Unseal: %v", err)
	}
	if string(opened) != "spnego client to server" {
		t.Fatalf("opened = %q", opened)
	}
	signature, err := acceptor.Sign([]byte("spnego server to client"))
	if err != nil {
		t.Fatalf("acceptor Sign: %v", err)
	}
	if err := client.Verify([]byte("spnego server to client"), signature); err != nil {
		t.Fatalf("client Verify: %v", err)
	}
}

func TestSessionSecurityCloseLifecycle(t *testing.T) {
	client, acceptor, _ := testSessionSecurityRawExchange(t, testSessionSecurityClientConfig(), testSessionSecurityAcceptorConfig())
	clientSecurity, err := client.SecuritySession()
	if err != nil {
		t.Fatalf("client SecuritySession: %v", err)
	}
	acceptorSecurity, err := acceptor.SecuritySession()
	if err != nil {
		t.Fatalf("acceptor SecuritySession: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("client Close: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("second client Close: %v", err)
	}
	if !clientSecurity.Closed() {
		t.Fatalf("client security session is not closed")
	}
	if client.sessionBaseKey != nil || client.exportedSessionKey != nil || client.responseKey != nil {
		t.Fatalf("client retains key material after Close")
	}
	if _, err := client.Sign([]byte("x")); !errors.Is(err, ErrClientState) {
		t.Fatalf("client Sign error = %v, want ErrClientState", err)
	}
	if _, err := client.ExportedSessionKey(); !errors.Is(err, ErrClientState) {
		t.Fatalf("client ExportedSessionKey error = %v, want ErrClientState", err)
	}
	if err := acceptor.Close(); err != nil {
		t.Fatalf("acceptor Close: %v", err)
	}
	if err := acceptor.Close(); err != nil {
		t.Fatalf("second acceptor Close: %v", err)
	}
	if !acceptorSecurity.Closed() {
		t.Fatalf("acceptor security session is not closed")
	}
	if acceptor.exportedSessionKey != nil {
		t.Fatalf("acceptor retains the exported session key after Close")
	}
	if _, err := acceptor.Sign([]byte("x")); !errors.Is(err, ErrAcceptorState) {
		t.Fatalf("acceptor Sign error = %v, want ErrAcceptorState", err)
	}
	if _, err := acceptor.SecuritySession(); !errors.Is(err, ErrAcceptorState) {
		t.Fatalf("acceptor SecuritySession error = %v, want ErrAcceptorState", err)
	}
	if _, err := acceptor.ExportedSessionKey(); !errors.Is(err, ErrAcceptorState) {
		t.Fatalf("acceptor ExportedSessionKey error = %v, want ErrAcceptorState", err)
	}
}

func TestSPNEGOClientCloseLifecycle(t *testing.T) {
	client, err := NewSPNEGOClient(testSessionSecurityClientConfig())
	if err != nil {
		t.Fatalf("NewSPNEGOClient: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := client.InitialToken(); !errors.Is(err, ErrSPNEGOState) {
		t.Fatalf("InitialToken error = %v, want ErrSPNEGOState", err)
	}
	if _, err := client.Sign([]byte("x")); !errors.Is(err, ErrSPNEGOState) {
		t.Fatalf("Sign error = %v, want ErrSPNEGOState", err)
	}
	if _, err := client.ExportedSessionKey(); !errors.Is(err, ErrSPNEGOState) {
		t.Fatalf("ExportedSessionKey error = %v, want ErrSPNEGOState", err)
	}
}
