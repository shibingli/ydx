package ntlm

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
)

// testKerberosOID is the Kerberos V5 GSS-API mechanism OID without its tag and
// length. | testKerberosOID 是不含标签与长度的 Kerberos V5 GSS-API 机制 OID。
var testKerberosOID = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}

// testAcceptorConfig returns a deterministic acceptor for the official client
// identity. | testAcceptorConfig 为官方客户端身份返回确定性接受方。
func testAcceptorConfig() AcceptorConfig {
	return AcceptorConfig{
		Password: func(domain, username string) (string, bool) {
			if domain == "Domain" && username == "User" {
				return "Password", true
			}
			return "", false
		},
		Domain:          "Domain",
		ServerName:      "Server",
		ServerChallenge: []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
	}
}

// testNewAcceptor builds an acceptor or fails the test. | testNewAcceptor 构建接受方，
// 失败时终止测试。
func testNewAcceptor(t *testing.T, config AcceptorConfig) *Acceptor {
	t.Helper()
	acceptor, err := NewAcceptor(config)
	if err != nil {
		t.Fatalf("NewAcceptor: %v", err)
	}
	return acceptor
}

// testNewSPNEGOClient builds a SPNEGO client using the official client config. |
// testNewSPNEGOClient 使用官方客户端配置构建 SPNEGO 客户端。
func testNewSPNEGOClient(t *testing.T) *SPNEGOClient {
	t.Helper()
	client, err := NewSPNEGOClient(clientConfig())
	if err != nil {
		t.Fatalf("NewSPNEGOClient: %v", err)
	}
	return client
}

// testSPNEGOClientFinal runs the initiator through the challenge and returns the
// client final token, its Type 3 message and the raw server challenge token. |
// testSPNEGOClientFinal 驱动发起方完成挑战阶段，返回客户端最终令牌、其 Type 3 消息与
// 原始服务端挑战令牌。
func testSPNEGOClientFinal(t *testing.T, acceptor *Acceptor, client *SPNEGOClient) (finalToken, type3, challengeToken []byte) {
	t.Helper()
	initial, err := client.InitialToken()
	if err != nil {
		t.Fatalf("InitialToken: %v", err)
	}
	challengeToken, err = acceptor.AcceptInitial(initial)
	if err != nil {
		t.Fatalf("AcceptInitial: %v", err)
	}
	parsedChallenge, err := ParseSPNEGOToken(challengeToken)
	if err != nil {
		t.Fatalf("ParseSPNEGOToken(challenge): %v", err)
	}
	if len(parsedChallenge.ResponseToken) == 0 {
		t.Fatalf("challenge token carries no responseToken")
	}
	finalToken, err = client.AcceptToken(challengeToken)
	if err != nil {
		t.Fatalf("client AcceptToken: %v", err)
	}
	parsedFinal, err := ParseSPNEGOToken(finalToken)
	if err != nil {
		t.Fatalf("ParseSPNEGOToken(final): %v", err)
	}
	return finalToken, parsedFinal.ResponseToken, challengeToken
}

// testSPNEGOExchange performs a complete successful SPNEGO exchange. |
// testSPNEGOExchange 执行完整的成功 SPNEGO 交换。
func testSPNEGOExchange(t *testing.T, config AcceptorConfig) (*Acceptor, *SPNEGOClient, *AcceptResult) {
	t.Helper()
	acceptor := testNewAcceptor(t, config)
	client := testNewSPNEGOClient(t)
	finalToken, _, _ := testSPNEGOClientFinal(t, acceptor, client)
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
	return acceptor, client, result
}

func TestNewAcceptorValidation(t *testing.T) {
	key := func(string, string) ([]byte, bool) { return make([]byte, md4Size), true }
	tests := []struct {
		name   string
		config AcceptorConfig
	}{
		{name: "no credentials", config: AcceptorConfig{Domain: "Domain"}},
		{name: "short server challenge", config: AcceptorConfig{
			ResponseKey:     key,
			Domain:          "Domain",
			ServerChallenge: []byte{1, 2, 3},
		}},
		{name: "empty target info", config: AcceptorConfig{ResponseKey: key}},
		{name: "flags without NTLM", config: AcceptorConfig{
			ResponseKey: key,
			Domain:      "Domain",
			Flags:       FlagUnicode,
		}},
		{name: "flags without Unicode", config: AcceptorConfig{
			ResponseKey: key,
			Domain:      "Domain",
			Flags:       FlagOEM | FlagNTLM,
		}},
		{name: "invalid target info", config: AcceptorConfig{
			ResponseKey: key,
			TargetInfo:  TargetInfo{{Type: AVFlags, Value: []byte{1, 2, 3}}},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewAcceptor(test.config); !errors.Is(err, ErrAcceptorConfig) {
				t.Fatalf("error = %v, want ErrAcceptorConfig", err)
			}
		})
	}
}

func TestAcceptorTargetInfo(t *testing.T) {
	config := testAcceptorConfig()
	config.Flags = baseAcceptorFlags
	config.RequireMIC = true
	config.TargetInfo = TargetInfo{
		{Type: AVNbDomainName, Value: encodeString("Ignored", true)},
		{Type: AVEndOfList},
	}
	acceptor := testNewAcceptor(t, config)
	if acceptor.targetName != "Domain" {
		t.Fatalf("target name = %q", acceptor.targetName)
	}
	client := testNewSPNEGOClient(t)
	initial, err := client.InitialToken()
	if err != nil {
		t.Fatalf("InitialToken: %v", err)
	}
	challengeToken, err := acceptor.AcceptInitial(initial)
	if err != nil {
		t.Fatalf("AcceptInitial: %v", err)
	}
	parsed, err := ParseSPNEGOToken(challengeToken)
	if err != nil {
		t.Fatalf("ParseSPNEGOToken: %v", err)
	}
	challenge, err := DecodeChallenge(parsed.ResponseToken)
	if err != nil {
		t.Fatalf("DecodeChallenge: %v", err)
	}
	if challenge.Flags != config.Flags {
		t.Fatalf("challenge flags = %#x, want %#x", challenge.Flags, config.Flags)
	}
	if challenge.ServerChallenge != [8]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef} {
		t.Fatalf("server challenge = %x", challenge.ServerChallenge)
	}
	domain, ok := challenge.TargetInfo.Get(AVNbDomainName)
	if !ok || !bytes.Equal(domain, encodeString("Ignored", true)) {
		t.Fatalf("domain AV pair = %x, %v", domain, ok)
	}
	computer, ok := challenge.TargetInfo.Get(AVNbComputerName)
	if !ok || !bytes.Equal(computer, encodeString("Server", true)) {
		t.Fatalf("computer name AV pair = %x, %v", computer, ok)
	}
	flags, ok := challenge.TargetInfo.Flags()
	if !ok || flags&AVFlagMICPresent == 0 {
		t.Fatalf("AV flags = %#x, %v", flags, ok)
	}
}

func TestAcceptorRawNTLMRoundTrip(t *testing.T) {
	config := testAcceptorConfig()
	config.AllowRawNTLM = true
	config.RequireMIC = true
	acceptor := testNewAcceptor(t, config)
	client := clientCreate(t, clientConfig())
	type1, err := client.Negotiate()
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	type2, err := acceptor.AcceptInitial(type1)
	if err != nil {
		t.Fatalf("AcceptInitial: %v", err)
	}
	if !bytes.HasPrefix(type2, []byte(Signature)) {
		t.Fatalf("raw AcceptInitial returned a non-NTLM token")
	}
	type3, err := client.Authenticate(type2)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	result, final, err := acceptor.AcceptFinal(type3)
	if err != nil {
		t.Fatalf("AcceptFinal: %v", err)
	}
	if final != nil {
		t.Fatalf("raw exchange returned a SPNEGO final token")
	}
	if result.SPNEGO {
		t.Fatalf("result.SPNEGO = true")
	}
	if result.Domain != "Domain" || result.Username != "User" {
		t.Fatalf("result identity = %q\\%q", result.Domain, result.Username)
	}
	if !result.MICVerified {
		t.Fatalf("Type 3 MIC was not verified")
	}
	if result.MechListMICVerified {
		t.Fatalf("raw exchange verified a mechListMIC")
	}
	if len(result.SessionBaseKey) != md4Size {
		t.Fatalf("SessionBaseKey length = %d", len(result.SessionBaseKey))
	}
	der := mustHex(t, mechListTypesDER)
	clientMIC, err := client.MechListMIC(der)
	if err != nil {
		t.Fatalf("client MechListMIC: %v", err)
	}
	acceptorMIC, err := ComputeMechListMIC(result.SessionBaseKey, der, result.Flags)
	if err != nil {
		t.Fatalf("ComputeMechListMIC: %v", err)
	}
	if !bytes.Equal(clientMIC, acceptorMIC) {
		t.Fatalf("client and acceptor session keys differ")
	}
	if acceptor.State() != SPNEGOStateCompleted {
		t.Fatalf("acceptor state = %s", acceptor.State())
	}
}

func TestAcceptorType3MIC(t *testing.T) {
	t.Run("required MIC missing", func(t *testing.T) {
		config := testAcceptorConfig()
		config.AllowRawNTLM = true
		config.RequireMIC = true
		acceptor := testNewAcceptor(t, config)
		client := clientCreate(t, clientConfig())
		type1, _ := client.Negotiate()
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
		if message.MIC == nil {
			t.Fatalf("client did not produce a MIC")
		}
		message.MIC = nil
		stripped, err := message.Encode()
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		if _, _, err := acceptor.AcceptFinal(stripped); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("error = %v, want ErrAuthentication", err)
		}
		if acceptor.State() != SPNEGOStateFailed {
			t.Fatalf("acceptor state = %s", acceptor.State())
		}
	})

	t.Run("SPNEGO MIC missing", func(t *testing.T) {
		config := testAcceptorConfig()
		config.RequireMIC = true
		acceptor := testNewAcceptor(t, config)
		client := testNewSPNEGOClient(t)
		final, _, _ := testSPNEGOClientFinal(t, acceptor, client)
		parsed, err := ParseSPNEGOToken(final)
		if err != nil {
			t.Fatalf("ParseSPNEGOToken: %v", err)
		}
		message, err := DecodeAuthenticate(parsed.ResponseToken)
		if err != nil {
			t.Fatalf("DecodeAuthenticate: %v", err)
		}
		if message.MIC == nil {
			t.Fatalf("client did not produce a MIC")
		}
		message.MIC = nil
		stripped, err := message.Encode()
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		withoutMIC, err := EncodeSPNEGOResponseWithMIC(stripped, parsed.MechListMIC)
		if err != nil {
			t.Fatalf("EncodeSPNEGOResponseWithMIC: %v", err)
		}
		if _, _, err := acceptor.AcceptFinal(withoutMIC); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("error = %v, want ErrAuthentication", err)
		}
	})

	t.Run("tampered MIC", func(t *testing.T) {
		config := testAcceptorConfig()
		config.RequireMIC = true
		acceptor := testNewAcceptor(t, config)
		client := testNewSPNEGOClient(t)
		final, type3, _ := testSPNEGOClientFinal(t, acceptor, client)
		parsed, err := ParseSPNEGOToken(final)
		if err != nil {
			t.Fatalf("ParseSPNEGOToken: %v", err)
		}
		message, err := DecodeAuthenticate(type3)
		if err != nil {
			t.Fatalf("DecodeAuthenticate: %v", err)
		}
		if len(message.MIC) != micSize {
			t.Fatalf("MIC length = %d", len(message.MIC))
		}
		message.MIC[0] ^= 0xff
		tampered, err := message.Encode()
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		token, err := EncodeSPNEGOResponseWithMIC(tampered, parsed.MechListMIC)
		if err != nil {
			t.Fatalf("EncodeSPNEGOResponseWithMIC: %v", err)
		}
		if _, _, err := acceptor.AcceptFinal(token); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("error = %v, want ErrAuthentication", err)
		}
	})
}

// testAcceptorRawType3 performs a raw NTLM negotiation and returns a Type 3
// message for the acceptor to verify. | testAcceptorRawType3 执行裸 NTLM 协商并返回
// 供接受方校验的 Type 3 消息。
func testAcceptorRawType3(t *testing.T, config AcceptorConfig) (*Acceptor, []byte) {
	t.Helper()
	config.AllowRawNTLM = true
	acceptor := testNewAcceptor(t, config)
	client := clientCreate(t, clientConfig())
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

func TestAcceptorType3Policy(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AuthenticateMessage)
	}{
		{
			name: "NTLM flag missing",
			mutate: func(message *AuthenticateMessage) {
				message.Flags &^= FlagNTLM | FlagNTLMOnly
			},
		},
		{
			name: "Unicode flag missing",
			mutate: func(message *AuthenticateMessage) {
				message.Flags = (message.Flags &^ FlagUnicode) | FlagOEM
			},
		},
		{
			name: "unoffered flag",
			mutate: func(message *AuthenticateMessage) {
				message.Flags |= FlagSign
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			acceptor, type3 := testAcceptorRawType3(t, testAcceptorConfig())
			message, err := DecodeAuthenticate(type3)
			if err != nil {
				t.Fatalf("DecodeAuthenticate: %v", err)
			}
			test.mutate(message)
			mutated, err := message.Encode()
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if _, _, err := acceptor.AcceptFinal(mutated); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("error = %v, want ErrAuthentication", err)
			}
		})
	}
}

func TestAcceptorNTLMv2StructureErrors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AuthenticateMessage)
	}{
		{
			name: "NT response short",
			mutate: func(message *AuthenticateMessage) {
				message.NTResponse = message.NTResponse[:20]
			},
		},
		{
			name: "temporary response type",
			mutate: func(message *AuthenticateMessage) {
				message.NTResponse[16] = 2
			},
		},
		{
			name: "temporary reserved field",
			mutate: func(message *AuthenticateMessage) {
				message.NTResponse[18] = 1
			},
		},
		{
			name: "LMv2 short",
			mutate: func(message *AuthenticateMessage) {
				message.LMResponse = message.LMResponse[:23]
			},
		},
		{
			name: "LMv2 client challenge mismatch",
			mutate: func(message *AuthenticateMessage) {
				message.LMResponse[16] ^= 1
			},
		},
		{
			name: "LMv2 proof mismatch",
			mutate: func(message *AuthenticateMessage) {
				message.LMResponse[0] ^= 1
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			acceptor, type3 := testAcceptorRawType3(t, testAcceptorConfig())
			message, err := DecodeAuthenticate(type3)
			if err != nil {
				t.Fatalf("DecodeAuthenticate: %v", err)
			}
			test.mutate(message)
			mutated, err := message.Encode()
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if _, _, err := acceptor.AcceptFinal(mutated); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("error = %v, want ErrAuthentication", err)
			}
		})
	}
}

func TestAcceptorFinalUnsupportedMechanism(t *testing.T) {
	acceptor := testNewAcceptor(t, testAcceptorConfig())
	client := testNewSPNEGOClient(t)
	_, type3, _ := testSPNEGOClientFinal(t, acceptor, client)
	token, err := EncodeSPNEGOToken(&SPNEGOToken{
		SupportedMech: testKerberosOID,
		ResponseToken: type3,
	}, false)
	if err != nil {
		t.Fatalf("EncodeSPNEGOToken: %v", err)
	}
	if _, _, err := acceptor.AcceptFinal(token); !errors.Is(err, ErrSPNEGO) {
		t.Fatalf("error = %v, want ErrSPNEGO", err)
	}
}

func TestAcceptorInitialType1Policy(t *testing.T) {
	encodeType1 := func(t *testing.T, flags NegotiateFlags) []byte {
		t.Helper()
		message := &NegotiateMessage{Flags: flags}
		encoded, err := message.Encode()
		if err != nil {
			t.Fatalf("NegotiateMessage.Encode: %v", err)
		}
		token, err := EncodeSPNEGONegotiateInit(encoded)
		if err != nil {
			t.Fatalf("EncodeSPNEGONegotiateInit: %v", err)
		}
		return token
	}
	tests := []struct {
		name  string
		flags NegotiateFlags
	}{
		{name: "NTLM missing", flags: FlagUnicode | FlagOEM | FlagVersion},
		{name: "Unicode missing", flags: FlagOEM | FlagNTLM | FlagVersion},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			acceptor := testNewAcceptor(t, testAcceptorConfig())
			if _, err := acceptor.AcceptInitial(encodeType1(t, test.flags)); !errors.Is(err, ErrMessage) {
				t.Fatalf("error = %v, want ErrMessage", err)
			}
			if acceptor.State() != SPNEGOStateFailed {
				t.Fatalf("acceptor state = %s", acceptor.State())
			}
		})
	}
}

func TestAcceptorRandomServerChallenge(t *testing.T) {
	config := testAcceptorConfig()
	config.ServerChallenge = nil
	acceptor := testNewAcceptor(t, config)
	client := testNewSPNEGOClient(t)
	initial, err := client.InitialToken()
	if err != nil {
		t.Fatalf("InitialToken: %v", err)
	}
	challengeToken, err := acceptor.AcceptInitial(initial)
	if err != nil {
		t.Fatalf("AcceptInitial: %v", err)
	}
	parsed, err := ParseSPNEGOToken(challengeToken)
	if err != nil {
		t.Fatalf("ParseSPNEGOToken: %v", err)
	}
	challenge, err := DecodeChallenge(parsed.ResponseToken)
	if err != nil {
		t.Fatalf("DecodeChallenge: %v", err)
	}
	var zero [8]byte
	if challenge.ServerChallenge == zero {
		t.Fatalf("random server challenge is all zero")
	}
}

func TestAcceptorMalformedInitial(t *testing.T) {
	tests := []struct {
		name   string
		config AcceptorConfig
		token  []byte
	}{
		{name: "malformed SPNEGO", config: testAcceptorConfig(), token: []byte{0x30, 0x01}},
		{
			name: "malformed SPNEGO with raw enabled",
			config: func() AcceptorConfig {
				config := testAcceptorConfig()
				config.AllowRawNTLM = true
				return config
			}(),
			token: []byte{0x30, 0x01},
		},
		{
			name: "truncated raw NTLM",
			config: func() AcceptorConfig {
				config := testAcceptorConfig()
				config.AllowRawNTLM = true
				return config
			}(),
			token: []byte(Signature),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			acceptor := testNewAcceptor(t, test.config)
			if _, err := acceptor.AcceptInitial(test.token); err == nil {
				t.Fatalf("AcceptInitial accepted a malformed token")
			}
			if acceptor.State() != SPNEGOStateFailed {
				t.Fatalf("acceptor state = %s", acceptor.State())
			}
		})
	}
}

func TestAcceptorMechListMIC(t *testing.T) {
	t.Run("tampered client MIC", func(t *testing.T) {
		acceptor := testNewAcceptor(t, testAcceptorConfig())
		client := testNewSPNEGOClient(t)
		final, _, _ := testSPNEGOClientFinal(t, acceptor, client)
		parsed, err := ParseSPNEGOToken(final)
		if err != nil {
			t.Fatalf("ParseSPNEGOToken: %v", err)
		}
		if !parsed.HasMechListMIC || len(parsed.MechListMIC) != MechListMICSize {
			t.Fatalf("client mechListMIC = %x", parsed.MechListMIC)
		}
		parsed.MechListMIC[0] ^= 0xff
		tampered, err := EncodeSPNEGOToken(parsed, false)
		if err != nil {
			t.Fatalf("EncodeSPNEGOToken: %v", err)
		}
		if _, _, err := acceptor.AcceptFinal(tampered); !errors.Is(err, ErrMechListMIC) {
			t.Fatalf("error = %v, want ErrMechListMIC", err)
		}
	})

	t.Run("required MIC missing", func(t *testing.T) {
		config := testAcceptorConfig()
		config.RequireMechListMIC = true
		acceptor := testNewAcceptor(t, config)
		client := testNewSPNEGOClient(t)
		final, type3, _ := testSPNEGOClientFinal(t, acceptor, client)
		parsed, err := ParseSPNEGOToken(final)
		if err != nil {
			t.Fatalf("ParseSPNEGOToken: %v", err)
		}
		if !parsed.HasMechListMIC {
			t.Fatalf("client did not send a mechListMIC")
		}
		withoutMIC, err := EncodeSPNEGOResponse(type3)
		if err != nil {
			t.Fatalf("EncodeSPNEGOResponse: %v", err)
		}
		if _, _, err := acceptor.AcceptFinal(withoutMIC); !errors.Is(err, ErrMechListMIC) {
			t.Fatalf("error = %v, want ErrMechListMIC", err)
		}
	})

	t.Run("Type 3 MIC implies mechListMIC", func(t *testing.T) {
		config := testAcceptorConfig()
		config.RequireMIC = true
		acceptor := testNewAcceptor(t, config)
		client := testNewSPNEGOClient(t)
		final, type3, _ := testSPNEGOClientFinal(t, acceptor, client)
		parsed, err := ParseSPNEGOToken(final)
		if err != nil {
			t.Fatalf("ParseSPNEGOToken: %v", err)
		}
		if !parsed.HasMechListMIC {
			t.Fatalf("client did not send a mechListMIC")
		}
		withoutMIC, err := EncodeSPNEGOResponse(type3)
		if err != nil {
			t.Fatalf("EncodeSPNEGOResponse: %v", err)
		}
		if _, _, err := acceptor.AcceptFinal(withoutMIC); !errors.Is(err, ErrMechListMIC) {
			t.Fatalf("error = %v, want ErrMechListMIC", err)
		}
	})
}

func TestAcceptorWrongCredentials(t *testing.T) {
	tests := []struct {
		name   string
		config func() AcceptorConfig
	}{
		{
			name: "wrong password",
			config: func() AcceptorConfig {
				config := testAcceptorConfig()
				config.Password = func(string, string) (string, bool) {
					return "Wrong-Password-For-Test", true
				}
				return config
			},
		},
		{
			name: "unknown password",
			config: func() AcceptorConfig {
				config := testAcceptorConfig()
				config.Password = func(string, string) (string, bool) { return "", false }
				return config
			},
		},
		{
			name: "response key not found",
			config: func() AcceptorConfig {
				config := testAcceptorConfig()
				config.Password = nil
				config.ResponseKey = func(string, string) ([]byte, bool) { return nil, false }
				return config
			},
		},
		{
			name: "response key wrong length",
			config: func() AcceptorConfig {
				config := testAcceptorConfig()
				config.Password = nil
				config.ResponseKey = func(string, string) ([]byte, bool) { return []byte{1, 2, 3}, true }
				return config
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			acceptor := testNewAcceptor(t, test.config())
			client := testNewSPNEGOClient(t)
			final, _, _ := testSPNEGOClientFinal(t, acceptor, client)
			result, token, err := acceptor.AcceptFinal(final)
			if !errors.Is(err, ErrAuthentication) {
				t.Fatalf("error = %v, want ErrAuthentication", err)
			}
			if result != nil || token != nil {
				t.Fatalf("failure returned result or token")
			}
			if strings.Contains(err.Error(), "Wrong-Password-For-Test") {
				t.Fatalf("error leaks the password: %v", err)
			}
			if acceptor.State() != SPNEGOStateFailed {
				t.Fatalf("acceptor state = %s", acceptor.State())
			}
		})
	}
}

func TestAcceptorResponseKeyCallback(t *testing.T) {
	var gotDomain, gotUsername string
	config := testAcceptorConfig()
	config.Password = nil
	config.ResponseKey = func(domain, username string) ([]byte, bool) {
		gotDomain = domain
		gotUsername = username
		return NTLMv2Hash("Password", username, domain), true
	}
	_, client, result := testSPNEGOExchange(t, config)
	if gotDomain != "Domain" || gotUsername != "User" {
		t.Fatalf("callback identity = %q\\%q", gotDomain, gotUsername)
	}
	if result.Username != "User" || result.Domain != "Domain" {
		t.Fatalf("result identity = %q\\%q", result.Domain, result.Username)
	}
	if client.State() != SPNEGOStateCompleted {
		t.Fatalf("client state = %s", client.State())
	}
	if len(result.SessionBaseKey) != md4Size {
		t.Fatalf("SessionBaseKey length = %d", len(result.SessionBaseKey))
	}
}

func TestAcceptorInitialValidation(t *testing.T) {
	makeInit := func(t *testing.T, token *SPNEGOToken) []byte {
		t.Helper()
		encoded, err := EncodeSPNEGOToken(token, true)
		if err != nil {
			t.Fatalf("EncodeSPNEGOToken: %v", err)
		}
		return encoded
	}
	client := clientCreate(t, clientConfig())
	type1, err := client.Negotiate()
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	tests := []struct {
		name    string
		config  AcceptorConfig
		token   []byte
		wantErr error
	}{
		{
			name:    "unsupported mechanism",
			config:  testAcceptorConfig(),
			token:   makeInit(t, &SPNEGOToken{MechTypes: [][]byte{testKerberosOID}, MechToken: type1}),
			wantErr: ErrSPNEGO,
		},
		{
			name:    "no mech token",
			config:  testAcceptorConfig(),
			token:   makeInit(t, &SPNEGOToken{MechTypes: [][]byte{ntlmMechOID}}),
			wantErr: ErrSPNEGO,
		},
		{
			name:   "mechListMIC before challenge",
			config: testAcceptorConfig(),
			token: makeInit(t, &SPNEGOToken{
				MechTypes:      [][]byte{ntlmMechOID},
				MechToken:      type1,
				MechListMIC:    make([]byte, micSize),
				HasMechListMIC: true,
			}),
			wantErr: ErrMechListMIC,
		},
		{
			name: "raw NTLM disabled",
			config: func() AcceptorConfig {
				config := testAcceptorConfig()
				config.AllowRawNTLM = false
				return config
			}(),
			token:   type1,
			wantErr: ErrSPNEGO,
		},
		{
			name: "raw NTLM requires mechListMIC",
			config: func() AcceptorConfig {
				config := testAcceptorConfig()
				config.AllowRawNTLM = true
				config.RequireMechListMIC = true
				return config
			}(),
			token:   type1,
			wantErr: ErrMechListMIC,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			acceptor := testNewAcceptor(t, test.config)
			token, err := acceptor.AcceptInitial(test.token)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
			if token != nil {
				t.Fatalf("failure returned a token")
			}
			if acceptor.State() != SPNEGOStateFailed {
				t.Fatalf("acceptor state = %s", acceptor.State())
			}
		})
	}
}

func TestAcceptorStateMachine(t *testing.T) {
	acceptor := testNewAcceptor(t, testAcceptorConfig())
	if _, _, err := acceptor.AcceptFinal(nil); !errors.Is(err, ErrAcceptorState) {
		t.Fatalf("AcceptFinal before AcceptInitial error = %v", err)
	}
	client := testNewSPNEGOClient(t)
	initial, err := client.InitialToken()
	if err != nil {
		t.Fatalf("InitialToken: %v", err)
	}
	challengeToken, err := acceptor.AcceptInitial(initial)
	if err != nil {
		t.Fatalf("AcceptInitial: %v", err)
	}
	if _, err := acceptor.AcceptInitial(initial); !errors.Is(err, ErrAcceptorState) {
		t.Fatalf("second AcceptInitial error = %v", err)
	}
	final, _, err := func() ([]byte, []byte, error) {
		final, err := client.AcceptToken(challengeToken)
		parsed, parseErr := ParseSPNEGOToken(final)
		if parseErr != nil {
			return nil, nil, parseErr
		}
		return final, parsed.ResponseToken, err
	}()
	if err != nil {
		t.Fatalf("client AcceptToken: %v", err)
	}
	result, _, err := acceptor.AcceptFinal(final)
	if err != nil {
		t.Fatalf("AcceptFinal: %v", err)
	}
	if result == nil {
		t.Fatalf("AcceptFinal returned no result")
	}
	if _, _, err := acceptor.AcceptFinal(final); !errors.Is(err, ErrAcceptorState) {
		t.Fatalf("second AcceptFinal error = %v", err)
	}
	if _, err := acceptor.AcceptInitial(initial); !errors.Is(err, ErrAcceptorState) {
		t.Fatalf("AcceptInitial after completion error = %v", err)
	}
}

func TestAcceptorFinalNegState(t *testing.T) {
	tests := []struct {
		name    string
		token   func(t *testing.T, type3 []byte) []byte
		wantErr error
	}{
		{
			name: "no response token",
			token: func(t *testing.T, _ []byte) []byte {
				encoded, err := EncodeSPNEGOToken(&SPNEGOToken{
					HasNegState:   true,
					NegState:      NegStateAcceptIncomplete,
					SupportedMech: ntlmMechOID,
				}, false)
				if err != nil {
					t.Fatalf("EncodeSPNEGOToken: %v", err)
				}
				return encoded
			},
			wantErr: ErrSPNEGO,
		},
		{
			name: "client rejects",
			token: func(t *testing.T, type3 []byte) []byte {
				encoded, err := EncodeSPNEGOToken(&SPNEGOToken{
					HasNegState:   true,
					NegState:      NegStateReject,
					SupportedMech: ntlmMechOID,
					ResponseToken: type3,
				}, false)
				if err != nil {
					t.Fatalf("EncodeSPNEGOToken: %v", err)
				}
				return encoded
			},
			wantErr: ErrSPNEGOState,
		},
		{
			name: "client accepts completed early",
			token: func(t *testing.T, type3 []byte) []byte {
				encoded, err := EncodeSPNEGOToken(&SPNEGOToken{
					HasNegState:   true,
					NegState:      NegStateAcceptCompleted,
					SupportedMech: ntlmMechOID,
					ResponseToken: type3,
				}, false)
				if err != nil {
					t.Fatalf("EncodeSPNEGOToken: %v", err)
				}
				return encoded
			},
			wantErr: ErrSPNEGOState,
		},
		{
			name: "client requests MIC after final",
			token: func(t *testing.T, type3 []byte) []byte {
				encoded, err := EncodeSPNEGOToken(&SPNEGOToken{
					HasNegState:   true,
					NegState:      NegStateRequestMIC,
					SupportedMech: ntlmMechOID,
					ResponseToken: type3,
				}, false)
				if err != nil {
					t.Fatalf("EncodeSPNEGOToken: %v", err)
				}
				return encoded
			},
			wantErr: ErrSPNEGOState,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			acceptor := testNewAcceptor(t, testAcceptorConfig())
			client := testNewSPNEGOClient(t)
			_, type3, _ := testSPNEGOClientFinal(t, acceptor, client)
			if _, _, err := acceptor.AcceptFinal(test.token(t, type3)); !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestAcceptorRejectsTamperedTargetInfo(t *testing.T) {
	config := testAcceptorConfig()
	config.AllowRawNTLM = true
	acceptor := testNewAcceptor(t, config)
	client := clientCreate(t, clientConfig())
	type1, _ := client.Negotiate()
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
	nt := append([]byte(nil), message.NTResponse...)
	temp := nt[16:]
	// Corrupt the first AV pair length so the echoed target info no longer
	// parses. | 破坏首个 AV 对长度，使回显的目标信息无法解析。
	if len(temp) < 32 {
		t.Fatalf("temporary structure is %d bytes", len(temp))
	}
	temp[31] = 0xff
	message.NTResponse = nt
	tampered, err := message.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, _, err := acceptor.AcceptFinal(tampered); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("error = %v, want ErrAuthentication", err)
	}
}

func TestAcceptorChallengeTargetInfoRequired(t *testing.T) {
	config := testAcceptorConfig()
	config.Domain = ""
	config.ServerName = ""
	if _, err := NewAcceptor(config); !errors.Is(err, ErrAcceptorConfig) {
		t.Fatalf("error = %v, want ErrAcceptorConfig", err)
	}
	config.TargetInfo = TargetInfo{
		{Type: AVNbDomainName, Value: encodeString("Domain", true)},
		{Type: AVEndOfList},
	}
	if _, err := NewAcceptor(config); err != nil {
		t.Fatalf("NewAcceptor: %v", err)
	}
}

func TestAcceptorConcurrentExchanges(t *testing.T) {
	const count = 8
	var wg sync.WaitGroup
	errorsCh := make(chan error, count)
	for index := 0; index < count; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			acceptor, err := NewAcceptor(testAcceptorConfig())
			if err != nil {
				errorsCh <- err
				return
			}
			client, err := NewSPNEGOClient(clientConfig())
			if err != nil {
				errorsCh <- err
				return
			}
			initial, err := client.InitialToken()
			if err != nil {
				errorsCh <- err
				return
			}
			challenge, err := acceptor.AcceptInitial(initial)
			if err != nil {
				errorsCh <- err
				return
			}
			final, err := client.AcceptToken(challenge)
			if err != nil {
				errorsCh <- err
				return
			}
			result, serverFinal, err := acceptor.AcceptFinal(final)
			if err != nil {
				errorsCh <- err
				return
			}
			if result.Username != "User" {
				errorsCh <- errors.New("unexpected user")
				return
			}
			if serverFinal == nil {
				errorsCh <- errors.New("missing server final token")
				return
			}
			if _, err := client.AcceptToken(serverFinal); err != nil {
				errorsCh <- err
				return
			}
		}()
	}
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Fatalf("concurrent exchange: %v", err)
	}
}

func TestAcceptorConcurrentInitialCalls(t *testing.T) {
	acceptor := testNewAcceptor(t, testAcceptorConfig())
	first := testNewSPNEGOClient(t)
	second := testNewSPNEGOClient(t)
	firstToken, err := first.InitialToken()
	if err != nil {
		t.Fatalf("first InitialToken: %v", err)
	}
	secondToken, err := second.InitialToken()
	if err != nil {
		t.Fatalf("second InitialToken: %v", err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, token := range [][]byte{firstToken, secondToken} {
		wg.Add(1)
		go func(token []byte) {
			defer wg.Done()
			response, err := acceptor.AcceptInitial(token)
			if err == nil && response == nil {
				err = errors.New("nil response")
			}
			results <- err
		}(token)
	}
	wg.Wait()
	close(results)
	var succeeded, rejected int
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrAcceptorState):
			rejected++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("succeeded = %d, rejected = %d", succeeded, rejected)
	}
}
