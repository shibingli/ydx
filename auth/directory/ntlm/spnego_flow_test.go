package ntlm

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestSPNEGOClientAcceptorRoundTrip(t *testing.T) {
	acceptor := testNewAcceptor(t, testAcceptorConfig())
	client := testNewSPNEGOClient(t)
	if client.State() != SPNEGOStateInitial {
		t.Fatalf("initial state = %s", client.State())
	}
	initial, err := client.InitialToken()
	if err != nil {
		t.Fatalf("InitialToken: %v", err)
	}
	parsedInitial, err := ParseSPNEGOToken(initial)
	if err != nil {
		t.Fatalf("ParseSPNEGOToken(initial): %v", err)
	}
	if len(parsedInitial.MechTypes) != 1 || !bytes.Equal(parsedInitial.MechTypes[0], ntlmMechOID) {
		t.Fatalf("initial mechTypes = %x", parsedInitial.MechTypes)
	}
	if len(parsedInitial.MechToken) == 0 {
		t.Fatalf("initial token carries no mechToken")
	}
	challengeToken, err := acceptor.AcceptInitial(initial)
	if err != nil {
		t.Fatalf("AcceptInitial: %v", err)
	}
	parsedChallenge, err := ParseSPNEGOToken(challengeToken)
	if err != nil {
		t.Fatalf("ParseSPNEGOToken(challenge): %v", err)
	}
	if !parsedChallenge.HasNegState || parsedChallenge.NegState != NegStateAcceptIncomplete {
		t.Fatalf("challenge negState = %v, %v", parsedChallenge.NegState, parsedChallenge.HasNegState)
	}
	if !bytes.Equal(parsedChallenge.SupportedMech, ntlmMechOID) {
		t.Fatalf("challenge supportedMech = %x", parsedChallenge.SupportedMech)
	}
	finalToken, err := client.AcceptToken(challengeToken)
	if err != nil {
		t.Fatalf("client AcceptToken: %v", err)
	}
	parsedFinal, err := ParseSPNEGOToken(finalToken)
	if err != nil {
		t.Fatalf("ParseSPNEGOToken(final): %v", err)
	}
	if len(parsedFinal.ResponseToken) == 0 {
		t.Fatalf("final token carries no responseToken")
	}
	if !parsedFinal.HasMechListMIC || len(parsedFinal.MechListMIC) != MechListMICSize {
		t.Fatalf("final mechListMIC = %x", parsedFinal.MechListMIC)
	}
	result, serverFinal, err := acceptor.AcceptFinal(finalToken)
	if err != nil {
		t.Fatalf("AcceptFinal: %v", err)
	}
	if result.Username != "User" || result.Domain != "Domain" {
		t.Fatalf("result identity = %q\\%q", result.Domain, result.Username)
	}
	if !result.SPNEGO {
		t.Fatalf("result.SPNEGO = false")
	}
	if result.MICVerified {
		t.Fatalf("unexpected Type 3 MIC verification")
	}
	if !result.MechListMICVerified {
		t.Fatalf("client mechListMIC was not verified")
	}
	if len(result.SessionBaseKey) != md4Size {
		t.Fatalf("SessionBaseKey length = %d", len(result.SessionBaseKey))
	}
	parsedServerFinal, err := ParseSPNEGOToken(serverFinal)
	if err != nil {
		t.Fatalf("ParseSPNEGOToken(server final): %v", err)
	}
	if !parsedServerFinal.HasNegState || parsedServerFinal.NegState != NegStateAcceptCompleted {
		t.Fatalf("server final negState = %v, %v", parsedServerFinal.NegState, parsedServerFinal.HasNegState)
	}
	if _, err := client.AcceptToken(serverFinal); err != nil {
		t.Fatalf("client AcceptToken(server final): %v", err)
	}
	if client.State() != SPNEGOStateCompleted {
		t.Fatalf("client state = %s", client.State())
	}
	if acceptor.State() != SPNEGOStateCompleted {
		t.Fatalf("acceptor state = %s", acceptor.State())
	}
	if _, err := client.NegotiatedFlags(); err != nil {
		t.Fatalf("NegotiatedFlags: %v", err)
	}
}

func TestSPNEGOClientAcceptorRequireMICAndMechListMIC(t *testing.T) {
	config := testAcceptorConfig()
	config.RequireMIC = true
	config.RequireMechListMIC = true
	config.SendMechListMIC = true
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
	parsedChallenge, err := ParseSPNEGOToken(challengeToken)
	if err != nil {
		t.Fatalf("ParseSPNEGOToken(challenge): %v", err)
	}
	if !parsedChallenge.HasNegState || parsedChallenge.NegState != NegStateRequestMIC {
		t.Fatalf("challenge negState = %v, %v", parsedChallenge.NegState, parsedChallenge.HasNegState)
	}
	finalToken, err := client.AcceptToken(challengeToken)
	if err != nil {
		t.Fatalf("client AcceptToken: %v", err)
	}
	parsedFinal, err := ParseSPNEGOToken(finalToken)
	if err != nil {
		t.Fatalf("ParseSPNEGOToken(final): %v", err)
	}
	if !parsedFinal.HasMechListMIC || len(parsedFinal.MechListMIC) != MechListMICSize {
		t.Fatalf("client mechListMIC = %x", parsedFinal.MechListMIC)
	}
	result, serverFinal, err := acceptor.AcceptFinal(finalToken)
	if err != nil {
		t.Fatalf("AcceptFinal: %v", err)
	}
	if !result.MICVerified {
		t.Fatalf("Type 3 MIC was not verified")
	}
	if !result.MechListMICVerified {
		t.Fatalf("client mechListMIC was not verified")
	}
	parsedServerFinal, err := ParseSPNEGOToken(serverFinal)
	if err != nil {
		t.Fatalf("ParseSPNEGOToken(server final): %v", err)
	}
	if !parsedServerFinal.HasNegState || parsedServerFinal.NegState != NegStateAcceptCompleted {
		t.Fatalf("server final negState = %v, %v", parsedServerFinal.NegState, parsedServerFinal.HasNegState)
	}
	if !parsedServerFinal.HasMechListMIC || len(parsedServerFinal.MechListMIC) != MechListMICSize {
		t.Fatalf("server mechListMIC = %x", parsedServerFinal.MechListMIC)
	}
	if _, err := client.AcceptToken(serverFinal); err != nil {
		t.Fatalf("client AcceptToken(server final): %v", err)
	}
	if client.State() != SPNEGOStateCompleted {
		t.Fatalf("client state = %s", client.State())
	}
}

func TestSPNEGOClientServerNegState(t *testing.T) {
	makeAcceptorClientChallenge := func(t *testing.T, client *SPNEGOClient) []byte {
		t.Helper()
		acceptor := testNewAcceptor(t, testAcceptorConfig())
		initial, err := client.InitialToken()
		if err != nil {
			t.Fatalf("InitialToken: %v", err)
		}
		challenge, err := acceptor.AcceptInitial(initial)
		if err != nil {
			t.Fatalf("AcceptInitial: %v", err)
		}
		return challenge
	}
	tests := []struct {
		name    string
		token   func(t *testing.T, challenge []byte) []byte
		wantErr error
	}{
		{
			name: "reject",
			token: func(t *testing.T, challenge []byte) []byte {
				parsed, err := ParseSPNEGOToken(challenge)
				if err != nil {
					t.Fatalf("ParseSPNEGOToken: %v", err)
				}
				encoded, err := EncodeSPNEGOToken(&SPNEGOToken{
					HasNegState:   true,
					NegState:      NegStateReject,
					SupportedMech: ntlmMechOID,
					ResponseToken: parsed.ResponseToken,
				}, false)
				if err != nil {
					t.Fatalf("EncodeSPNEGOToken: %v", err)
				}
				return encoded
			},
			wantErr: ErrSPNEGOState,
		},
		{
			name: "accept completed before authentication",
			token: func(t *testing.T, challenge []byte) []byte {
				parsed, err := ParseSPNEGOToken(challenge)
				if err != nil {
					t.Fatalf("ParseSPNEGOToken: %v", err)
				}
				encoded, err := EncodeSPNEGOToken(&SPNEGOToken{
					HasNegState:   true,
					NegState:      NegStateAcceptCompleted,
					SupportedMech: ntlmMechOID,
					ResponseToken: parsed.ResponseToken,
				}, false)
				if err != nil {
					t.Fatalf("EncodeSPNEGOToken: %v", err)
				}
				return encoded
			},
			wantErr: ErrSPNEGOState,
		},
		{
			name: "unsupported mechanism",
			token: func(t *testing.T, challenge []byte) []byte {
				parsed, err := ParseSPNEGOToken(challenge)
				if err != nil {
					t.Fatalf("ParseSPNEGOToken: %v", err)
				}
				encoded, err := EncodeSPNEGOToken(&SPNEGOToken{
					HasNegState:   true,
					NegState:      NegStateAcceptIncomplete,
					SupportedMech: testKerberosOID,
					ResponseToken: parsed.ResponseToken,
				}, false)
				if err != nil {
					t.Fatalf("EncodeSPNEGOToken: %v", err)
				}
				return encoded
			},
			wantErr: ErrSPNEGO,
		},
		{
			name: "missing challenge",
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
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := testNewSPNEGOClient(t)
			challenge := makeAcceptorClientChallenge(t, client)
			token := test.token(t, challenge)
			if _, err := client.AcceptToken(token); !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
			if client.State() != SPNEGOStateFailed {
				t.Fatalf("client state = %s", client.State())
			}
		})
	}
}

func TestSPNEGOClientServerMechListMIC(t *testing.T) {
	der := mustHex(t, mechListTypesDER)
	acceptor := testNewAcceptor(t, testAcceptorConfig())
	client := testNewSPNEGOClient(t)
	initial, err := client.InitialToken()
	if err != nil {
		t.Fatalf("InitialToken: %v", err)
	}
	challengeToken, err := acceptor.AcceptInitial(initial)
	if err != nil {
		t.Fatalf("AcceptInitial: %v", err)
	}
	parsedChallenge, err := ParseSPNEGOToken(challengeToken)
	if err != nil {
		t.Fatalf("ParseSPNEGOToken: %v", err)
	}
	targetInfo, err := acceptor.targetInfo.withoutEndOfList().Encode()
	if err != nil {
		t.Fatalf("TargetInfo.Encode: %v", err)
	}
	response, err := ComputeNTLMv2Response(
		NTLMv2Hash("Password", "User", "Domain"),
		acceptor.serverChallenge[:],
		clientFixedChallenge(),
		time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC),
		targetInfo,
	)
	if err != nil {
		t.Fatalf("ComputeNTLMv2Response: %v", err)
	}
	serverMIC, err := ComputeMechListMIC(response.SessionBaseKey, der, 0)
	if err != nil {
		t.Fatalf("ComputeMechListMIC: %v", err)
	}
	token, err := EncodeSPNEGOToken(&SPNEGOToken{
		HasNegState:    true,
		NegState:       NegStateAcceptIncomplete,
		SupportedMech:  ntlmMechOID,
		ResponseToken:  parsedChallenge.ResponseToken,
		MechListMIC:    serverMIC,
		HasMechListMIC: true,
	}, false)
	if err != nil {
		t.Fatalf("EncodeSPNEGOToken: %v", err)
	}
	finalToken, err := client.AcceptToken(token)
	if err != nil {
		t.Fatalf("client AcceptToken: %v", err)
	}
	result, _, err := acceptor.AcceptFinal(finalToken)
	if err != nil {
		t.Fatalf("AcceptFinal: %v", err)
	}
	if result.Username != "User" {
		t.Fatalf("result user = %q", result.Username)
	}

	t.Run("tampered server MIC", func(t *testing.T) {
		acceptor := testNewAcceptor(t, testAcceptorConfig())
		client := testNewSPNEGOClient(t)
		initial, err := client.InitialToken()
		if err != nil {
			t.Fatalf("InitialToken: %v", err)
		}
		challengeToken, err := acceptor.AcceptInitial(initial)
		if err != nil {
			t.Fatalf("AcceptInitial: %v", err)
		}
		parsedChallenge, err := ParseSPNEGOToken(challengeToken)
		if err != nil {
			t.Fatalf("ParseSPNEGOToken: %v", err)
		}
		badMIC := append([]byte(nil), serverMIC...)
		badMIC[0] ^= 0xff
		token, err := EncodeSPNEGOToken(&SPNEGOToken{
			HasNegState:    true,
			NegState:       NegStateAcceptIncomplete,
			SupportedMech:  ntlmMechOID,
			ResponseToken:  parsedChallenge.ResponseToken,
			MechListMIC:    badMIC,
			HasMechListMIC: true,
		}, false)
		if err != nil {
			t.Fatalf("EncodeSPNEGOToken: %v", err)
		}
		if _, err := client.AcceptToken(token); !errors.Is(err, ErrMechListMIC) {
			t.Fatalf("error = %v, want ErrMechListMIC", err)
		}
		if client.State() != SPNEGOStateFailed {
			t.Fatalf("client state = %s", client.State())
		}
	})
}

func TestSPNEGOClientServerFinalErrors(t *testing.T) {
	config := testAcceptorConfig()
	config.SendMechListMIC = true
	tests := []struct {
		name    string
		token   func(t *testing.T) []byte
		wantErr error
	}{
		{
			name: "accept incomplete",
			token: func(t *testing.T) []byte {
				return mustEncodeNegState(t, NegStateAcceptIncomplete, nil)
			},
			wantErr: ErrSPNEGOState,
		},
		{
			name: "reject",
			token: func(t *testing.T) []byte {
				return mustEncodeNegState(t, NegStateReject, nil)
			},
			wantErr: ErrSPNEGOState,
		},
		{
			name: "request MIC after final",
			token: func(t *testing.T) []byte {
				return mustEncodeNegState(t, NegStateRequestMIC, nil)
			},
			wantErr: ErrSPNEGOState,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			acceptor := testNewAcceptor(t, config)
			client := testNewSPNEGOClient(t)
			finalToken, _, _ := testSPNEGOClientFinal(t, acceptor, client)
			if _, _, err := acceptor.AcceptFinal(finalToken); err != nil {
				t.Fatalf("AcceptFinal: %v", err)
			}
			if _, err := client.AcceptToken(test.token(t)); !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
			if client.State() != SPNEGOStateFailed {
				t.Fatalf("client state = %s", client.State())
			}
		})
	}

	t.Run("tampered final MIC", func(t *testing.T) {
		acceptor := testNewAcceptor(t, config)
		client := testNewSPNEGOClient(t)
		finalToken, _, _ := testSPNEGOClientFinal(t, acceptor, client)
		_, serverFinal, err := acceptor.AcceptFinal(finalToken)
		if err != nil {
			t.Fatalf("AcceptFinal: %v", err)
		}
		parsed, err := ParseSPNEGOToken(serverFinal)
		if err != nil {
			t.Fatalf("ParseSPNEGOToken: %v", err)
		}
		if !parsed.HasMechListMIC || len(parsed.MechListMIC) != MechListMICSize {
			t.Fatalf("server mechListMIC = %x", parsed.MechListMIC)
		}
		parsed.MechListMIC[0] ^= 0xff
		tampered, err := EncodeSPNEGOToken(parsed, false)
		if err != nil {
			t.Fatalf("EncodeSPNEGOToken: %v", err)
		}
		if _, err := client.AcceptToken(tampered); !errors.Is(err, ErrMechListMIC) {
			t.Fatalf("error = %v, want ErrMechListMIC", err)
		}
		if client.State() != SPNEGOStateFailed {
			t.Fatalf("client state = %s", client.State())
		}
	})
}

func TestSPNEGOClientStateMachine(t *testing.T) {
	client := testNewSPNEGOClient(t)
	if _, err := client.AcceptToken(nil); !errors.Is(err, ErrSPNEGOState) {
		t.Fatalf("AcceptToken before InitialToken error = %v", err)
	}
	if err := client.Complete(); !errors.Is(err, ErrSPNEGOState) {
		t.Fatalf("Complete before InitialToken error = %v", err)
	}
	initial, err := client.InitialToken()
	if err != nil {
		t.Fatalf("InitialToken: %v", err)
	}
	if _, err := client.InitialToken(); !errors.Is(err, ErrSPNEGOState) {
		t.Fatalf("second InitialToken error = %v", err)
	}
	if err := client.Complete(); !errors.Is(err, ErrSPNEGOState) {
		t.Fatalf("Complete before final token error = %v", err)
	}
	acceptor := testNewAcceptor(t, testAcceptorConfig())
	challenge, err := acceptor.AcceptInitial(initial)
	if err != nil {
		t.Fatalf("AcceptInitial: %v", err)
	}
	if _, err := client.AcceptToken(challenge); err != nil {
		t.Fatalf("AcceptToken: %v", err)
	}
	if err := client.Complete(); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if client.State() != SPNEGOStateCompleted {
		t.Fatalf("client state = %s", client.State())
	}
	if _, err := client.AcceptToken(nil); !errors.Is(err, ErrSPNEGOState) {
		t.Fatalf("AcceptToken after completion error = %v", err)
	}
	if err := client.Complete(); !errors.Is(err, ErrSPNEGOState) {
		t.Fatalf("second Complete error = %v", err)
	}
	if _, err := client.NegotiatedFlags(); err != nil {
		t.Fatalf("NegotiatedFlags: %v", err)
	}
}

func TestSPNEGOClientRequestMICLegacyUnavailable(t *testing.T) {
	config := testAcceptorConfig()
	config.RequireMechListMIC = true
	config.Flags = baseAcceptorFlags &^ FlagExtendedSessionSecurity
	acceptor := testNewAcceptor(t, config)
	clientConfig := clientConfig()
	clientConfig.ResponseMode = ResponseNTLMv1
	clientConfig.AllowLegacy = true
	client, err := NewSPNEGOClient(clientConfig)
	if err != nil {
		t.Fatalf("NewSPNEGOClient: %v", err)
	}
	initial, err := client.InitialToken()
	if err != nil {
		t.Fatalf("InitialToken: %v", err)
	}
	challenge, err := acceptor.AcceptInitial(initial)
	if err != nil {
		t.Fatalf("AcceptInitial: %v", err)
	}
	parsed, err := ParseSPNEGOToken(challenge)
	if err != nil {
		t.Fatalf("ParseSPNEGOToken: %v", err)
	}
	if !parsed.HasNegState || parsed.NegState != NegStateRequestMIC {
		t.Fatalf("challenge negState = %v, %v", parsed.NegState, parsed.HasNegState)
	}
	if _, err := client.AcceptToken(challenge); !errors.Is(err, ErrMechListMIC) {
		t.Fatalf("error = %v, want ErrMechListMIC", err)
	}
	if client.State() != SPNEGOStateFailed {
		t.Fatalf("client state = %s", client.State())
	}
}

func TestSPNEGOStateString(t *testing.T) {
	tests := []struct {
		state SPNEGOState
		want  string
	}{
		{state: SPNEGOStateInitial, want: "initial"},
		{state: SPNEGOStateInProgress, want: "in-progress"},
		{state: SPNEGOStateCompleted, want: "completed"},
		{state: SPNEGOStateFailed, want: "failed"},
		{state: SPNEGOState(9), want: "unknown"},
	}
	for _, test := range tests {
		if got := test.state.String(); got != test.want {
			t.Fatalf("SPNEGOState(%d).String() = %q, want %q", test.state, got, test.want)
		}
	}
}

func TestSPNEGOMechTypesExtension(t *testing.T) {
	der, err := EncodeMechTypeList([][]byte{ntlmMechOID})
	if err != nil {
		t.Fatalf("EncodeMechTypeList: %v", err)
	}
	token := &SPNEGOToken{
		HasNegState:   true,
		NegState:      NegStateAcceptIncomplete,
		SupportedMech: ntlmMechOID,
		MechTypesDER:  der,
	}
	encoded, err := EncodeSPNEGOToken(token, false)
	if err != nil {
		t.Fatalf("EncodeSPNEGOToken: %v", err)
	}
	parsed, err := ParseSPNEGOToken(encoded)
	if err != nil {
		t.Fatalf("ParseSPNEGOToken: %v", err)
	}
	if len(parsed.MechTypes) != 1 || !bytes.Equal(parsed.MechTypes[0], ntlmMechOID) {
		t.Fatalf("parsed mechTypes = %x", parsed.MechTypes)
	}
	if !bytes.Equal(parsed.MechTypesDER, der) {
		t.Fatalf("parsed mechTypesDER = %x, want %x", parsed.MechTypesDER, der)
	}
	if !parsed.SupportsNTLM() {
		t.Fatalf("parsed token does not advertise NTLM")
	}

	multiple, err := EncodeSPNEGOToken(&SPNEGOToken{
		MechTypes: [][]byte{spnegoMechOID, ntlmMechOID},
	}, false)
	if err != nil {
		t.Fatalf("EncodeSPNEGOToken(multi): %v", err)
	}
	parsedMultiple, err := ParseSPNEGOToken(multiple)
	if err != nil {
		t.Fatalf("ParseSPNEGOToken(multi): %v", err)
	}
	if len(parsedMultiple.MechTypes) != 2 || !parsedMultiple.SupportsNTLM() {
		t.Fatalf("parsed multiple mechTypes = %x", parsedMultiple.MechTypes)
	}
	if len(parsedMultiple.MechTypesDER) == 0 {
		t.Fatalf("multiple mechTypes has no DER list")
	}
}

func TestSPNEGOTokenEncodingValidation(t *testing.T) {
	tests := []struct {
		name  string
		token *SPNEGOToken
		init  bool
	}{
		{name: "nil token", init: true},
		{name: "invalid negState", token: &SPNEGOToken{HasNegState: true, NegState: NegState(9)}},
		{name: "init without mechTypes", token: &SPNEGOToken{MechToken: []byte{1, 2, 3}}, init: true},
		{name: "init with empty OID", token: &SPNEGOToken{MechTypes: [][]byte{{}}}, init: true},
		{name: "malformed mechTypesDER", token: &SPNEGOToken{MechTypesDER: []byte{0x31, 0x00}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := EncodeSPNEGOToken(test.token, test.init); !errors.Is(err, ErrSPNEGO) {
				t.Fatalf("error = %v, want ErrSPNEGO", err)
			}
		})
	}
}

func TestParseNegTokenInit2MechListMIC(t *testing.T) {
	der, err := EncodeMechTypeList([][]byte{ntlmMechOID})
	if err != nil {
		t.Fatalf("EncodeMechTypeList: %v", err)
	}
	initToken := testSeq(t, 0x30,
		testSeq(t, 0xA0, der),
		testSeq(t, 0xA4, testTLV(t, 0x04, []byte("mic"))),
	)
	wrapped := testSeq(t, 0xA0, initToken)
	parsed, err := ParseSPNEGOToken(wrapped)
	if err != nil {
		t.Fatalf("ParseSPNEGOToken: %v", err)
	}
	if !parsed.HasMechListMIC || !bytes.Equal(parsed.MechListMIC, []byte("mic")) {
		t.Fatalf("mechListMIC = %x, present = %v", parsed.MechListMIC, parsed.HasMechListMIC)
	}
	if len(parsed.MechTypes) != 1 || !bytes.Equal(parsed.MechTypes[0], ntlmMechOID) {
		t.Fatalf("mechTypes = %x", parsed.MechTypes)
	}
	if !bytes.Equal(parsed.MechTypesDER, der) {
		t.Fatalf("mechTypesDER = %x, want %x", parsed.MechTypesDER, der)
	}

	invalid := testSeq(t, 0x30,
		testSeq(t, 0xA0, der),
		testSeq(t, 0xA4, testTLV(t, 0x02, []byte{1})),
	)
	if _, err := ParseSPNEGOToken(testSeq(t, 0xA0, invalid)); !errors.Is(err, ErrSPNEGO) {
		t.Fatalf("invalid init MIC error = %v, want ErrSPNEGO", err)
	}

	invalidResponse := testSeq(t, 0xA1, testSeq(t, 0x30,
		testSeq(t, 0xA4, testTLV(t, 0x04, []byte{1})),
	))
	if _, err := ParseSPNEGOToken(invalidResponse); !errors.Is(err, ErrSPNEGO) {
		t.Fatalf("invalid response mechTypes error = %v, want ErrSPNEGO", err)
	}
}

// mustEncodeNegState builds a final server NegTokenResp. | mustEncodeNegState 构建
// 最终服务端 NegTokenResp。
func mustEncodeNegState(t *testing.T, state NegState, token []byte) []byte {
	t.Helper()
	encoded, err := EncodeSPNEGOToken(&SPNEGOToken{
		HasNegState:   true,
		NegState:      state,
		SupportedMech: ntlmMechOID,
		ResponseToken: token,
	}, false)
	if err != nil {
		t.Fatalf("EncodeSPNEGOToken: %v", err)
	}
	return encoded
}
