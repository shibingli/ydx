package ntlm

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

// The MS-NLMP 4.2.4 NTLMv2 authentication vector. | MS-NLMP 4.2.4 NTLMv2 认证向量。
const (
	clientServerChallengeHex = "0123456789abcdef"
	clientChallengeHex       = "aaaaaaaaaaaaaaaa"
	clientTargetInfoHex      = "02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000"
	clientProofHex           = "68cd0ab851e51c96aabc927bebef6a1c"
	clientLMv2Hex            = "86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa"
	clientNTResponseHex      = clientProofHex +
		"01010000000000000000000000000000" +
		"aaaaaaaaaaaaaaaa" +
		"00000000" +
		clientTargetInfoHex +
		"00000000"
)

// testHMACMD5 is an independent standard-library HMAC-MD5 used to verify what
// the package produced. | testHMACMD5 是独立的标准库 HMAC-MD5，用于校验本包的输出。
func testHMACMD5(key, data []byte) []byte {
	mac := hmac.New(md5.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// clientServerFlags are the challenge flags a domain controller sends. |
// clientServerFlags 是域控制器发送的挑战标志。
func clientServerFlags() NegotiateFlags {
	return FlagUnicode | FlagOEM | FlagRequestTarget | FlagNTLM | FlagAlwaysSign |
		FlagTargetInfo | FlagVersion | Flag128 | Flag56 | FlagExtendedSessionSecurity
}

// clientOfficialTargetInfo parses the target information of the official
// vector. | clientOfficialTargetInfo 解析官方向量的目标信息。
func clientOfficialTargetInfo(t *testing.T) TargetInfo {
	t.Helper()
	info, err := ParseTargetInfo(mustHex(t, clientTargetInfoHex))
	if err != nil {
		t.Fatalf("ParseTargetInfo: %v", err)
	}
	return info
}

// clientDomainTargetInfo returns a minimal target information containing the
// NetBIOS domain name. | clientDomainTargetInfo 返回仅含 NetBIOS 域名的最小目标信息。
func clientDomainTargetInfo() TargetInfo {
	return TargetInfo{{Type: AVNbDomainName, Value: encodeString("Domain", true)}}
}

// clientChallengeBytes encodes a Type 2 challenge for client tests. |
// clientChallengeBytes 为客户端测试编码 Type 2 挑战。
func clientChallengeBytes(t *testing.T, flags NegotiateFlags, server [8]byte, info TargetInfo) []byte {
	t.Helper()
	message := &ChallengeMessage{Flags: flags, ServerChallenge: server, TargetInfo: info}
	encoded, err := message.Encode()
	if err != nil {
		t.Fatalf("ChallengeMessage.Encode: %v", err)
	}
	return encoded
}

// clientFixedChallenge returns a fresh copy of the official client challenge. |
// clientFixedChallenge 返回官方向量客户端挑战的新副本。
func clientFixedChallenge() []byte {
	return []byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}
}

// clientConfig returns the official-vector client configuration. |
// clientConfig 返回官方向量的客户端配置。
func clientConfig() Config {
	return Config{
		Domain:          "Domain",
		Username:        "User",
		Password:        "Password",
		ClientChallenge: clientFixedChallenge(),
		Timestamp:       time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// clientCreate builds a client or fails the test. | clientCreate 构建客户端，失败时终止测试。
func clientCreate(t *testing.T, config Config) *Client {
	t.Helper()
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

// clientExchange runs a successful exchange and decodes the Type 3 message. |
// clientExchange 执行成功的交换并解码 Type 3 消息。
func clientExchange(t *testing.T, config Config, flags NegotiateFlags, server [8]byte, info TargetInfo) (type1, challengeData, type3 []byte, message *AuthenticateMessage) {
	t.Helper()
	client := clientCreate(t, config)
	type1, err := client.Negotiate()
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	challengeData = clientChallengeBytes(t, flags, server, info)
	type3, err = client.Authenticate(challengeData)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	message, err = DecodeAuthenticate(type3)
	if err != nil {
		t.Fatalf("DecodeAuthenticate: %v", err)
	}
	return type1, challengeData, type3, message
}

// clientResponseTimestamp extracts the timestamp from the NTLMv2 temporary
// structure. | clientResponseTimestamp 从 NTLMv2 临时结构中提取时间戳。
func clientResponseTimestamp(t *testing.T, ntResponse []byte) uint64 {
	t.Helper()
	if len(ntResponse) < 32 {
		t.Fatalf("NT response is %d bytes, want at least 32", len(ntResponse))
	}
	return binary.LittleEndian.Uint64(ntResponse[24:32])
}

// clientResponseTargetInfo extracts the AV pairs echoed in the NTLMv2
// temporary structure. | clientResponseTargetInfo 提取 NTLMv2 临时结构中回显的 AV 对。
func clientResponseTargetInfo(t *testing.T, ntResponse []byte) TargetInfo {
	t.Helper()
	if len(ntResponse) < 16+28+4 {
		t.Fatalf("NT response is %d bytes, want at least %d", len(ntResponse), 16+28+4)
	}
	temp := ntResponse[16:]
	info, err := ParseTargetInfo(temp[28 : len(temp)-4])
	if err != nil {
		t.Fatalf("ParseTargetInfo: %v", err)
	}
	return info
}

// clientType3MICOffset returns the MIC offset the encoder uses. |
// clientType3MICOffset 返回编码器使用的 MIC 偏移。
func clientType3MICOffset(flags NegotiateFlags) int {
	offset := authenticateBaseHeader
	if flags.Has(FlagVersion) {
		offset += versionSize
	}
	return offset
}

func TestClientNTLMv2OfficialVector(t *testing.T) {
	server := [8]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	info := clientOfficialTargetInfo(t)
	type1, challengeData, type3, message := clientExchange(t, clientConfig(), clientServerFlags(), server, info)

	negotiate, err := DecodeNegotiate(type1)
	if err != nil {
		t.Fatalf("DecodeNegotiate: %v", err)
	}
	if negotiate.Domain != "Domain" {
		t.Fatalf("Type 1 domain = %q", negotiate.Domain)
	}
	if !negotiate.Flags.Has(FlagUnicode) || !negotiate.Flags.Has(FlagNTLM) || !negotiate.Flags.Has(FlagExtendedSessionSecurity) {
		t.Fatalf("Type 1 flags = %#x", negotiate.Flags)
	}
	if negotiate.Version == nil || *negotiate.Version != DefaultVersion() {
		t.Fatalf("Type 1 version = %#v", negotiate.Version)
	}

	if message.Domain != "Domain" || message.Username != "User" || message.Workstation != "" {
		t.Fatalf("Type 3 identity = %q\\%q workstation %q", message.Domain, message.Username, message.Workstation)
	}
	if got := hex.EncodeToString(message.NTResponse); got != clientNTResponseHex {
		t.Fatalf("NTResponse = %s, want %s", got, clientNTResponseHex)
	}
	if got := hex.EncodeToString(message.LMResponse); got != clientLMv2Hex {
		t.Fatalf("LMResponse = %s, want %s", got, clientLMv2Hex)
	}
	if message.MIC != nil {
		t.Fatalf("unexpected MIC")
	}

	key := NTLMv2Hash("Password", "User", "Domain")
	proof := message.NTResponse[:16]
	temp := message.NTResponse[16:]
	wantProof := testHMACMD5(key, append(append([]byte(nil), server[:]...), temp...))
	if !bytes.Equal(proof, wantProof) {
		t.Fatalf("proof does not verify against HMAC-MD5")
	}
	wantLM := testHMACMD5(key, append(append([]byte(nil), server[:]...), mustHex(t, clientChallengeHex)...))
	if !bytes.Equal(message.LMResponse[:16], wantLM) || !bytes.Equal(message.LMResponse[16:], mustHex(t, clientChallengeHex)) {
		t.Fatalf("LMv2 response does not verify")
	}
	if !bytes.Equal(temp[16:24], mustHex(t, clientChallengeHex)) {
		t.Fatalf("temporary client challenge = %x", temp[16:24])
	}
	if !bytes.Equal(temp[len(temp)-4:], []byte{0, 0, 0, 0}) {
		t.Fatalf("temporary structure lacks Reserved4: %x", temp[len(temp)-4:])
	}

	decodedChallenge, err := DecodeChallenge(challengeData)
	if err != nil {
		t.Fatalf("DecodeChallenge: %v", err)
	}
	if decodedChallenge.ServerChallenge != server {
		t.Fatalf("decoded server challenge = %x", decodedChallenge.ServerChallenge)
	}

	replica := append([]byte(nil), type3...)
	if !bytes.Equal(replica, type3) {
		t.Fatalf("Type 3 encoding is not deterministic")
	}
}

func TestClientNTLMv2TimestampPrecedence(t *testing.T) {
	server := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	serverTimestamp := time.Date(2023, 11, 14, 22, 13, 20, 0, time.UTC)
	serverTicks := filetimeFromTime(serverTimestamp)
	serverTicksBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(serverTicksBytes, serverTicks)
	info := TargetInfo{
		{Type: AVNbDomainName, Value: encodeString("Domain", true)},
		{Type: AVTimestamp, Value: serverTicksBytes},
	}

	t.Run("server timestamp", func(t *testing.T) {
		config := clientConfig()
		config.Timestamp = time.Time{}
		_, _, _, message := clientExchange(t, config, clientServerFlags(), server, info)
		if got := clientResponseTimestamp(t, message.NTResponse); got != serverTicks {
			t.Fatalf("timestamp = %d, want %d", got, serverTicks)
		}
	})

	t.Run("configured timestamp wins", func(t *testing.T) {
		moment := time.Date(2020, 1, 2, 3, 4, 5, 600, time.UTC)
		config := clientConfig()
		config.Timestamp = moment
		_, _, _, message := clientExchange(t, config, clientServerFlags(), server, info)
		if got, want := clientResponseTimestamp(t, message.NTResponse), filetimeFromTime(moment); got != want {
			t.Fatalf("timestamp = %d, want %d", got, want)
		}
	})

	t.Run("current time fallback", func(t *testing.T) {
		config := clientConfig()
		config.Timestamp = time.Time{}
		infoWithoutStamp := TargetInfo{{Type: AVNbDomainName, Value: encodeString("Domain", true)}}
		_, _, _, message := clientExchange(t, config, clientServerFlags(), server, infoWithoutStamp)
		ticks := clientResponseTimestamp(t, message.NTResponse)
		if ticks == 0 {
			t.Fatalf("timestamp is zero")
		}
		got := timeFromFiletime(ticks)
		if delta := time.Since(got); delta < -10*time.Minute || delta > 10*time.Minute {
			t.Fatalf("fallback timestamp %v is far from now", got)
		}
	})
}

func TestClientRandomClientChallenge(t *testing.T) {
	server := [8]byte{9, 8, 7, 6, 5, 4, 3, 2}
	info := clientDomainTargetInfo()
	config := clientConfig()
	config.ClientChallenge = nil
	serverTimestamp := time.Date(2022, 5, 6, 7, 8, 9, 0, time.UTC)
	config.Timestamp = serverTimestamp
	config.AllowMissingTargetInfo = false

	_, _, _, first := clientExchange(t, config, clientServerFlags(), server, info)
	_, _, _, second := clientExchange(t, config, clientServerFlags(), server, info)
	firstChallenge := first.NTResponse[32:40]
	secondChallenge := second.NTResponse[32:40]
	if bytes.Equal(firstChallenge, secondChallenge) {
		t.Fatalf("random client challenges are equal: %x", firstChallenge)
	}
	if bytes.Equal(first.NTResponse, second.NTResponse) {
		t.Fatalf("random client challenges did not change the response")
	}
}

func TestClientMIC(t *testing.T) {
	server := [8]byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80}
	micFlags := make([]byte, 4)
	binary.LittleEndian.PutUint32(micFlags, AVFlagMICPresent)

	tests := []struct {
		name       string
		config     Config
		serverInfo TargetInfo
	}{
		{
			name:   "server requests MIC",
			config: clientConfig(),
			serverInfo: TargetInfo{
				{Type: AVNbDomainName, Value: encodeString("Domain", true)},
				{Type: AVFlags, Value: micFlags},
			},
		},
		{
			name:       "ForceMIC",
			config:     func() Config { config := clientConfig(); config.ForceMIC = true; return config }(),
			serverInfo: clientDomainTargetInfo(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			type1, challengeData, type3, message := clientExchange(t, test.config, clientServerFlags(), server, test.serverInfo)
			if len(message.MIC) != micSize {
				t.Fatalf("MIC length = %d", len(message.MIC))
			}
			if bytes.Equal(message.MIC, make([]byte, micSize)) {
				t.Fatalf("MIC is all zero")
			}
			key := NTLMv2Hash(test.config.Password, "User", "Domain")
			sessionBaseKey := testHMACMD5(key, message.NTResponse[:16])
			zeroed := append([]byte(nil), type3...)
			offset := clientType3MICOffset(message.Flags)
			if len(zeroed) < offset+micSize {
				t.Fatalf("Type 3 message is too short for a MIC")
			}
			for index := offset; index < offset+micSize; index++ {
				zeroed[index] = 0
			}
			macInput := make([]byte, 0, len(type1)+len(challengeData)+len(zeroed))
			macInput = append(macInput, type1...)
			macInput = append(macInput, challengeData...)
			macInput = append(macInput, zeroed...)
			want := testHMACMD5(sessionBaseKey, macInput)
			if !bytes.Equal(message.MIC, want) {
				t.Fatalf("MIC = %x, want %x", message.MIC, want)
			}
		})
	}
}

func TestClientNegotiateReturnsCopy(t *testing.T) {
	server := [8]byte{1, 3, 5, 7, 9, 11, 13, 15}
	micFlags := make([]byte, 4)
	binary.LittleEndian.PutUint32(micFlags, AVFlagMICPresent)
	info := TargetInfo{
		{Type: AVNbDomainName, Value: encodeString("Domain", true)},
		{Type: AVFlags, Value: micFlags},
	}
	config := clientConfig()
	client := clientCreate(t, config)
	type1, err := client.Negotiate()
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	original := append([]byte(nil), type1...)
	type1[0] = 0
	challengeData := clientChallengeBytes(t, clientServerFlags(), server, info)
	type3, err := client.Authenticate(challengeData)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	message, err := DecodeAuthenticate(type3)
	if err != nil {
		t.Fatalf("DecodeAuthenticate: %v", err)
	}
	sessionBaseKey := testHMACMD5(NTLMv2Hash("Password", "User", "Domain"), message.NTResponse[:16])
	zeroed := append([]byte(nil), type3...)
	offset := clientType3MICOffset(message.Flags)
	for index := offset; index < offset+micSize; index++ {
		zeroed[index] = 0
	}
	macInput := make([]byte, 0, len(original)+len(challengeData)+len(zeroed))
	macInput = append(macInput, original...)
	macInput = append(macInput, challengeData...)
	macInput = append(macInput, zeroed...)
	if want := testHMACMD5(sessionBaseKey, macInput); !bytes.Equal(message.MIC, want) {
		t.Fatalf("MIC was computed over the caller's mutated buffer")
	}
}

func TestClientChannelBindings(t *testing.T) {
	server := [8]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}
	binding := bytes.Repeat([]byte{0x42}, 16)
	otherBinding := bytes.Repeat([]byte{0x43}, 16)
	serverInfo := func(value []byte) TargetInfo {
		return TargetInfo{
			{Type: AVNbDomainName, Value: encodeString("Domain", true)},
			{Type: AVChannelBindings, Value: value},
		}
	}

	t.Run("matching", func(t *testing.T) {
		config := clientConfig()
		config.ChannelBindings = binding
		_, _, _, message := clientExchange(t, config, clientServerFlags(), server, serverInfo(binding))
		got, ok := clientResponseTargetInfo(t, message.NTResponse).Get(AVChannelBindings)
		if !ok || !bytes.Equal(got, binding) {
			t.Fatalf("response binding = %x, %v", got, ok)
		}
	})

	t.Run("client adds binding", func(t *testing.T) {
		config := clientConfig()
		config.ChannelBindings = binding
		_, _, _, message := clientExchange(t, config, clientServerFlags(), server, clientDomainTargetInfo())
		got, ok := clientResponseTargetInfo(t, message.NTResponse).Get(AVChannelBindings)
		if !ok || !bytes.Equal(got, binding) {
			t.Fatalf("response binding = %x, %v", got, ok)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		config := clientConfig()
		config.ChannelBindings = binding
		client := clientCreate(t, config)
		if _, err := client.Negotiate(); err != nil {
			t.Fatalf("Negotiate: %v", err)
		}
		challenge := clientChallengeBytes(t, clientServerFlags(), server, serverInfo(otherBinding))
		if _, err := client.Authenticate(challenge); !errors.Is(err, ErrChannelBindings) {
			t.Fatalf("error = %v, want ErrChannelBindings", err)
		}
	})

	t.Run("server binding without configuration", func(t *testing.T) {
		client := clientCreate(t, clientConfig())
		if _, err := client.Negotiate(); err != nil {
			t.Fatalf("Negotiate: %v", err)
		}
		challenge := clientChallengeBytes(t, clientServerFlags(), server, serverInfo(binding))
		if _, err := client.Authenticate(challenge); !errors.Is(err, ErrChannelBindings) {
			t.Fatalf("error = %v, want ErrChannelBindings", err)
		}
	})
}

func TestClientStateOrder(t *testing.T) {
	server := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	challenge := clientChallengeBytes(t, clientServerFlags(), server, clientDomainTargetInfo())
	client := clientCreate(t, clientConfig())
	if _, err := client.Authenticate(challenge); !errors.Is(err, ErrClientState) {
		t.Fatalf("Authenticate before Negotiate error = %v", err)
	}
	if _, err := client.Negotiate(); err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	if _, err := client.Negotiate(); !errors.Is(err, ErrClientState) {
		t.Fatalf("second Negotiate error = %v", err)
	}
	if _, err := client.Authenticate(challenge); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if _, err := client.Authenticate(challenge); !errors.Is(err, ErrClientState) {
		t.Fatalf("second Authenticate error = %v", err)
	}
}

func TestClientChallengePolicy(t *testing.T) {
	server := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	micFlags := make([]byte, 4)
	binary.LittleEndian.PutUint32(micFlags, AVFlagMICPresent)
	base := clientServerFlags()

	tests := []struct {
		name    string
		config  Config
		flags   NegotiateFlags
		server  [8]byte
		info    TargetInfo
		wantErr error
	}{
		{
			name:    "no NTLM flag",
			config:  clientConfig(),
			flags:   base &^ (FlagNTLM | FlagNTLMOnly),
			server:  server,
			info:    clientDomainTargetInfo(),
			wantErr: ErrChallenge,
		},
		{
			name:    "no Unicode",
			config:  clientConfig(),
			flags:   (base &^ FlagUnicode) | FlagOEM,
			server:  server,
			info:    clientDomainTargetInfo(),
			wantErr: ErrChallenge,
		},
		{
			name:    "zero server challenge",
			config:  clientConfig(),
			flags:   base,
			server:  [8]byte{},
			info:    clientDomainTargetInfo(),
			wantErr: ErrChallenge,
		},
		{
			name:    "missing target info",
			config:  clientConfig(),
			flags:   base,
			server:  server,
			info:    nil,
			wantErr: ErrTargetInfo,
		},
		{
			name: "missing target info allowed",
			config: func() Config {
				config := clientConfig()
				config.AllowMissingTargetInfo = true
				return config
			}(),
			flags:  base,
			server: server,
			info:   nil,
		},
		{
			name: "NTLM2 session without extended session security",
			config: Config{
				Domain: "Domain", Username: "User", Password: "Password",
				ResponseMode: ResponseNTLM2Session, AllowLegacy: true,
				ClientChallenge: clientFixedChallenge(),
			},
			flags:   base &^ FlagExtendedSessionSecurity,
			server:  server,
			info:    clientDomainTargetInfo(),
			wantErr: ErrChallenge,
		},
		{
			name: "NTLMv1 with extended session security",
			config: Config{
				Domain: "Domain", Username: "User", Password: "Password",
				ResponseMode: ResponseNTLMv1, AllowLegacy: true,
				ClientChallenge: clientFixedChallenge(),
			},
			flags:   base | FlagExtendedSessionSecurity,
			server:  server,
			info:    clientDomainTargetInfo(),
			wantErr: ErrChallenge,
		},
		{
			name: "NTLMv1 server requires MIC",
			config: Config{
				Domain: "Domain", Username: "User", Password: "Password",
				ResponseMode: ResponseNTLMv1, AllowLegacy: true,
				ClientChallenge: clientFixedChallenge(),
			},
			flags:  base &^ FlagExtendedSessionSecurity,
			server: server,
			info: TargetInfo{
				{Type: AVNbDomainName, Value: encodeString("Domain", true)},
				{Type: AVFlags, Value: micFlags},
			},
			wantErr: ErrUnsupported,
		},
		{
			name: "NTLM2 session server requires MIC",
			config: Config{
				Domain: "Domain", Username: "User", Password: "Password",
				ResponseMode: ResponseNTLM2Session, AllowLegacy: true,
				ClientChallenge: clientFixedChallenge(),
			},
			flags:  base | FlagExtendedSessionSecurity,
			server: server,
			info: TargetInfo{
				{Type: AVNbDomainName, Value: encodeString("Domain", true)},
				{Type: AVFlags, Value: micFlags},
			},
			wantErr: ErrUnsupported,
		},
		{
			name:    "unrelated flags",
			config:  clientConfig(),
			flags:   base &^ (FlagAlwaysSign | Flag128 | Flag56),
			server:  server,
			info:    clientDomainTargetInfo(),
			wantErr: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := clientCreate(t, test.config)
			if _, err := client.Negotiate(); err != nil {
				t.Fatalf("Negotiate: %v", err)
			}
			challenge := clientChallengeBytes(t, test.flags, test.server, test.info)
			_, err := client.Authenticate(challenge)
			if test.wantErr == nil {
				if err != nil {
					t.Fatalf("Authenticate: %v", err)
				}
				return
			}
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestClientMalformedChallenge(t *testing.T) {
	client := clientCreate(t, clientConfig())
	if _, err := client.Negotiate(); err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	for _, data := range [][]byte{
		nil,
		[]byte("NTLMSSP\x00"),
		append([]byte(Signature), 2, 0, 0, 0),
	} {
		if _, err := client.Authenticate(data); !errors.Is(err, ErrMessage) {
			t.Fatalf("Authenticate(%x) error = %v, want ErrMessage", data, err)
		}
	}
}

func TestClientLegacyResponses(t *testing.T) {
	server := [8]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	base := FlagUnicode | FlagOEM | FlagNTLM | FlagTargetInfo | FlagVersion

	t.Run("NTLMv1", func(t *testing.T) {
		config := clientConfig()
		config.ResponseMode = ResponseNTLMv1
		config.AllowLegacy = true
		config.Timestamp = time.Time{}
		client := clientCreate(t, config)
		type1, err := client.Negotiate()
		if err != nil {
			t.Fatalf("Negotiate: %v", err)
		}
		negotiate, err := DecodeNegotiate(type1)
		if err != nil {
			t.Fatalf("DecodeNegotiate: %v", err)
		}
		if negotiate.Flags.Has(FlagExtendedSessionSecurity) {
			t.Fatalf("NTLMv1 Type 1 requests extended session security")
		}
		challenge := clientChallengeBytes(t, base, server, nil)
		type3, err := client.Authenticate(challenge)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		message, err := DecodeAuthenticate(type3)
		if err != nil {
			t.Fatalf("DecodeAuthenticate: %v", err)
		}
		if got := hex.EncodeToString(message.NTResponse); got != "67c43011f30298a2ad35ece64f16331c44bdbed927841f94" {
			t.Fatalf("NT response = %s", got)
		}
		if got := hex.EncodeToString(message.LMResponse); got != "98def7b87f88aa5dafe2df779688a172def11c7d5ccdef13" {
			t.Fatalf("LM response = %s", got)
		}
		if message.MIC != nil {
			t.Fatalf("unexpected MIC")
		}
	})

	t.Run("NTLM2 session", func(t *testing.T) {
		config := clientConfig()
		config.ResponseMode = ResponseNTLM2Session
		config.AllowLegacy = true
		config.Timestamp = time.Time{}
		client := clientCreate(t, config)
		type1, err := client.Negotiate()
		if err != nil {
			t.Fatalf("Negotiate: %v", err)
		}
		negotiate, err := DecodeNegotiate(type1)
		if err != nil {
			t.Fatalf("DecodeNegotiate: %v", err)
		}
		if !negotiate.Flags.Has(FlagExtendedSessionSecurity) {
			t.Fatalf("NTLM2 session Type 1 lacks extended session security")
		}
		challenge := clientChallengeBytes(t, base|FlagExtendedSessionSecurity, server, nil)
		type3, err := client.Authenticate(challenge)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		message, err := DecodeAuthenticate(type3)
		if err != nil {
			t.Fatalf("DecodeAuthenticate: %v", err)
		}
		if got := hex.EncodeToString(message.NTResponse); got != "05e87ab9c858ae0acd5d16d157c35ad2ac4e307723418155" {
			t.Fatalf("NT response = %s", got)
		}
		wantLM := clientChallengeHex + strings.Repeat("00", 16)
		if got := hex.EncodeToString(message.LMResponse); got != wantLM {
			t.Fatalf("LM response = %s, want %s", got, wantLM)
		}
	})
}

func TestClientIdentityForms(t *testing.T) {
	server := [8]byte{0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78}
	info := clientDomainTargetInfo()

	t.Run("DOMAIN backslash user", func(t *testing.T) {
		config := clientConfig()
		config.Domain = ""
		config.Username = `Domain\User`
		_, _, _, message := clientExchange(t, config, clientServerFlags(), server, info)
		if message.Domain != "Domain" || message.Username != "User" {
			t.Fatalf("identity = %q\\%q", message.Domain, message.Username)
		}
		key := NTLMv2Hash("Password", "User", "Domain")
		if !bytes.Equal(message.NTResponse[:16], testHMACMD5(key, append(append([]byte(nil), server[:]...), message.NTResponse[16:]...))) {
			t.Fatalf("proof does not verify for DOMAIN\\user")
		}
	})

	t.Run("UPN", func(t *testing.T) {
		config := clientConfig()
		config.Domain = "Ignored"
		config.Username = "user@example.com"
		_, _, _, message := clientExchange(t, config, clientServerFlags(), server, info)
		if message.Domain != "" || message.Username != "user@example.com" {
			t.Fatalf("identity = %q\\%q", message.Domain, message.Username)
		}
		key := NTLMv2Hash("Password", "user@example.com", "")
		if !bytes.Equal(message.NTResponse[:16], testHMACMD5(key, append(append([]byte(nil), server[:]...), message.NTResponse[16:]...))) {
			t.Fatalf("proof does not verify for UPN")
		}
	})

	t.Run("workstation normalized", func(t *testing.T) {
		config := clientConfig()
		config.Workstation = "  WS01  "
		type1, _, _, message := clientExchange(t, config, clientServerFlags(), server, info)
		negotiate, err := DecodeNegotiate(type1)
		if err != nil {
			t.Fatalf("DecodeNegotiate: %v", err)
		}
		if negotiate.Workstation != "WS01" || message.Workstation != "WS01" {
			t.Fatalf("workstation = %q, %q", negotiate.Workstation, message.Workstation)
		}
	})

	t.Run("custom version", func(t *testing.T) {
		config := clientConfig()
		version := Version{Major: 6, Minor: 1, Build: 7601, Revision: 0x0f}
		config.Version = &version
		type1, _, _, message := clientExchange(t, config, clientServerFlags(), server, info)
		negotiate, err := DecodeNegotiate(type1)
		if err != nil {
			t.Fatalf("DecodeNegotiate: %v", err)
		}
		if negotiate.Version == nil || *negotiate.Version != version {
			t.Fatalf("Type 1 version = %#v", negotiate.Version)
		}
		if message.Version == nil || *message.Version != version {
			t.Fatalf("Type 3 version = %#v", message.Version)
		}
	})
}

func TestClientNegotiatedFlagsIntersection(t *testing.T) {
	server := [8]byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
	serverFlags := clientServerFlags() &^ (Flag128 | Flag56 | FlagAlwaysSign)
	type1, _, _, message := clientExchange(t, clientConfig(), serverFlags, server, clientDomainTargetInfo())
	negotiate, err := DecodeNegotiate(type1)
	if err != nil {
		t.Fatalf("DecodeNegotiate: %v", err)
	}
	want := negotiate.Flags & serverFlags
	if message.Flags != want {
		t.Fatalf("Type 3 flags = %#x, want %#x", message.Flags, want)
	}
	if message.Flags.Has(Flag128) || message.Flags.Has(Flag56) || message.Flags.Has(FlagAlwaysSign) {
		t.Fatalf("Type 3 flags contain server-unsupported bits: %#x", message.Flags)
	}
}

func TestNewClientValidation(t *testing.T) {
	const secret = "P@ssw0rd-Secret-Value"
	base := Config{Domain: "Domain", Username: "User", Password: secret}
	tests := []struct {
		name   string
		config Config
		want   error
	}{
		{name: "unknown response mode", config: func() Config {
			config := base
			config.ResponseMode = ResponseMode(9)
			return config
		}(), want: ErrUnsupported},
		{name: "NTLMv1 without AllowLegacy", config: func() Config {
			config := base
			config.ResponseMode = ResponseNTLMv1
			return config
		}(), want: ErrLegacyDisabled},
		{name: "NTLM2 session without AllowLegacy", config: func() Config {
			config := base
			config.ResponseMode = ResponseNTLM2Session
			return config
		}(), want: ErrLegacyDisabled},
		{name: "ForceMIC with NTLMv1", config: func() Config {
			config := base
			config.ResponseMode = ResponseNTLMv1
			config.AllowLegacy = true
			config.ForceMIC = true
			return config
		}(), want: ErrUnsupported},
		{name: "channel bindings with NTLM2 session", config: func() Config {
			config := base
			config.ResponseMode = ResponseNTLM2Session
			config.AllowLegacy = true
			config.ChannelBindings = make([]byte, 16)
			return config
		}(), want: ErrChannelBindings},
		{name: "short channel bindings", config: func() Config {
			config := base
			config.ChannelBindings = make([]byte, 15)
			return config
		}(), want: ErrChannelBindings},
		{name: "long channel bindings", config: func() Config {
			config := base
			config.ChannelBindings = make([]byte, 17)
			return config
		}(), want: ErrChannelBindings},
		{name: "short client challenge", config: func() Config {
			config := base
			config.ClientChallenge = make([]byte, 7)
			return config
		}(), want: ErrCredentials},
		{name: "long client challenge", config: func() Config {
			config := base
			config.ClientChallenge = make([]byte, 9)
			return config
		}(), want: ErrCredentials},
		{name: "empty username", config: func() Config {
			config := base
			config.Username = ""
			return config
		}(), want: ErrCredentials},
		{name: "NUL password", config: func() Config {
			config := base
			config.Password = "bad\x00password"
			return config
		}(), want: ErrCredentials},
		{name: "NUL workstation", config: func() Config {
			config := base
			config.Workstation = "WS\x00"
			return config
		}(), want: ErrCredentials},
		{name: "malformed domain login", config: func() Config {
			config := base
			config.Username = `Domain\`
			return config
		}(), want: ErrCredentials},
		{name: "conflicting domain", config: func() Config {
			config := base
			config.Username = `Other\User`
			return config
		}(), want: ErrCredentials},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewClient(test.config)
			if client != nil {
				t.Fatalf("NewClient returned a client")
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error leaks the password: %v", err)
			}
		})
	}
}

func TestSplitUsername(t *testing.T) {
	tests := []struct {
		name       string
		login      string
		domain     string
		wantDomain string
		wantUser   string
		wantErr    error
	}{
		{name: "domain backslash", login: `DOMAIN\user`, wantDomain: "DOMAIN", wantUser: "user"},
		{name: "domain backslash case-insensitive configured domain", login: `DOMAIN\user`, domain: "domain", wantDomain: "DOMAIN", wantUser: "user"},
		{name: "upn ignores configured domain", login: "user@example.com", domain: "Domain", wantDomain: "", wantUser: "user@example.com"},
		{name: "plain", login: "user", domain: "Domain", wantDomain: "Domain", wantUser: "user"},
		{name: "whitespace", login: " user ", domain: " Domain ", wantDomain: "Domain", wantUser: "user"},
		{name: "empty", login: " ", wantErr: ErrCredentials},
		{name: "empty domain part", login: `\user`, wantErr: ErrCredentials},
		{name: "empty user part", login: `DOMAIN\`, wantErr: ErrCredentials},
		{name: "conflicting explicit domain", login: `DOMAIN\user`, domain: "OTHER", wantErr: ErrCredentials},
		{name: "NUL login", login: "user\x00", wantErr: ErrCredentials},
		{name: "NUL domain", login: "user", domain: "Domain\x00", wantErr: ErrCredentials},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			domain, user, err := SplitUsername(test.login, test.domain)
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("error = %v, want %v", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("SplitUsername: %v", err)
			}
			if domain != test.wantDomain || user != test.wantUser {
				t.Fatalf("SplitUsername = %q, %q, want %q, %q", domain, user, test.wantDomain, test.wantUser)
			}
		})
	}
}

func TestClientErrorsDoNotLeakSecrets(t *testing.T) {
	const secret = "P@ssw0rd-Secret-Value"
	server := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	config := clientConfig()
	config.Password = secret
	client := clientCreate(t, config)
	if _, err := client.Negotiate(); err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	challenge := clientChallengeBytes(t, clientServerFlags(), server, clientDomainTargetInfo())
	if _, err := client.Authenticate([]byte("not a challenge")); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("error = %v", err)
	}
	type3, err := client.Authenticate(challenge)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if bytes.Contains(type3, []byte(secret)) {
		t.Fatalf("Type 3 message contains the password")
	}
}

func TestResponseModeAndFlagHelpers(t *testing.T) {
	tests := []struct {
		mode ResponseMode
		name string
	}{
		{ResponseNTLMv2, "NTLMv2"},
		{ResponseNTLMv1, "NTLMv1"},
		{ResponseNTLM2Session, "NTLM2-session"},
		{ResponseMode(9), "unknown"},
	}
	for _, test := range tests {
		if got := test.mode.String(); got != test.name {
			t.Fatalf("ResponseMode(%d).String() = %q, want %q", test.mode, got, test.name)
		}
	}
	if !FlagUnicode.Has(FlagUnicode) || FlagUnicode.Has(FlagUnicode|FlagOEM) {
		t.Fatalf("Has does not require every bit")
	}
	if DefaultVersion() != (Version{Major: 10, Minor: 0, Build: 19041, Revision: 0x0f}) {
		t.Fatalf("DefaultVersion = %#v", DefaultVersion())
	}
}
