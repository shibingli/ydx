package kms

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"net/http"
	"testing"

	"github.com/shibingli/ydx/base64"
)

// TestSignAndVerifyRejectedOptions verifies unsupported digests and direct-signature rules.
// | TestSignAndVerifyRejectedOptions 校验不支持的摘要与直接签名规则。
func TestSignAndVerifyRejectedOptions(t *testing.T) {
	ctx := context.Background()
	service, _ := newServiceForTest(t, Config{})
	aes := createKeyForTest(t, service, CreateKeyRequest{ID: "opt-aes", Type: KeyTypeAES, Bits: 256}, true)
	if _, err := service.Sign(ctx, aes.ID, []byte("data"), WithHash(crypto.MD5)); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("Sign MD5 err = %v, want ErrNotSupported | Sign MD5 错误 = %v，期望 ErrNotSupported", err, err)
	}

	ed := createKeyForTest(t, service, CreateKeyRequest{ID: "opt-ed", Type: KeyTypeEd25519}, true)
	if _, err := service.Sign(ctx, ed.ID, []byte("data"), WithDigest()); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("Ed25519 Sign digest err = %v, want ErrNotSupported | Ed25519 摘要签名错误 = %v，期望 ErrNotSupported", err, err)
	}
	if _, err := service.Verify(ctx, ed.ID, []byte("data"), make([]byte, 64), WithDigest()); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("Ed25519 Verify digest err = %v, want ErrNotSupported | Ed25519 摘要验签错误 = %v，期望 ErrNotSupported", err, err)
	}

	sm2 := createKeyForTest(t, service, CreateKeyRequest{ID: "opt-sm2", Type: KeyTypeSM2, Bits: 256}, true)
	if _, err := service.Sign(ctx, sm2.ID, []byte("data"), WithDigest()); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("SM2 Sign digest err = %v, want ErrNotSupported | SM2 摘要签名错误 = %v，期望 ErrNotSupported", err, err)
	}
}

// TestValidateMaterialAndParsingBranches verifies material validation, parser mismatches and size
// fallbacks. | TestValidateMaterialAndParsingBranches 校验材料校验、解析类型不匹配与长度回退。
func TestValidateMaterialAndParsingBranches(t *testing.T) {
	if _, _, _, err := ValidateMaterial(KeyTypeAES, 100, make([]byte, 12), nil); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("AES 100 bits err = %v, want ErrInvalidKeySize | AES 100 位错误 = %v，期望 ErrInvalidKeySize", err, err)
	}
	if _, _, _, err := ValidateMaterial(KeyTypeRSA, 0, nil, nil); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("empty RSA material err = %v, want ErrInvalidMaterial | 空 RSA 材料错误 = %v，期望 ErrInvalidMaterial", err, err)
	}
	if _, _, _, err := ValidateMaterial(KeyTypeAES, 0, bytes.Repeat([]byte{1}, 32), nil); err != nil {
		t.Fatalf("AES default bits err = %v | AES 默认位长错误 = %v", err, err)
	}

	private, public, _, _, err := generateMaterial(KeyTypeEd25519, 0)
	if err != nil {
		t.Fatalf("generateMaterial: %v | generateMaterial：%v", err, err)
	}
	if _, err := parsePrivateKey(KeyTypeECDSA, private); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("private type mismatch err = %v, want ErrInvalidMaterial | 私钥类型不匹配错误 = %v，期望 ErrInvalidMaterial", err, err)
	}
	if _, err := parsePrivateKey(KeyTypeAES, private); !errors.Is(err, ErrInvalidKeyType) {
		t.Fatalf("private default err = %v, want ErrInvalidKeyType | 私钥默认分支错误 = %v，期望 ErrInvalidKeyType", err, err)
	}
	if _, err := parsePublicKey(KeyTypeRSA, nil); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("empty public err = %v, want ErrInvalidMaterial | 空公钥错误 = %v，期望 ErrInvalidMaterial", err, err)
	}
	if _, err := parsePublicKey(KeyTypeRSA, public); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("public type mismatch err = %v, want ErrInvalidMaterial | 公钥类型不匹配错误 = %v，期望 ErrInvalidMaterial", err, err)
	}
	if _, err := parsePublicKey(KeyTypeAES, public); !errors.Is(err, ErrInvalidKeyType) {
		t.Fatalf("public default err = %v, want ErrInvalidKeyType | 公钥默认分支错误 = %v，期望 ErrInvalidKeyType", err, err)
	}
	if _, err := publicFromPrivate(KeyTypeAES, nil); !errors.Is(err, ErrInvalidKeyType) {
		t.Fatalf("publicFromPrivate default err = %v, want ErrInvalidKeyType | publicFromPrivate 默认分支错误 = %v，期望 ErrInvalidKeyType", err, err)
	}
	if got := bitsForPublic(KeyTypeRSA, nil); got != 2048 {
		t.Fatalf("RSA fallback bits = %d, want 2048 | RSA 回退位长 = %d，期望 2048", got, got)
	}
	if got := bitsForPublic(KeyTypeECDSA, nil); got != 256 {
		t.Fatalf("ECDSA fallback bits = %d, want 256 | ECDSA 回退位长 = %d，期望 256", got, got)
	}
	if got := bitsForPublic(KeyTypeEd25519, nil); got != 256 {
		t.Fatalf("Ed25519 fallback bits = %d, want 256 | Ed25519 回退位长 = %d，期望 256", got, got)
	}
	if got := bitsForPublic(KeyTypeSM2, nil); got != 256 {
		t.Fatalf("SM2 fallback bits = %d, want 256 | SM2 回退位长 = %d，期望 256", got, got)
	}
	if got := bitsForPublic(KeyTypeAES, nil); got != 0 {
		t.Fatalf("unknown fallback bits = %d, want 0 | 未知回退位长 = %d，期望 0", got, got)
	}
}

// TestParseCipherEnvelopeRejectsCorruption verifies every header validation branch. |
// TestParseCipherEnvelopeRejectsCorruption 校验每个头部校验分支。
func TestParseCipherEnvelopeRejectsCorruption(t *testing.T) {
	header := buildCipherHeader(wrappedMagic, algAES256GCM, "key-1", 1, make([]byte, gcmNonceSize))
	valid := append(append([]byte(nil), header...), make([]byte, 16)...)
	if _, err := parseCipherEnvelope(wrappedMagic, valid); err != nil {
		t.Fatalf("valid envelope err = %v | 合法信封错误 = %v", err, err)
	}

	badVersion := append([]byte(nil), valid...)
	badVersion[len(wrappedMagic)] = cipherFormatVersion + 1
	badAlg := append([]byte(nil), valid...)
	badAlg[len(wrappedMagic)+1] = 0x7f
	badKeyID := append([]byte(nil), valid...)
	badKeyID[len(wrappedMagic)+2] = 0
	badKeyID[len(wrappedMagic)+3] = 0
	nonceLengthOffset := len(wrappedMagic) + 2 + 2 + len("key-1") + 4
	badNonce := append([]byte(nil), valid...)
	badNonce[nonceLengthOffset] = 0
	truncated := append(append([]byte(nil), header...), 0, 0)

	cases := []struct {
		name string
		data []byte
	}{
		{"format version", badVersion},
		{"algorithm", badAlg},
		{"key id length", badKeyID},
		{"nonce length", badNonce},
		{"truncated ciphertext", truncated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseCipherEnvelope(wrappedMagic, tc.data); !errors.Is(err, ErrInvalidCiphertext) {
				t.Fatalf("parse err = %v, want ErrInvalidCiphertext | 解析错误 = %v，期望 ErrInvalidCiphertext", err, err)
			}
		})
	}
}

// TestDecryptEnvelopeRejectsMetadataAndTampering verifies envelope identity, version, nonce and
// authentication failures. | TestDecryptEnvelopeRejectsMetadataAndTampering 校验信封身份、版本、
// nonce 与认证失败。
func TestDecryptEnvelopeRejectsMetadataAndTampering(t *testing.T) {
	ctx := context.Background()
	service, _ := newServiceForTest(t, Config{})
	key := createKeyForTest(t, service, CreateKeyRequest{ID: "env-key", Type: KeyTypeAES, Bits: 256, Alias: "env-alias"}, true)
	aad := []byte("envelope-aad")
	envelope, err := service.EncryptEnvelope(ctx, key.ID, []byte("payload"), aad)
	if err != nil {
		t.Fatalf("EncryptEnvelope: %v | EncryptEnvelope：%v", err, err)
	}

	if _, err := service.DecryptEnvelope(ctx, &Envelope{KeyID: "absent"}, nil); !errors.Is(err, ErrAliasNotFound) {
		t.Fatalf("missing key err = %v, want ErrAliasNotFound | 缺少密钥错误 = %v，期望 ErrAliasNotFound", err, err)
	}

	aliasEnvelope := envelope.Clone()
	aliasEnvelope.KeyID = key.Alias
	if _, err := service.DecryptEnvelope(ctx, aliasEnvelope, aad); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("alias envelope err = %v, want ErrInvalidCiphertext | 别名信封错误 = %v，期望 ErrInvalidCiphertext", err, err)
	}

	missingVersion := envelope.Clone()
	missingVersion.KeyVersion = 99
	if _, err := service.DecryptEnvelope(ctx, missingVersion, aad); !errors.Is(err, ErrVersionNotFound) {
		t.Fatalf("missing version err = %v, want ErrVersionNotFound | 缺少版本错误 = %v，期望 ErrVersionNotFound", err, err)
	}

	badNonce := envelope.Clone()
	badNonce.Nonce = nil
	if _, err := service.DecryptEnvelope(ctx, badNonce, aad); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("bad nonce err = %v, want ErrInvalidCiphertext | 错误 nonce 错误 = %v，期望 ErrInvalidCiphertext", err, err)
	}

	tampered := envelope.Clone()
	tampered.Ciphertext[0] ^= 0xff
	if _, err := service.DecryptEnvelope(ctx, tampered, aad); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered err = %v, want ErrAuthentication | 篡改错误 = %v，期望 ErrAuthentication", err, err)
	}
}

// TestEncryptEnvelopeUsageDenied verifies envelope encryption enforces the encrypt usage. |
// TestEncryptEnvelopeUsageDenied 校验信封加密强制 encrypt 用途。
func TestEncryptEnvelopeUsageDenied(t *testing.T) {
	ctx := context.Background()
	service, _ := newServiceForTest(t, Config{})
	key := createKeyForTest(t, service, CreateKeyRequest{
		ID:    "env-decrypt-only",
		Type:  KeyTypeAES,
		Bits:  256,
		Usage: []KeyUsage{UsageDecrypt},
	}, true)
	if _, err := service.EncryptEnvelope(ctx, key.ID, []byte("payload"), nil); !errors.Is(err, ErrUsageNotAllowed) {
		t.Fatalf("EncryptEnvelope err = %v, want ErrUsageNotAllowed | EncryptEnvelope 错误 = %v，期望 ErrUsageNotAllowed", err, err)
	}
}

// TestUnwrapKeyRejectsMismatchedMetadata verifies identifier and version checks after parsing. |
// TestUnwrapKeyRejectsMismatchedMetadata 校验解析后的标识与版本检查。
func TestUnwrapKeyRejectsMismatchedMetadata(t *testing.T) {
	ctx := context.Background()
	service, _ := newServiceForTest(t, Config{})
	key := createKeyForTest(t, service, CreateKeyRequest{ID: "unwrap-key", Type: KeyTypeAES, Bits: 256, Alias: "unwrap-alias"}, true)
	wrapped, err := service.WrapKey(ctx, key.ID, []byte("material"), nil)
	if err != nil {
		t.Fatalf("WrapKey: %v | WrapKey：%v", err, err)
	}
	if _, err := service.UnwrapKey(ctx, "absent", wrapped, nil); !errors.Is(err, ErrAliasNotFound) {
		t.Fatalf("missing key err = %v, want ErrAliasNotFound | 缺少密钥错误 = %v，期望 ErrAliasNotFound", err, err)
	}
	other := createKeyForTest(t, service, CreateKeyRequest{ID: "unwrap-other", Type: KeyTypeAES, Bits: 256}, true)
	if _, err := service.UnwrapKey(ctx, other.ID, wrapped, nil); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("cross-key unwrap err = %v, want ErrInvalidCiphertext | 跨密钥解包错误 = %v，期望 ErrInvalidCiphertext", err, err)
	}
	if plain, err := service.UnwrapKey(ctx, key.Alias, wrapped, nil); err != nil || !bytes.Equal(plain, []byte("material")) {
		t.Fatalf("alias unwrap = %q, %v | 别名解包 = %q，%v", plain, err, plain, err)
	}

	header := buildCipherHeader(wrappedMagic, algAES256GCM, key.ID, 99, make([]byte, gcmNonceSize))
	missingVersion := append(append([]byte(nil), header...), make([]byte, 16)...)
	if _, err := service.UnwrapKey(ctx, key.ID, missingVersion, nil); !errors.Is(err, ErrVersionNotFound) {
		t.Fatalf("missing version err = %v, want ErrVersionNotFound | 缺少版本错误 = %v，期望 ErrVersionNotFound", err, err)
	}
}

// TestDeriveKeyDefaultLength verifies the zero length default. | TestDeriveKeyDefaultLength 校验零长度默认值。
func TestDeriveKeyDefaultLength(t *testing.T) {
	ctx := context.Background()
	service, _ := newServiceForTest(t, Config{})
	key := createKeyForTest(t, service, CreateKeyRequest{ID: "derive-key", Type: KeyTypeAES, Bits: 256}, true)
	out, err := service.DeriveKey(ctx, key.ID, 0, "domain", nil)
	if err != nil || len(out) != 32 {
		t.Fatalf("DeriveKey = %d bytes, %v | DeriveKey = %d 字节，%v", len(out), err, len(out), err)
	}
}

// TestVerifyWithoutPublicMaterial verifies the no-verifiable-key failure and the key-level fallback
// retained by older versions. | TestVerifyWithoutPublicMaterial 校验无可验签公钥的失败，以及旧版本
// 使用密钥级公钥的回退。
func TestVerifyWithoutPublicMaterial(t *testing.T) {
	ctx := context.Background()
	service, _ := newServiceForTest(t, Config{})
	key := createKeyForTest(t, service, CreateKeyRequest{ID: "verify-ed", Type: KeyTypeEd25519}, true)
	signature, err := service.Sign(ctx, key.ID, []byte("message"))
	if err != nil {
		t.Fatalf("Sign: %v | Sign：%v", err, err)
	}

	raw, err := service.store.GetKey(ctx, key.ID)
	if err != nil {
		t.Fatalf("GetKey: %v | GetKey：%v", err, err)
	}
	fallback := raw.Clone()
	for _, version := range fallback.Versions {
		version.PublicMaterial = nil
	}
	if err := service.store.UpdateKey(ctx, fallback); err != nil {
		t.Fatalf("UpdateKey fallback: %v | UpdateKey 回退：%v", err, err)
	}
	valid, err := service.Verify(ctx, key.ID, []byte("message"), signature)
	if err != nil || !valid {
		t.Fatalf("key-level fallback Verify = %v, %v | 密钥级回退 Verify = %v，%v", valid, err, valid, err)
	}

	stripped, err := service.store.GetKey(ctx, key.ID)
	if err != nil {
		t.Fatalf("GetKey stripped: %v | GetKey 剥离：%v", err, err)
	}
	stripped.PublicMaterial = nil
	for _, version := range stripped.Versions {
		version.PublicMaterial = nil
	}
	if err := service.store.UpdateKey(ctx, stripped); err != nil {
		t.Fatalf("UpdateKey stripped: %v | UpdateKey 剥离：%v", err, err)
	}
	if _, err := service.Verify(ctx, key.ID, []byte("message"), signature); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("no public material err = %v, want ErrInvalidMaterial | 无公钥材料错误 = %v，期望 ErrInvalidMaterial", err, err)
	}
}

// TestServerCryptoAuthorizationAndDecoding verifies per-endpoint authorization and Base64 decoding
// failures. | TestServerCryptoAuthorizationAndDecoding 校验逐端点授权与 Base64 解码失败。
func TestServerCryptoAuthorizationAndDecoding(t *testing.T) {
	service, _ := newServiceForTest(t, Config{})
	denied, err := NewServer(service, ServerConfig{Authorizer: func(_ context.Context, _ *http.Request, _, _ string) error {
		return ErrForbidden
	}})
	if err != nil {
		t.Fatalf("NewServer: %v | NewServer：%v", err, err)
	}
	key := createKeyForTest(t, service, CreateKeyRequest{ID: "srv-key", Type: KeyTypeAES, Bits: 256}, true)
	deniedHandler := denied.HTTPHandler("/api")
	encoded := base64.StdEncoding.EncodeToString([]byte("data"))
	requests := []struct {
		path string
		body any
	}{
		{"/api/encrypt", encryptJSON{KeyID: key.ID, Plaintext: encoded}},
		{"/api/decrypt", decryptJSON{KeyID: key.ID, Ciphertext: encoded}},
		{"/api/sign", signJSON{KeyID: key.ID, Data: encoded}},
		{"/api/verify", signJSON{KeyID: key.ID, Data: encoded, Signature: encoded}},
		{"/api/generate-data-key", generateDataKeyJSON{KeyID: key.ID}},
		{"/api/random", randomJSON{Length: 8}},
	}
	for _, request := range requests {
		expectStatus(t, jsonRequest(t, deniedHandler, http.MethodPost, request.path, request.body), http.StatusForbidden)
	}

	server, err := NewServer(service, ServerConfig{})
	if err != nil {
		t.Fatalf("NewServer allowed: %v | NewServer 允许：%v", err, err)
	}
	handler := server.HTTPHandler("/api")
	expectStatus(t, jsonRequest(t, handler, http.MethodPost, "/api/encrypt", encryptJSON{KeyID: key.ID, Plaintext: "not-base64!"}), http.StatusBadRequest)
	expectStatus(t, jsonRequest(t, handler, http.MethodPost, "/api/encrypt", encryptJSON{KeyID: key.ID, Plaintext: encoded, AAD: "not-base64!"}), http.StatusBadRequest)
	expectStatus(t, jsonRequest(t, handler, http.MethodPost, "/api/decrypt", decryptJSON{KeyID: key.ID, Ciphertext: "not-base64!"}), http.StatusBadRequest)
	expectStatus(t, jsonRequest(t, handler, http.MethodPost, "/api/decrypt", decryptJSON{KeyID: key.ID, Ciphertext: encoded, AAD: "not-base64!"}), http.StatusBadRequest)
	expectStatus(t, jsonRequest(t, handler, http.MethodPost, "/api/sign", signJSON{KeyID: key.ID, Data: "not-base64!"}), http.StatusBadRequest)
	expectStatus(t, jsonRequest(t, handler, http.MethodPost, "/api/sign", signJSON{KeyID: key.ID, Data: encoded, Hash: "md5"}), http.StatusBadRequest)
	expectStatus(t, jsonRequest(t, handler, http.MethodPost, "/api/verify", signJSON{KeyID: key.ID, Data: "not-base64!"}), http.StatusBadRequest)
	expectStatus(t, jsonRequest(t, handler, http.MethodPost, "/api/verify", signJSON{KeyID: key.ID, Data: encoded, Signature: "not-base64!"}), http.StatusBadRequest)
	expectStatus(t, jsonRequest(t, handler, http.MethodPost, "/api/verify", signJSON{KeyID: key.ID, Data: encoded, Hash: "md5"}), http.StatusBadRequest)
	expectStatus(t, jsonRequest(t, handler, http.MethodPost, "/api/generate-data-key", generateDataKeyJSON{KeyID: key.ID, AAD: "not-base64!"}), http.StatusBadRequest)
	expectStatus(t, jsonRequest(t, handler, http.MethodGet, "/api/audit?offset=x", nil), http.StatusBadRequest)
	expectStatus(t, jsonRequest(t, handler, http.MethodGet, "/api/audit?until=not-a-time", nil), http.StatusBadRequest)

	generated := jsonRequest(t, handler, http.MethodPost, "/api/generate-data-key", generateDataKeyJSON{KeyID: key.ID})
	expectStatus(t, generated, http.StatusOK)
	var dataKey dataKeyResponse
	decodeResponse(t, generated, &dataKey)
	if dataKey.Plaintext == "" || dataKey.Wrapped == "" || dataKey.KeyID != key.ID {
		t.Fatalf("data key response = %+v | 数据密钥响应 = %+v", dataKey, dataKey)
	}
}

// TestSignOptionsFromJSONBranches verifies every hash spelling and the digest/PSS switches. |
// TestSignOptionsFromJSONBranches 校验每种摘要写法以及 digest/PSS 开关。
func TestSignOptionsFromJSONBranches(t *testing.T) {
	cases := []signJSON{
		{Digest: true},
		{PSS: true},
		{Hash: "SHA-384"},
		{Hash: "sha-512"},
		{Hash: "sha256"},
	}
	for _, body := range cases {
		options, err := signOptionsFromJSON(body)
		if err != nil || len(options) == 0 {
			t.Fatalf("signOptionsFromJSON(%+v) = %d options, %v | signOptionsFromJSON(%+v) = %d 个选项，%v", body, len(options), err, body, len(options), err)
		}
	}
	if _, err := signOptionsFromJSON(signJSON{Hash: "md5"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("md5 err = %v, want ErrInvalidRequest | md5 错误 = %v，期望 ErrInvalidRequest", err, err)
	}
}

// TestGenerateRandomRejectsOutOfRange verifies the documented 1..1 MiB bound. |
// TestGenerateRandomRejectsOutOfRange 校验文档规定的 1..1 MiB 边界。
func TestGenerateRandomRejectsOutOfRange(t *testing.T) {
	ctx := context.Background()
	service, _ := newServiceForTest(t, Config{})
	for _, n := range []int{0, -1, (1 << 20) + 1} {
		if _, err := service.GenerateRandom(ctx, n); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("GenerateRandom(%d) err = %v, want ErrInvalidRequest | GenerateRandom(%d) 错误 = %v，期望 ErrInvalidRequest", n, err, n, err)
		}
	}
}
