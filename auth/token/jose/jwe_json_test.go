package jose

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/shibingli/ydx/json"
)

// rfc7516A4JWK is the RSA private key of RFC 7516 Appendix A.2.3. | rfc7516A4JWK 是 RFC 7516
// 附录 A.2.3 的 RSA 私钥。
const rfc7516A4JWK = `{"kty":"RSA",
      "n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
      "e":"AQAB",
      "d":"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
      "p":"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM",
      "q":"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0",
      "dp":"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs",
      "dq":"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU",
      "qi":"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo"}`

// rfc7516A3OctJWK is the AES key wrap key of RFC 7516 Appendix A.3. | rfc7516A3OctJWK 是 RFC 7516
// 附录 A.3 的 AES 密钥包装密钥。
const rfc7516A3OctJWK = `{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}`

// rfc7516A4JWE is the general JWE JSON serialization of RFC 7516 Appendix A.4.7. | rfc7516A4JWE 是
// RFC 7516 附录 A.4.7 的通用 JWE JSON 序列化。
const rfc7516A4JWE = `{
      "protected":
       "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
      "unprotected":
       {"jku":"https://server.example.com/keys.jwks"},
      "recipients":[
       {"header":
         {"alg":"RSA1_5","kid":"2011-04-29"},
        "encrypted_key":
         "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"},
       {"header":
         {"alg":"A128KW","kid":"7"},
        "encrypted_key":
         "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"}],
      "iv":
       "AxY8DCtDaGlsbGljb3RoZQ",
      "ciphertext":
       "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
      "tag":
       "Mz-VPPyU4RlcuYv1IwIvzw"
     }`

// rfc7516A5JWE is the flattened JWE JSON serialization of RFC 7516 Appendix A.5. | rfc7516A5JWE 是
// RFC 7516 附录 A.5 的扁平 JWE JSON 序列化。
const rfc7516A5JWE = `{
      "protected":
       "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
      "unprotected":
       {"jku":"https://server.example.com/keys.jwks"},
      "header":
       {"alg":"A128KW","kid":"7"},
      "encrypted_key":
       "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
      "iv":
       "AxY8DCtDaGlsbGljb3RoZQ",
      "ciphertext":
       "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
      "tag":
       "Mz-VPPyU4RlcuYv1IwIvzw"
     }`

// jweJSONObject decodes a JSON JWE into a generic map. | jweJSONObject 把 JSON JWE 解码为通用映射。
func jweJSONObject(t *testing.T, token string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := unmarshal([]byte(token), &m); err != nil {
		t.Fatalf("decode JSON JWE failed: %v", err)
	}
	return m
}

// encodeJWEJSONObject re-encodes a modified JSON JWE. | encodeJWEJSONObject 重新编码修改后的 JSON JWE。
func encodeJWEJSONObject(t *testing.T, m map[string]any) string {
	t.Helper()
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("encode JSON JWE failed: %v", err)
	}
	return string(out)
}

// mustEncryptJWEJSON encrypts plaintext with opts and fails the test on error. | mustEncryptJWEJSON
// 使用 opts 加密 plaintext，出错时失败测试。
func mustEncryptJWEJSON(t *testing.T, plaintext []byte, key *Key, opts EncryptOptions) string {
	t.Helper()
	token, err := Encrypt(plaintext, key, opts)
	if err != nil {
		t.Fatalf("Encrypt(%s/%s) failed: %v", opts.Alg, opts.Enc, err)
	}
	return token
}

// mustDecryptJWEJSON decrypts token with key and fails the test on error. | mustDecryptJWEJSON 使用
// key 解密 token，出错时失败测试。
func mustDecryptJWEJSON(t *testing.T, token string, key *Key, opts DecryptOptions) []byte {
	t.Helper()
	plaintext, err := Decrypt(token, key, opts)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	return plaintext
}

// TestJWEJSONRoundTripMatrix covers the flattened and general forms across the representative
// key-management and content-encryption algorithms. | TestJWEJSONRoundTripMatrix 覆盖扁平与通用形式
// 在代表性密钥管理与内容加密算法上的往返。
func TestJWEJSONRoundTripMatrix(t *testing.T) {
	plaintext := []byte("JSON JWE: Live long and prosper. | JSON JWE：生生不息，繁荣昌盛。")
	rsaKey := jweTestKey(t, AlgRSAOAEP)
	kwKey := testOctKey(t, 16)
	ecdhKey := testECDHKey(t, 256)
	dirGCM := testOctKey(t, 16)
	dirCBC := testOctKey(t, 32)
	cases := []struct {
		name        string
		key         *Key
		alg         string
		enc         string
		allowRSA15  bool
		expectKeyID bool
	}{
		{"dir-gcm", dirGCM, AlgDir, EncA128GCM, false, true},
		{"dir-cbc", dirCBC, AlgDir, EncA128CBCHS256, false, true},
		{"a128kw-gcm", kwKey, AlgA128KW, EncA128GCM, false, true},
		{"a128kw-cbc", kwKey, AlgA128KW, EncA128CBCHS256, false, true},
		{"rsa-oaep-gcm", rsaKey, AlgRSAOAEP, EncA128GCM, false, true},
		{"rsa-oaep-256-cbc", rsaKey, AlgRSAOAEP256, EncA128CBCHS256, false, true},
		{"rsa1_5-gcm", rsaKey, AlgRSA15, EncA128GCM, true, true},
		{"ecdh-es-gcm", ecdhKey, AlgECDHES, EncA128GCM, false, true},
		{"ecdh-es-kw-cbc", ecdhKey, AlgECDHESA128KW, EncA128CBCHS256, false, true},
	}
	for _, ser := range []Serialization{SerializationFlattened, SerializationGeneral} {
		ser := ser
		for _, tc := range cases {
			tc := tc
			t.Run(string(ser)+"/"+tc.name, func(t *testing.T) {
				token := mustEncryptJWEJSON(t, plaintext, tc.key, EncryptOptions{
					Alg:           tc.alg,
					Enc:           tc.enc,
					Serialization: ser,
					AllowRSA1_5:   tc.allowRSA15,
					APU:           []byte("Alice"),
					APV:           []byte("Bob"),
				})
				root := jweJSONObject(t, token)
				if _, ok := root["recipients"]; ok != (ser == SerializationGeneral) {
					t.Fatalf("recipients presence = %v, want general=%v", ok, ser == SerializationGeneral)
				}
				if ser == SerializationFlattened {
					if _, ok := root["header"]; ok {
						t.Fatalf("single-key flattened output must not carry a per-recipient header")
					}
				}
				var encryptedKey string
				var hasEncryptedKey bool
				if ser == SerializationGeneral {
					entry, ok := root["recipients"].([]any)[0].(map[string]any)
					if !ok {
						t.Fatalf("recipient entry is not an object")
					}
					encryptedKey, hasEncryptedKey = entry["encrypted_key"].(string)
				} else {
					encryptedKey, hasEncryptedKey = root["encrypted_key"].(string)
				}
				wantEncryptedKey := tc.alg != AlgDir && tc.alg != AlgECDHES
				if hasEncryptedKey != wantEncryptedKey {
					t.Fatalf("encrypted_key present = %v, want %v", hasEncryptedKey, wantEncryptedKey)
				}
				if wantEncryptedKey && encryptedKey == "" {
					t.Fatalf("empty encrypted_key")
				}
				got := mustDecryptJWEJSON(t, token, tc.key, DecryptOptions{AllowRSA1_5: tc.allowRSA15})
				if !bytes.Equal(got, plaintext) {
					t.Fatalf("plaintext = %q, want %q", got, plaintext)
				}
			})
		}
	}
}

// TestJWEJSONMultiRecipient encrypts one plaintext to RSA, AES Key Wrap and ECDH-ES key-wrap
// recipients and decrypts it with each private key. | TestJWEJSONMultiRecipient 把同一明文加密给
// RSA、AES 密钥包装与 ECDH-ES 密钥包装接收方，并用各私钥分别解密。
func TestJWEJSONMultiRecipient(t *testing.T) {
	plaintext := []byte("shared plaintext | 共享明文")
	rsaKey := jweTestKey(t, AlgRSAOAEP)
	kwKey := testOctKey(t, 16)
	ecdhKey := testECDHKey(t, 256)
	token, err := Encrypt(plaintext, nil, EncryptOptions{
		Enc:           EncA256CBCHS512,
		Serialization: SerializationGeneral,
		Recipients: []Recipient{
			{Key: rsaKey, Alg: AlgRSAOAEP, Kid: "rsa"},
			{Key: kwKey, Alg: AlgA128KW, Kid: "kw"},
			{Key: ecdhKey, Alg: AlgECDHESA128KW, Kid: "ecdh"},
		},
		Unprotected: map[string]any{"jku": "https://example.test/keys.jwks"},
		AAD:         []byte("multi-recipient aad"),
	})
	if err != nil {
		t.Fatalf("Encrypt multi-recipient failed: %v", err)
	}
	root := jweJSONObject(t, token)
	recipients, ok := root["recipients"].([]any)
	if !ok || len(recipients) != 3 {
		t.Fatalf("recipients = %T(%v), want three entries", root["recipients"], root["recipients"])
	}
	if _, ok := root["aad"]; !ok {
		t.Fatalf("aad member missing")
	}
	for _, tc := range []struct {
		name string
		key  *Key
	}{
		{"rsa", rsaKey},
		{"kw", kwKey},
		{"ecdh", ecdhKey},
	} {
		got, err := Decrypt(token, tc.key, DecryptOptions{})
		if err != nil {
			t.Fatalf("Decrypt(%s) failed: %v", tc.name, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("Decrypt(%s) = %q, want %q", tc.name, got, plaintext)
		}
	}
	// Each recipient header carries its own alg and kid, while enc stays shared and protected.
	entry, ok := recipients[1].(map[string]any)
	if !ok {
		t.Fatalf("recipient entry is %T, want object", recipients[1])
	}
	header, ok := entry["header"].(map[string]any)
	if !ok {
		t.Fatalf("recipient header is %T, want object", entry["header"])
	}
	if header["alg"] != AlgA128KW || header["kid"] != "kw" {
		t.Fatalf("recipient header = %v", header)
	}
	protectedBytes, err := DecodeSegment(root["protected"].(string))
	if err != nil {
		t.Fatalf("decode protected failed: %v", err)
	}
	protected := string(protectedBytes)
	if strings.Contains(protected, `"alg"`) || !strings.Contains(protected, `"enc"`) {
		t.Fatalf("protected header must hold shared enc only: %s", protected)
	}
}

// TestJWEJSONMultiRecipientRSA15 covers RSA1_5 as one of several recipients with explicit opt-in. |
// TestJWEJSONMultiRecipientRSA15 覆盖 RSA1_5 作为多接收方之一并显式开启的场景。
func TestJWEJSONMultiRecipientRSA15(t *testing.T) {
	plaintext := []byte("legacy recipient | 旧系统接收方")
	rsaKey := jweTestKey(t, AlgRSA15)
	kwKey := testOctKey(t, 32)
	opts := EncryptOptions{
		Enc:           EncA128GCM,
		Serialization: SerializationGeneral,
		Recipients: []Recipient{
			{Key: rsaKey, Alg: AlgRSA15, Kid: "legacy"},
			{Key: kwKey, Alg: AlgA256KW, Kid: "modern"},
		},
	}
	if _, err := Encrypt(plaintext, nil, opts); !errors.Is(err, ErrAlgNotAllowed) {
		t.Fatalf("encrypt RSA1_5 without opt-in err = %v, want ErrAlgNotAllowed", err)
	}
	opts.AllowRSA1_5 = true
	token, err := Encrypt(plaintext, nil, opts)
	if err != nil {
		t.Fatalf("encrypt with RSA1_5 opt-in failed: %v", err)
	}
	if _, err := Decrypt(token, rsaKey, DecryptOptions{}); !errors.Is(err, ErrAlgNotAllowed) {
		t.Fatalf("decrypt RSA1_5 without opt-in err = %v, want ErrAlgNotAllowed", err)
	}
	got, err := Decrypt(token, rsaKey, DecryptOptions{AllowRSA1_5: true})
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypt RSA1_5 = %q, %v", got, err)
	}
	got, err = Decrypt(token, kwKey, DecryptOptions{})
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypt AES-KW recipient = %q, %v", got, err)
	}
}

// TestJWEJSONHeaderMerge covers shared unprotected headers, per-recipient headers and the
// duplicate-location rules. | TestJWEJSONHeaderMerge 覆盖共享非保护头部、每接收方头部与重复位置
// 规则。
func TestJWEJSONHeaderMerge(t *testing.T) {
	plaintext := []byte("headers | 头部")
	kwKey := testOctKey(t, 16)
	token := mustEncryptJWEJSON(t, plaintext, nil, EncryptOptions{
		Enc:           EncA128GCM,
		Serialization: SerializationGeneral,
		Recipients: []Recipient{{
			Key: kwKey,
			Alg: AlgA128KW,
			Kid: "kw",
			Header: map[string]any{
				"jku": "https://example.test/keys.jwks",
				"cty": "text/plain",
			},
		}},
		Unprotected: map[string]any{"typ": "JWE"},
	})
	if got := mustDecryptJWEJSON(t, token, kwKey, DecryptOptions{}); !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext = %q", got)
	}

	base := jweJSONObject(t, token)
	baseProtected := base["protected"]

	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   error
	}{
		{
			name: "duplicate protected and unprotected",
			mutate: func(m map[string]any) {
				m["unprotected"] = map[string]any{"enc": EncA128GCM}
			},
			want: ErrInvalidHeader,
		},
		{
			name: "duplicate protected and recipient",
			mutate: func(m map[string]any) {
				recipients := m["recipients"].([]any)
				entry := recipients[0].(map[string]any)
				header := entry["header"].(map[string]any)
				header["enc"] = EncA128GCM
			},
			want: ErrInvalidHeader,
		},
		{
			name: "duplicate unprotected and recipient",
			mutate: func(m map[string]any) {
				m["unprotected"] = map[string]any{"jku": "https://other.test"}
			},
			want: ErrInvalidHeader,
		},
		{
			name: "crit in unprotected",
			mutate: func(m map[string]any) {
				m["unprotected"] = map[string]any{"crit": []any{}}
			},
			want: ErrInvalidHeader,
		},
		{
			name: "crit in recipient",
			mutate: func(m map[string]any) {
				recipients := m["recipients"].([]any)
				entry := recipients[0].(map[string]any)
				header := entry["header"].(map[string]any)
				header["crit"] = []any{}
			},
			want: ErrInvalidHeader,
		},
		{
			name: "zip in recipient",
			mutate: func(m map[string]any) {
				recipients := m["recipients"].([]any)
				entry := recipients[0].(map[string]any)
				header := entry["header"].(map[string]any)
				header["zip"] = ZipDEF
			},
			want: ErrInvalidHeader,
		},
		{
			name: "crit in protected",
			mutate: func(m map[string]any) {
				m["protected"] = EncodeSegment([]byte(`{"enc":"A128GCM","crit":["exp"]}`))
			},
			want: ErrUnsupportedCrit,
		},
		{
			name: "mixed general and flattened",
			mutate: func(m map[string]any) {
				m["header"] = map[string]any{"kid": "kw"}
			},
			want: ErrMalformed,
		},
		{
			name: "missing iv",
			mutate: func(m map[string]any) {
				delete(m, "iv")
			},
			want: ErrMalformed,
		},
		{
			name: "missing ciphertext",
			mutate: func(m map[string]any) {
				delete(m, "ciphertext")
			},
			want: ErrMalformed,
		},
		{
			name: "missing tag",
			mutate: func(m map[string]any) {
				delete(m, "tag")
			},
			want: ErrMalformed,
		},
		{
			name: "iv not a string",
			mutate: func(m map[string]any) {
				m["iv"] = 1
			},
			want: ErrMalformed,
		},
		{
			name: "iv not base64url",
			mutate: func(m map[string]any) {
				m["iv"] = "!!!"
			},
			want: ErrMalformed,
		},
		{
			name: "aad not a string",
			mutate: func(m map[string]any) {
				m["aad"] = true
			},
			want: ErrMalformed,
		},
		{
			name: "protected not a string",
			mutate: func(m map[string]any) {
				m["protected"] = 1
			},
			want: ErrInvalidHeader,
		},
		{
			name: "protected empty",
			mutate: func(m map[string]any) {
				m["protected"] = ""
			},
			want: ErrInvalidHeader,
		},
		{
			name: "recipients empty",
			mutate: func(m map[string]any) {
				m["recipients"] = []any{}
			},
			want: ErrMalformed,
		},
		{
			name: "recipients not an array",
			mutate: func(m map[string]any) {
				m["recipients"] = "x"
			},
			want: ErrMalformed,
		},
		{
			name: "recipient not an object",
			mutate: func(m map[string]any) {
				m["recipients"] = []any{"x"}
			},
			want: ErrMalformed,
		},
		{
			name: "recipient header not an object",
			mutate: func(m map[string]any) {
				m["recipients"] = []any{map[string]any{"header": "x"}}
			},
			want: ErrInvalidHeader,
		},
		{
			name: "recipient encrypted_key not a string",
			mutate: func(m map[string]any) {
				m["recipients"] = []any{map[string]any{"encrypted_key": 1}}
			},
			want: ErrMalformed,
		},
		{
			name: "too many recipients",
			mutate: func(m map[string]any) {
				arr := make([]any, maxJWERecipients+1)
				for i := range arr {
					arr[i] = map[string]any{}
				}
				m["recipients"] = arr
			},
			want: ErrMalformed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := make(map[string]any, len(base))
			for k, v := range base {
				m[k] = v
			}
			// The mutation helpers act on nested values; clone the nested recipients array so cases
			// cannot observe one another. | 修改辅助函数作用于嵌套值；复制嵌套 recipients 数组，避免
			// 用例互相影响。
			if arr, ok := base["recipients"].([]any); ok {
				copied := make([]any, len(arr))
				for i, item := range arr {
					entry := make(map[string]any, len(item.(map[string]any)))
					orig := item.(map[string]any)
					for k, v := range orig {
						entry[k] = v
					}
					if header, ok := orig["header"].(map[string]any); ok {
						hcopy := make(map[string]any, len(header))
						for k, v := range header {
							hcopy[k] = v
						}
						entry["header"] = hcopy
					}
					copied[i] = entry
				}
				m["recipients"] = copied
			}
			tc.mutate(m)
			_, err := Decrypt(encodeJWEJSONObject(t, m), kwKey, DecryptOptions{})
			if !errors.Is(err, tc.want) {
				t.Fatalf("Decrypt err = %v, want %v", err, tc.want)
			}
		})
	}
	if baseProtected == nil {
		t.Fatalf("base token has no protected header")
	}
}

// TestJWEJSONRawParseErrors covers document-level strictness that cannot be expressed through the
// map form. | TestJWEJSONRawParseErrors 覆盖无法通过映射形式表达的文档级严格性。
func TestJWEJSONRawParseErrors(t *testing.T) {
	kwKey := testOctKey(t, 16)
	cases := []struct {
		name  string
		token string
		want  error
	}{
		{"not an object", `"x"`, ErrMalformed},
		{"array", `[]`, ErrMalformed},
		{"truncated", `{`, ErrMalformed},
		{"duplicate member", `{"iv":"AA","iv":"AA"}`, ErrInvalidHeader},
		{"trailing data", `{"iv":"AA"}x`, ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decrypt(tc.token, kwKey, DecryptOptions{}); !errors.Is(err, tc.want) {
				t.Fatalf("Decrypt err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestJWEJSONAAD covers the aad member, including the empty-versus-absent distinction and tamper
// rejection. | TestJWEJSONAAD 覆盖 aad 成员，包括空值与缺失的区别以及篡改拒绝。
func TestJWEJSONAAD(t *testing.T) {
	plaintext := []byte("aad | 附加认证数据")
	key := testOctKey(t, 16)
	aad := []byte("authenticate me | 认证我")
	token := mustEncryptJWEJSON(t, plaintext, key, EncryptOptions{
		Alg: AlgDir, Enc: EncA128GCM, Serialization: SerializationFlattened, AAD: aad,
	})
	root := jweJSONObject(t, token)
	member, ok := root["aad"].(string)
	if !ok || member != EncodeSegment(aad) {
		t.Fatalf("aad member = %v, want %s", root["aad"], EncodeSegment(aad))
	}
	if got := mustDecryptJWEJSON(t, token, key, DecryptOptions{}); !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext = %q", got)
	}

	tampered := EncodeSegment([]byte("authenticate me!"))
	tamperedRoot := jweJSONObject(t, token)
	tamperedRoot["aad"] = tampered
	if _, err := Decrypt(encodeJWEJSONObject(t, tamperedRoot), key, DecryptOptions{}); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("tampered aad err = %v, want ErrDecryptionFailed", err)
	}

	removedRoot := jweJSONObject(t, token)
	delete(removedRoot, "aad")
	if _, err := Decrypt(encodeJWEJSONObject(t, removedRoot), key, DecryptOptions{}); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("removed aad err = %v, want ErrDecryptionFailed", err)
	}

	emptyToken := mustEncryptJWEJSON(t, plaintext, key, EncryptOptions{
		Alg: AlgDir, Enc: EncA128GCM, Serialization: SerializationFlattened, AAD: []byte{},
	})
	emptyRoot := jweJSONObject(t, emptyToken)
	if member, ok := emptyRoot["aad"].(string); !ok || member != "" {
		t.Fatalf("empty aad member = %v, want empty string", emptyRoot["aad"])
	}
	if got := mustDecryptJWEJSON(t, emptyToken, key, DecryptOptions{}); !bytes.Equal(got, plaintext) {
		t.Fatalf("empty aad plaintext = %q", got)
	}

	absentToken := mustEncryptJWEJSON(t, plaintext, key, EncryptOptions{
		Alg: AlgDir, Enc: EncA128GCM, Serialization: SerializationFlattened,
	})
	if _, ok := jweJSONObject(t, absentToken)["aad"]; ok {
		t.Fatalf("nil aad emitted an aad member")
	}
}

// TestJWEJSONZip covers DEF protection, the decompression limit and the shared-only placement of
// zip. | TestJWEJSONZip 覆盖 DEF 保护、解压上限与 zip 仅限共享头部的位置规则。
func TestJWEJSONZip(t *testing.T) {
	plaintext := bytes.Repeat([]byte("compressible payload | 可压缩载荷"), 4096)
	key := testOctKey(t, 32)
	for _, ser := range []Serialization{SerializationFlattened, SerializationGeneral} {
		token := mustEncryptJWEJSON(t, plaintext, key, EncryptOptions{
			Alg: AlgA256KW, Enc: EncA256CBCHS512, Serialization: ser, Zip: ZipDEF,
		})
		protectedBytes, err := DecodeSegment(jweJSONObject(t, token)["protected"].(string))
		if err != nil {
			t.Fatalf("decode protected failed: %v", err)
		}
		if !strings.Contains(string(protectedBytes), `"zip":"DEF"`) {
			t.Fatalf("zip missing from protected header: %s", protectedBytes)
		}
		got := mustDecryptJWEJSON(t, token, key, DecryptOptions{})
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("zip round trip mismatch")
		}
		if _, err := Decrypt(token, key, DecryptOptions{MaxDecompressedSize: 64}); !errors.Is(err, ErrDecompressionLimit) {
			t.Fatalf("decompression limit err = %v, want ErrDecompressionLimit", err)
		}
	}
	if _, err := Encrypt(plaintext, key, EncryptOptions{
		Alg: AlgA256KW, Enc: EncA256CBCHS512, Serialization: SerializationFlattened, Zip: "GZIP",
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("unknown zip err = %v, want ErrInvalidConfig", err)
	}
}

// TestJWEJSONOptionErrors covers encryption-side configuration refusals. | TestJWEJSONOptionErrors 覆盖
// 加密侧的配置拒绝。
func TestJWEJSONOptionErrors(t *testing.T) {
	key := testOctKey(t, 16)
	key2 := testOctKey(t, 16)
	rsaKey := jweTestKey(t, AlgRSAOAEP)
	ecdhKey := testECDHKey(t, 256)
	cases := []struct {
		name string
		key  *Key
		opts EncryptOptions
		want error
	}{
		{
			name: "compact with AAD",
			key:  key,
			opts: EncryptOptions{Alg: AlgDir, Enc: EncA128GCM, AAD: []byte{}},
			want: ErrInvalidConfig,
		},
		{
			name: "compact with empty unprotected",
			key:  key,
			opts: EncryptOptions{Alg: AlgDir, Enc: EncA128GCM, Unprotected: map[string]any{}},
			want: ErrInvalidConfig,
		},
		{
			name: "compact with recipients",
			key:  key,
			opts: EncryptOptions{
				Enc:        EncA128GCM,
				Recipients: []Recipient{{Key: key, Alg: AlgDir}},
			},
			want: ErrInvalidConfig,
		},
		{
			name: "unknown serialization",
			key:  key,
			opts: EncryptOptions{Alg: AlgDir, Enc: EncA128GCM, Serialization: Serialization("bogus")},
			want: ErrInvalidConfig,
		},
		{
			name: "flattened with two recipients",
			key:  nil,
			opts: EncryptOptions{
				Enc:           EncA128GCM,
				Serialization: SerializationFlattened,
				Recipients:    []Recipient{{Key: key, Alg: AlgA128KW}, {Key: key2, Alg: AlgA128KW}},
			},
			want: ErrInvalidConfig,
		},
		{
			name: "key and recipients",
			key:  key,
			opts: EncryptOptions{
				Enc:           EncA128GCM,
				Serialization: SerializationGeneral,
				Recipients:    []Recipient{{Key: key, Alg: AlgA128KW}},
			},
			want: ErrInvalidConfig,
		},
		{
			name: "nil key",
			key:  nil,
			opts: EncryptOptions{Enc: EncA128GCM, Serialization: SerializationFlattened},
			want: ErrInvalidKey,
		},
		{
			name: "nil recipient key",
			key:  nil,
			opts: EncryptOptions{
				Enc:           EncA128GCM,
				Serialization: SerializationGeneral,
				Recipients:    []Recipient{{Alg: AlgA128KW}},
			},
			want: ErrInvalidKey,
		},
		{
			name: "recipient without alg",
			key:  nil,
			opts: EncryptOptions{
				Enc:           EncA128GCM,
				Serialization: SerializationGeneral,
				Recipients:    []Recipient{{Key: key}},
			},
			want: ErrAlgNotAllowed,
		},
		{
			name: "recipient unknown alg",
			key:  nil,
			opts: EncryptOptions{
				Enc:           EncA128GCM,
				Serialization: SerializationGeneral,
				Recipients:    []Recipient{{Key: key, Alg: "none"}},
			},
			want: ErrAlgNotAllowed,
		},
		{
			name: "dir with two recipients",
			key:  nil,
			opts: EncryptOptions{
				Enc:           EncA128GCM,
				Serialization: SerializationGeneral,
				Recipients:    []Recipient{{Key: key, Alg: AlgDir}, {Key: key2, Alg: AlgDir}},
			},
			want: ErrInvalidConfig,
		},
		{
			name: "ecdh-es with two recipients",
			key:  nil,
			opts: EncryptOptions{
				Enc:           EncA128GCM,
				Serialization: SerializationGeneral,
				Recipients:    []Recipient{{Key: ecdhKey, Alg: AlgECDHES}, {Key: ecdhKey, Alg: AlgECDHESA128KW}},
			},
			want: ErrInvalidConfig,
		},
		{
			name: "rsa1_5 without opt-in",
			key:  rsaKey,
			opts: EncryptOptions{Alg: AlgRSA15, Enc: EncA128GCM, Serialization: SerializationFlattened},
			want: ErrAlgNotAllowed,
		},
		{
			name: "unsupported enc",
			key:  key,
			opts: EncryptOptions{Alg: AlgDir, Enc: "A128CBC", Serialization: SerializationFlattened},
			want: ErrUnsupportedEnc,
		},
		{
			name: "recipient managed alg",
			key:  nil,
			opts: EncryptOptions{
				Enc:           EncA128GCM,
				Serialization: SerializationFlattened,
				Recipients:    []Recipient{{Key: key, Alg: AlgA128KW, Header: map[string]any{"alg": AlgDir}}},
			},
			want: ErrInvalidHeader,
		},
		{
			name: "recipient managed kid",
			key:  nil,
			opts: EncryptOptions{
				Enc:           EncA128GCM,
				Serialization: SerializationFlattened,
				Recipients:    []Recipient{{Key: key, Alg: AlgA128KW, Header: map[string]any{"kid": "x"}}},
			},
			want: ErrInvalidHeader,
		},
		{
			name: "recipient managed epk",
			key:  nil,
			opts: EncryptOptions{
				Enc:           EncA128GCM,
				Serialization: SerializationFlattened,
				Recipients:    []Recipient{{Key: key, Alg: AlgA128KW, Header: map[string]any{"epk": map[string]any{}}}},
			},
			want: ErrInvalidHeader,
		},
		{
			name: "unprotected managed enc",
			key:  key,
			opts: EncryptOptions{
				Alg: AlgDir, Enc: EncA128GCM, Serialization: SerializationFlattened,
				Unprotected: map[string]any{"enc": EncA128GCM},
			},
			want: ErrInvalidHeader,
		},
		{
			name: "unprotected crit",
			key:  key,
			opts: EncryptOptions{
				Alg: AlgDir, Enc: EncA128GCM, Serialization: SerializationFlattened,
				Unprotected: map[string]any{"crit": []any{}},
			},
			want: ErrInvalidHeader,
		},
		{
			name: "unprotected conflicts with protected",
			key:  key,
			opts: EncryptOptions{
				Alg: AlgDir, Enc: EncA128GCM, Serialization: SerializationFlattened, Typ: "JWE",
				Unprotected: map[string]any{"typ": "other"},
			},
			want: ErrInvalidHeader,
		},
		{
			name: "too many recipients",
			key:  nil,
			opts: func() EncryptOptions {
				recipients := make([]Recipient, maxJWERecipients+1)
				for i := range recipients {
					recipients[i] = Recipient{Key: key, Alg: AlgA128KW}
				}
				return EncryptOptions{Enc: EncA128GCM, Serialization: SerializationGeneral, Recipients: recipients}
			}(),
			want: ErrInvalidConfig,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Encrypt([]byte("x"), tc.key, tc.opts); !errors.Is(err, tc.want) {
				t.Fatalf("Encrypt err = %v, want %v", err, tc.want)
			}
		})
	}
}

// distinctOctKey returns an oct key whose material is repeated fill, so tests can build several
// keys that are not interchangeable. | distinctOctKey 返回材料由 fill 重复构成的 oct 密钥，使测试
// 能构造互不相同的多个密钥。
func distinctOctKey(t *testing.T, kid string, fill byte, n int) *Key {
	t.Helper()
	k, err := FromHMAC(kid, bytes.Repeat([]byte{fill}, n))
	if err != nil {
		t.Fatalf("FromHMAC failed: %v", err)
	}
	return k
}

// TestJWEJSONKeySelection covers kid-priority, fallback across recipients and resolver-driven key
// choice. | TestJWEJSONKeySelection 覆盖 kid 优先、跨接收方回退与 resolver 驱动的密钥选择。
func TestJWEJSONKeySelection(t *testing.T) {
	plaintext := []byte("select the right key | 选择正确的密钥")
	keyOne := distinctOctKey(t, "one", 0x11, 16)
	keyTwo := distinctOctKey(t, "two", 0x22, 16)
	token, err := Encrypt(plaintext, nil, EncryptOptions{
		Enc:           EncA128GCM,
		Serialization: SerializationGeneral,
		Recipients: []Recipient{
			{Key: keyOne, Alg: AlgA128KW, Kid: "one"},
			{Key: keyTwo, Alg: AlgA128KW, Kid: "two"},
		},
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	// keyTwo does not open recipient one, so the loop must fall through to recipient two.
	got, err := Decrypt(token, keyTwo, DecryptOptions{})
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("Decrypt(keyTwo) = %q, %v", got, err)
	}
	// A key carrying a kid that matches no recipient still falls back to document order and fails
	// with a real decryption error rather than a configuration error.
	stranger := distinctOctKey(t, "stranger", 0x33, 16)
	if _, err := Decrypt(token, stranger, DecryptOptions{}); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("Decrypt(stranger) err = %v, want ErrDecryptionFailed", err)
	}

	set := &KeySet{Keys: []*Key{keyOne, keyTwo}}
	got, err = DecryptWithResolver(token, KeySetResolver(set), DecryptOptions{})
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("DecryptWithResolver = %q, %v", got, err)
	}
	byKid := KeyResolverFunc(func(_ context.Context, header Header) (*Key, error) {
		switch header.String("kid") {
		case "one":
			return keyOne, nil
		case "two":
			return keyTwo, nil
		}
		return nil, nil
	})
	got, err = DecryptWithResolver(token, byKid, DecryptOptions{})
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("DecryptWithResolver(byKid) = %q, %v", got, err)
	}
	if _, err := DecryptWithResolver(token, nil, DecryptOptions{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil resolver err = %v, want ErrInvalidConfig", err)
	}
	if _, err := DecryptWithResolver(token, KeyResolverFunc(func(context.Context, Header) (*Key, error) {
		return nil, nil
	}), DecryptOptions{}); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("nil key resolver result err = %v, want ErrKeyNotFound", err)
	}
	boom := errors.New("resolver unavailable")
	if _, err := DecryptWithResolver(token, KeyResolverFunc(func(context.Context, Header) (*Key, error) {
		return nil, boom
	}), DecryptOptions{}); !errors.Is(err, boom) {
		t.Fatalf("resolver error err = %v, want %v", err, boom)
	}
}

// TestJWEJSONRFC7516Vectors decrypts the RFC 7516 Appendix A.4 general and A.5 flattened vectors. |
// TestJWEJSONRFC7516Vectors 解密 RFC 7516 附录 A.4 通用与 A.5 扁平向量。
func TestJWEJSONRFC7516Vectors(t *testing.T) {
	want := []byte("Live long and prosper.")
	rsaKey, err := ParseKey([]byte(rfc7516A4JWK))
	if err != nil {
		t.Fatalf("ParseKey(RSA) failed: %v", err)
	}
	octKey, err := ParseKey([]byte(rfc7516A3OctJWK))
	if err != nil {
		t.Fatalf("ParseKey(oct) failed: %v", err)
	}
	for _, tc := range []struct {
		name  string
		token string
		key   *Key
		opts  DecryptOptions
	}{
		{"A.4/RSA1_5", rfc7516A4JWE, rsaKey, DecryptOptions{AllowRSA1_5: true}},
		{"A.4/A128KW", rfc7516A4JWE, octKey, DecryptOptions{}},
		{"A.5/A128KW", rfc7516A5JWE, octKey, DecryptOptions{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Decrypt(tc.token, tc.key, tc.opts)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("plaintext = %q, want %q", got, want)
			}
		})
	}
	// The RSA1_5 recipient must still require explicit opt-in for the known vector.
	if _, err := Decrypt(rfc7516A4JWE, rsaKey, DecryptOptions{}); !errors.Is(err, ErrAlgNotAllowed) {
		t.Fatalf("A.4 without RSA1_5 opt-in err = %v, want ErrAlgNotAllowed", err)
	}
}

// TestJWEJSONTokenSizeLimit applies the pre-decode size bound to JSON serializations. |
// TestJWEJSONTokenSizeLimit 对 JSON 序列化应用解码前大小上限。
func TestJWEJSONTokenSizeLimit(t *testing.T) {
	key := testOctKey(t, 16)
	token := mustEncryptJWEJSON(t, []byte("size | 大小"), key, EncryptOptions{
		Alg: AlgDir, Enc: EncA128GCM, Serialization: SerializationFlattened,
	})
	if _, err := Decrypt(token, key, DecryptOptions{MaxTokenSize: len(token)}); err != nil {
		t.Fatalf("Decrypt at exact limit failed: %v", err)
	}
	if _, err := Decrypt(token, key, DecryptOptions{MaxTokenSize: len(token) - 1}); !errors.Is(err, ErrTokenTooLarge) {
		t.Fatalf("Decrypt over limit err = %v, want ErrTokenTooLarge", err)
	}
	if _, err := DecryptWithResolver(token, KeySetResolver(&KeySet{Keys: []*Key{key}}), DecryptOptions{MaxTokenSize: len(token) - 1}); !errors.Is(err, ErrTokenTooLarge) {
		t.Fatalf("DecryptWithResolver over limit err = %v, want ErrTokenTooLarge", err)
	}
}

// TestJWEJSONConcurrent exercises concurrent JSON encryption and decryption under the race
// detector. | TestJWEJSONConcurrent 在竞态检测器下并发执行 JSON 加解密。
func TestJWEJSONConcurrent(t *testing.T) {
	keyOne := testOctKey(t, 32)
	keyTwo := testOctKey(t, 32)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			plaintext := []byte(strings.Repeat("concurrent | 并发", i+1))
			token, err := Encrypt(plaintext, nil, EncryptOptions{
				Enc:           EncA256GCM,
				Serialization: SerializationGeneral,
				Recipients: []Recipient{
					{Key: keyOne, Alg: AlgA256KW, Kid: "one"},
					{Key: keyTwo, Alg: AlgA256KW, Kid: "two"},
				},
				AAD: []byte("concurrent aad"),
			})
			if err != nil {
				t.Errorf("Encrypt failed: %v", err)
				return
			}
			got, err := Decrypt(token, keyTwo, DecryptOptions{})
			if err != nil {
				t.Errorf("Decrypt failed: %v", err)
				return
			}
			if !bytes.Equal(got, plaintext) {
				t.Errorf("plaintext mismatch: %q", got)
			}
		}()
	}
	wg.Wait()
}
