package kerberos

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// mustHex decodes a hex string or fails the test. | mustHex 解码十六进制字符串，失败时终止测试。
func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("invalid test hex %q: %v", value, err)
	}
	return decoded
}

// TestNFoldVectors verifies the RFC 3961 Appendix A n-fold vectors. | TestNFoldVectors
// 校验 RFC 3961 附录 A 的 n-fold 向量。
func TestNFoldVectors(t *testing.T) {
	tests := []struct {
		input string
		size  int
		want  string
	}{
		{"012345", 8, "be072631276b1955"},
		{"password", 7, "78a07b6caf85fa"},
		{"Rough Consensus, and Running Code", 8, "bb6ed30870b7f0e0"},
		{"password", 21, "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e"},
		{"MASSACHVSETTS INSTITVTE OF TECHNOLOGY", 24, "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b"},
		{"Q", 21, "518a54a215a8452a518a54a215a8452a518a54a215"},
		{"ba", 21, "fb25d531ae8974499f52fd92ea9857c4ba24cf297e"},
		{"kerberos", 8, "6b65726265726f73"},
		{"kerberos", 16, "6b65726265726f737b9b5b2b93132b93"},
		{"kerberos", 21, "8372c236344e5f1550cd0747e15d62ca7a5a3bcea4"},
		{"kerberos", 32, "6b65726265726f737b9b5b2b93132b935c9bdcdad95c9899c4cae4dee6d6cae4"},
	}
	for _, test := range tests {
		got := nfold([]byte(test.input), test.size)
		want := mustHex(t, test.want)
		if !bytes.Equal(got, want) {
			t.Errorf("nfold(%q, %d) = %x, want %x", test.input, test.size, got, want)
		}
	}
	if got := nfold(nil, 8); got != nil {
		t.Errorf("nfold(nil) = %x, want nil", got)
	}
	if got := nfold([]byte("x"), 0); got != nil {
		t.Errorf("nfold(size 0) = %x, want nil", got)
	}
}

// TestStringToKeyRFC3962 verifies the RFC 3962 Appendix B PBKDF2 vectors. |
// TestStringToKeyRFC3962 校验 RFC 3962 附录 B 的 PBKDF2 向量。
func TestStringToKeyRFC3962(t *testing.T) {
	tests := []struct {
		name       string
		password   string
		salt       string
		iterations int
		etype      int32
		want       string
	}{
		{"iterations 1 aes128", "password", "ATHENA.MIT.EDUraeburn", 1, ETypeAES128CTS, "42263c6e89f4fc28b8df68ee09799f15"},
		{"iterations 1 aes256", "password", "ATHENA.MIT.EDUraeburn", 1, ETypeAES256CTS, "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161"},
		{"iterations 2 aes128", "password", "ATHENA.MIT.EDUraeburn", 2, ETypeAES128CTS, "c651bf29e2300ac27fa469d693bdda13"},
		{"iterations 2 aes256", "password", "ATHENA.MIT.EDUraeburn", 2, ETypeAES256CTS, "a2e16d16b36069c135d5e9d2e25f896102685618b95914b467c67622225824ff"},
		{"iterations 1200 aes128", "password", "ATHENA.MIT.EDUraeburn", 1200, ETypeAES128CTS, "4c01cd46d632d01e6dbe230a01ed642a"},
		{"iterations 1200 aes256", "password", "ATHENA.MIT.EDUraeburn", 1200, ETypeAES256CTS, "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a"},
		{"iterations 5 aes128", "password", string([]byte{0x12, 0x34, 0x56, 0x78, 0x78, 0x56, 0x34, 0x12}), 5, ETypeAES128CTS, "e9b23d52273747dd5c35cb55be619d8e"},
		{"iterations 5 aes256", "password", string([]byte{0x12, 0x34, 0x56, 0x78, 0x78, 0x56, 0x34, 0x12}), 5, ETypeAES256CTS, "97a4e786be20d81a382d5ebc96d5909cabcdadc87ca48f574504159f16c36e31"},
		{"64 bytes aes128", "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "pass phrase equals block size", 1200, ETypeAES128CTS, "59d1bb789a828b1aa54ef9c2883f69ed"},
		{"64 bytes aes256", "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "pass phrase equals block size", 1200, ETypeAES256CTS, "89adee3608db8bc71f1bfbfe459486b05618b70cbae22092534e56c553ba4b34"},
		{"65 bytes aes128", "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "pass phrase exceeds block size", 1200, ETypeAES128CTS, "cb8005dc5f90179a7f02104c0018751d"},
		{"65 bytes aes256", "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "pass phrase exceeds block size", 1200, ETypeAES256CTS, "d78c5c9cb872a8c9dad4697f0bb5b2d21496c82beb2caeda2112fceea057401b"},
		{"g-clef aes128", "\U0001D11E", "EXAMPLE.COMpianist", 50, ETypeAES128CTS, "f149c1f2e154a73452d43e7fe62a56e5"},
		{"g-clef aes256", "\U0001D11E", "EXAMPLE.COMpianist", 50, ETypeAES256CTS, "4b6d9839f84406df1f09cc166db4b83c571848b784a3d6bdc346589a3e393f9e"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, err := StringToKey(test.password, test.salt, test.iterations, test.etype)
			if err != nil {
				t.Fatalf("StringToKey: %v", err)
			}
			if want := mustHex(t, test.want); !bytes.Equal(key, want) {
				t.Fatalf("key = %x, want %x", key, want)
			}
		})
	}
}

// TestStringToKeyRC4 verifies the RFC 4757 password-to-key example. |
// TestStringToKeyRC4 校验 RFC 4757 的口令转密钥示例。
func TestStringToKeyRC4(t *testing.T) {
	key, err := StringToKey("foo", "ignored", 1, ETypeRC4HMAC)
	if err != nil {
		t.Fatalf("StringToKey: %v", err)
	}
	if want := mustHex(t, "ac8e657f83df82beea5d43bdaf7800cc"); !bytes.Equal(key, want) {
		t.Fatalf("key = %x, want %x", key, want)
	}
	if _, err := StringToKey("foo", "", 1, 99); err == nil {
		t.Fatal("StringToKey accepted an unsupported enctype")
	}
}

// TestAESCTSVectors verifies the RFC 3962 Appendix B AES-CTS vectors. |
// TestAESCTSVectors 校验 RFC 3962 附录 B 的 AES-CTS 向量。
func TestAESCTSVectors(t *testing.T) {
	key := mustHex(t, "636869636b656e207465726979616b69")
	tests := []struct {
		name      string
		plaintext string
		want      string
	}{
		{"17 bytes", "4920776f756c64206c696b652074686520", "c6353568f2bf8cb4d8a580362da7ff7f97"},
		{"31 bytes", "4920776f756c64206c696b65207468652047656e6572616c20476175277320", "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5"},
		{"32 bytes", "4920776f756c64206c696b65207468652047656e6572616c2047617527732043", "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584"},
		{"47 bytes", "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c", "97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5"},
		{"48 bytes", "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20", "97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd839312523a78662d5be7fcbcc98ebf5a8"},
		{"64 bytes", "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20616e6420776f6e746f6e20736f75702e", "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a84807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plaintext := mustHex(t, test.plaintext)
			ciphertext, err := aesCTSEncrypt(key, plaintext)
			if err != nil {
				t.Fatalf("aesCTSEncrypt: %v", err)
			}
			want := mustHex(t, test.want)
			if !bytes.Equal(ciphertext, want) {
				t.Fatalf("ciphertext = %x, want %x", ciphertext, want)
			}
			decrypted, err := aesCTSDecrypt(key, ciphertext)
			if err != nil {
				t.Fatalf("aesCTSDecrypt: %v", err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("decrypted = %x, want %x", decrypted, plaintext)
			}
		})
	}
}

// TestAESMessageRoundTrip verifies RFC 3962 message encryption for both AES key
// sizes. | TestAESMessageRoundTrip 校验两种 AES 密钥尺寸下的 RFC 3962 消息加密。
func TestAESMessageRoundTrip(t *testing.T) {
	for _, etype := range []int32{ETypeAES128CTS, ETypeAES256CTS} {
		t.Run(itoa(int(etype)), func(t *testing.T) {
			size, err := KeySize(etype)
			if err != nil {
				t.Fatalf("KeySize: %v", err)
			}
			key := bytes.Repeat([]byte{byte(etype)}, size)
			for _, plaintext := range [][]byte{{}, []byte("a"), bytes.Repeat([]byte{0x42}, 16), bytes.Repeat([]byte{0x43}, 37)} {
				ciphertext, err := EncryptMessage(etype, key, 3, plaintext)
				if err != nil {
					t.Fatalf("EncryptMessage: %v", err)
				}
				decrypted, err := DecryptMessage(etype, key, 3, ciphertext)
				if err != nil {
					t.Fatalf("DecryptMessage: %v", err)
				}
				if !bytes.Equal(decrypted, plaintext) {
					t.Fatalf("decrypted = %x, want %x", decrypted, plaintext)
				}
				if _, err := DecryptMessage(etype, key, 4, ciphertext); err == nil {
					t.Fatal("DecryptMessage accepted a different key usage")
				}
				tampered := append([]byte(nil), ciphertext...)
				tampered[len(tampered)-1] ^= 0x01
				if _, err := DecryptMessage(etype, key, 3, tampered); err == nil {
					t.Fatal("DecryptMessage accepted a tampered tag")
				}
			}
		})
	}
}

// TestRC4MessageRoundTrip verifies RFC 4757 message encryption. |
// TestRC4MessageRoundTrip 校验 RFC 4757 消息加密。
func TestRC4MessageRoundTrip(t *testing.T) {
	key := mustHex(t, "ac8e657f83df82beea5d43bdaf7800cc")
	for _, usage := range []uint32{1, 3, 8, 11, 12, 22, 23, 24, 25} {
		plaintext := []byte("rc4-hmac protected payload for usage")
		ciphertext, err := EncryptMessage(ETypeRC4HMAC, key, usage, plaintext)
		if err != nil {
			t.Fatalf("EncryptMessage usage %d: %v", usage, err)
		}
		decrypted, err := DecryptMessage(ETypeRC4HMAC, key, usage, ciphertext)
		if err != nil {
			t.Fatalf("DecryptMessage usage %d: %v", usage, err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("usage %d: decrypted = %x, want %x", usage, decrypted, plaintext)
		}
		if _, err := DecryptMessage(ETypeRC4HMAC, key, usage+100, ciphertext); err == nil {
			t.Fatalf("usage %d: decryption accepted a different usage", usage)
		}
	}
	translated := map[uint32]uint32{3: 8, 9: 8, 23: 13, 7: 7}
	for usage, want := range translated {
		if got := rc4Usage(usage); got != want {
			t.Errorf("rc4Usage(%d) = %d, want %d", usage, got, want)
		}
	}
}

// TestChecksumRoundTrip verifies keyed checksums for all implemented enctypes. |
// TestChecksumRoundTrip 校验所有已实现加密类型的带密钥校验和。
func TestChecksumRoundTrip(t *testing.T) {
	for _, etype := range SupportedETypes() {
		size, err := KeySize(etype)
		if err != nil {
			t.Fatalf("KeySize: %v", err)
		}
		key := bytes.Repeat([]byte{byte(etype + 1)}, size)
		data := []byte("checksum input")
		checksum, err := ChecksumMessage(etype, key, 6, data)
		if err != nil {
			t.Fatalf("ChecksumMessage(%d): %v", etype, err)
		}
		if err := VerifyChecksum(etype, key, 6, data, checksum); err != nil {
			t.Fatalf("VerifyChecksum(%d): %v", etype, err)
		}
		if err := VerifyChecksum(etype, key, 7, data, checksum); err == nil {
			t.Fatalf("VerifyChecksum(%d) accepted a different usage", etype)
		}
		tampered := append([]byte(nil), checksum...)
		tampered[0] ^= 0x80
		if err := VerifyChecksum(etype, key, 6, data, tampered); err == nil {
			t.Fatalf("VerifyChecksum(%d) accepted a modified checksum", etype)
		}
	}
}
