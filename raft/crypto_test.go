package raft

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
)

// testEncryptionKey returns an obviously fixed key for a suite. | testEncryptionKey
// 返回某个套件使用的明显固定测试密钥。
func testEncryptionKey(suite EncryptionSuite, b byte) []byte {
	if suite == EncryptionSM4GCM {
		return bytes.Repeat([]byte{b}, 16)
	}
	return bytes.Repeat([]byte{b}, 32)
}

// testSuites lists the suites exercised by the one-shot and streaming tests. |
// testSuites 列出一次性与流式测试覆盖的套件。
func testSuites() []EncryptionSuite {
	return []EncryptionSuite{EncryptionAES256GCM, EncryptionChaCha20Poly1305, EncryptionSM4GCM}
}

// TestEncryptorOneShotRoundTrip verifies every suite seals and opens with AAD,
// and rejects a wrong AAD, a tampered tag and a different key under the same ID.
// | TestEncryptorOneShotRoundTrip 验证每种套件带 AAD 的封装与解密，并拒绝错误 AAD、
// 被篡改的标签以及同一 ID 下的不同密钥。
func TestEncryptorOneShotRoundTrip(t *testing.T) {
	plain := []byte("raft one-shot payload | raft 一次性负载")
	aad := []byte("tenant=alpha")
	for _, suite := range testSuites() {
		t.Run(suite.String(), func(t *testing.T) {
			enc, err := NewEncryptor(EncryptionOptions{
				Keys: []EncryptionKey{{ID: 7, Suite: suite, Bytes: testEncryptionKey(suite, 0x11)}},
			})
			if err != nil {
				t.Fatal(err)
			}
			sealed, err := enc.Encrypt(nil, plain, aad)
			if err != nil {
				t.Fatal(err)
			}
			if string(sealed[:8]) != encryptionEnvelopeMagic {
				t.Fatalf("envelope magic = %q", sealed[:8])
			}
			if got := binary.LittleEndian.Uint32(sealed[9:13]); got != 7 {
				t.Fatalf("envelope key ID = %d, want 7", got)
			}
			opened, err := enc.Decrypt(nil, sealed, aad)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(opened, plain) {
				t.Fatalf("round trip = %q", opened)
			}
			if _, err := enc.Decrypt(nil, sealed, []byte("tenant=beta")); !errors.Is(err, ErrAuth) {
				t.Fatalf("wrong AAD error = %v, want ErrAuth", err)
			}
			tampered := append([]byte(nil), sealed...)
			tampered[len(tampered)-1] ^= 0xff
			if _, err := enc.Decrypt(nil, tampered, aad); !errors.Is(err, ErrAuth) {
				t.Fatalf("tampered error = %v, want ErrAuth", err)
			}
			if _, err := enc.Decrypt(nil, sealed[:encryptionHeaderSize+encryptionTagSize-1], aad); !errors.Is(err, ErrAuth) {
				t.Fatalf("short envelope error = %v, want ErrAuth", err)
			}
			wrong, err := NewEncryptor(EncryptionOptions{
				Keys: []EncryptionKey{{ID: 7, Suite: suite, Bytes: testEncryptionKey(suite, 0x22)}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := wrong.Decrypt(nil, sealed, aad); !errors.Is(err, ErrAuth) {
				t.Fatalf("wrong key error = %v, want ErrAuth", err)
			}
		})
	}
}

// TestEncryptorKeyRotation verifies an envelope carries its key ID and any key
// left in the ring can open old ciphertext. | TestEncryptorKeyRotation 验证信封携带
// 密钥 ID，且密钥环中保留的任意旧密钥都能解开旧密文。
func TestEncryptorKeyRotation(t *testing.T) {
	keys := []EncryptionKey{
		{ID: 1, Suite: EncryptionAES256GCM, Bytes: testEncryptionKey(EncryptionAES256GCM, 0x31)},
		{ID: 2, Suite: EncryptionSM4GCM, Bytes: testEncryptionKey(EncryptionSM4GCM, 0x32)},
	}
	first, err := NewEncryptor(EncryptionOptions{Keys: keys, ActiveKeyID: 1})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewEncryptor(EncryptionOptions{Keys: keys, ActiveKeyID: 2})
	if err != nil {
		t.Fatal(err)
	}
	if first.ActiveKeyID() != 1 || second.ActiveKeyID() != 2 {
		t.Fatalf("active IDs = %d/%d", first.ActiveKeyID(), second.ActiveKeyID())
	}
	if first.ActiveSuite() != EncryptionAES256GCM || second.ActiveSuite() != EncryptionSM4GCM {
		t.Fatalf("active suites = %s/%s", first.ActiveSuite(), second.ActiveSuite())
	}
	if first.ChunkSize() != defaultEncryptionChunkSize {
		t.Fatalf("chunk size = %d, want %d", first.ChunkSize(), defaultEncryptionChunkSize)
	}
	oldCipher, err := first.Encrypt(nil, []byte("old"), nil)
	if err != nil {
		t.Fatal(err)
	}
	newCipher, err := second.Encrypt(nil, []byte("new"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range []struct {
		enc  *Encryptor
		data []byte
		want uint32
	}{
		{second, oldCipher, 1},
		{first, newCipher, 2},
	} {
		opened, err := pair.enc.Decrypt(nil, pair.data, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := binary.LittleEndian.Uint32(pair.data[9:13]); got != pair.want {
			t.Fatalf("envelope key ID = %d, want %d", got, pair.want)
		}
		if string(opened) == "" {
			t.Fatal("empty plaintext")
		}
	}
	rotated, err := first.WithActiveKey(2)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.ActiveKeyID() != 2 {
		t.Fatalf("rotated active ID = %d, want 2", rotated.ActiveKeyID())
	}
	rotatedCipher, err := rotated.Encrypt(nil, []byte("rotated"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Decrypt(nil, rotatedCipher, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := first.WithActiveKey(9); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("missing rotation key error = %v, want ErrKeyNotFound", err)
	}
}

// TestEncryptorKeyValidation verifies unusable rings are rejected. |
// TestEncryptorKeyValidation 验证不可用的密钥环会被拒绝。
func TestEncryptorKeyValidation(t *testing.T) {
	valid := EncryptionKey{ID: 1, Suite: EncryptionAES256GCM, Bytes: testEncryptionKey(EncryptionAES256GCM, 1)}
	cases := []struct {
		name string
		opts EncryptionOptions
		want error
	}{
		{"empty", EncryptionOptions{}, ErrInvalidKey},
		{"zero-id", EncryptionOptions{Keys: []EncryptionKey{{ID: 0, Suite: EncryptionAES256GCM, Bytes: valid.Bytes}}}, ErrInvalidKey},
		{"duplicate", EncryptionOptions{Keys: []EncryptionKey{valid, valid}}, ErrInvalidKey},
		{"short", EncryptionOptions{Keys: []EncryptionKey{{ID: 1, Suite: EncryptionAES256GCM, Bytes: []byte("short")}}}, ErrInvalidKey},
		{"unknown-suite", EncryptionOptions{Keys: []EncryptionKey{{ID: 1, Suite: EncryptionSuite(9), Bytes: valid.Bytes}}}, ErrInvalidKey},
		{"missing-active", EncryptionOptions{Keys: []EncryptionKey{valid}, ActiveKeyID: 9}, ErrKeyNotFound},
		{"bad-chunk", EncryptionOptions{Keys: []EncryptionKey{valid}, ChunkSize: maxEncryptionChunkSize + 1}, ErrInvalidConfig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewEncryptor(tc.opts); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestEncryptorConcurrent verifies one Encryptor is safe for concurrent use. |
// TestEncryptorConcurrent 验证单个 Encryptor 可安全并发使用。
func TestEncryptorConcurrent(t *testing.T) {
	enc, err := NewEncryptor(EncryptionOptions{
		Keys: []EncryptionKey{{ID: 1, Suite: EncryptionAES256GCM, Bytes: testEncryptionKey(EncryptionAES256GCM, 3)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			plain := bytes.Repeat([]byte{byte(n)}, 256)
			for j := 0; j < 64; j++ {
				sealed, err := enc.Encrypt(nil, plain, nil)
				if err != nil {
					t.Errorf("encrypt: %v", err)
					return
				}
				opened, err := enc.Decrypt(nil, sealed, nil)
				if err != nil {
					t.Errorf("decrypt: %v", err)
					return
				}
				if !bytes.Equal(opened, plain) {
					t.Errorf("round trip mismatch")
					return
				}
			}
		}(i)
	}
	wg.Wait()
}
