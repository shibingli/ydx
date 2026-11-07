package xmlsig

import (
	"bytes"
	"errors"
	"testing"
)

// TestEncryptionRoundTrips covers every data-encryption algorithm with a direct content key. |
// TestEncryptionRoundTrips 使用直接内容密钥覆盖所有数据加密算法。
func TestEncryptionRoundTrips(t *testing.T) {
	plaintext := []byte("confidential payload \x00 with binary \xff bytes")
	keys := map[string][]byte{
		encAES128CBCURI: bytes.Repeat([]byte{0x11}, 16),
		encAES192CBCURI: bytes.Repeat([]byte{0x22}, 24),
		encAES256CBCURI: bytes.Repeat([]byte{0x33}, 32),
		encAES128GCMURI: bytes.Repeat([]byte{0x44}, 16),
		encAES192GCMURI: bytes.Repeat([]byte{0x55}, 24),
		encAES256GCMURI: bytes.Repeat([]byte{0x66}, 32),
		encSM4CBCURI:    bytes.Repeat([]byte{0x77}, 16),
		encSM4GCMURI:    bytes.Repeat([]byte{0x88}, 16),
	}
	for algorithm, key := range keys {
		t.Run(algorithm, func(t *testing.T) {
			encrypted, err := Encrypt(plaintext, key, EncryptOptions{Algorithm: algorithm})
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if bytes.Contains(encrypted, plaintext) {
				t.Fatal("ciphertext contains plaintext")
			}
			decrypted, err := Decrypt(encrypted, key, DecryptOptions{})
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("round trip mismatch: %q", decrypted)
			}
		})
	}
}

// TestRSAKeyTransport covers OAEP variants and the RSA1_5 opt-in. | TestRSAKeyTransport 覆盖 OAEP
// 变体与 RSA1_5 显式启用。
func TestRSAKeyTransport(t *testing.T) {
	key := testRSAPrivateKey(t)
	plaintext := []byte("rsa transported content key")
	cases := []struct {
		name       string
		transport  string
		allowRSA15 bool
	}{
		{name: "oaep-sha256", transport: encRSAOAEP11URI},
		{name: "oaep-sha1", transport: encRSAOAEPURI},
		{name: "rsa1_5", transport: encRSA15URI, allowRSA15: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encrypted, err := Encrypt(plaintext, &key.PublicKey, EncryptOptions{
				Algorithm:    encAES256GCMURI,
				KeyTransport: tc.transport,
				AllowRSA1_5:  tc.allowRSA15,
			})
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if tc.transport == encRSA15URI {
				if _, err := Decrypt(encrypted, key, DecryptOptions{}); !errors.Is(err, ErrAlgorithmNotAllowed) {
					t.Fatalf("RSA1_5 default error = %v, want ErrAlgorithmNotAllowed", err)
				}
			}
			decrypted, err := Decrypt(encrypted, key, DecryptOptions{AllowRSA1_5: tc.allowRSA15})
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("round trip mismatch: %q", decrypted)
			}
		})
	}

	if _, err := Encrypt(plaintext, &key.PublicKey, EncryptOptions{KeyTransport: encRSA15URI}); !errors.Is(err, ErrAlgorithmNotAllowed) {
		t.Fatalf("RSA1_5 encryption error = %v, want ErrAlgorithmNotAllowed", err)
	}
}

// TestAESKeyWrap covers explicit and inferred AES key wrap. | TestAESKeyWrap 覆盖显式与推断的 AES
// 密钥包装。
func TestAESKeyWrap(t *testing.T) {
	kek := bytes.Repeat([]byte{0x9a}, 32)
	plaintext := []byte("wrapped content key payload")
	encrypted, err := Encrypt(plaintext, kek, EncryptOptions{Algorithm: encAES256GCMURI, KeyWrap: encAES256KWURI})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	decrypted, err := Decrypt(encrypted, kek, DecryptOptions{})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("round trip mismatch: %q", decrypted)
	}

	// A KEK whose length differs from the data key length is inferred as a wrapping key. | KEK
	// 长度与数据密钥长度不同时按包装密钥处理。
	encrypted, err = Encrypt(plaintext, kek, EncryptOptions{Algorithm: encAES128GCMURI})
	if err != nil {
		t.Fatalf("Encrypt inferred wrap: %v", err)
	}
	decrypted, err = Decrypt(encrypted, kek, DecryptOptions{})
	if err != nil {
		t.Fatalf("Decrypt inferred wrap: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("inferred wrap mismatch: %q", decrypted)
	}

	wrong := bytes.Repeat([]byte{0x01}, 16)
	if _, err := Decrypt(encrypted, wrong, DecryptOptions{}); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("wrong KEK error = %v, want ErrKeyMismatch", err)
	}
}

// TestSM2KeyTransport covers SM2 key transport. | TestSM2KeyTransport 覆盖 SM2 密钥传输。
func TestSM2KeyTransport(t *testing.T) {
	key := testSM2Key(t)
	plaintext := []byte("sm2 transported content key")
	encrypted, err := Encrypt(plaintext, key.Public(), EncryptOptions{Algorithm: encSM4GCMURI})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	decrypted, err := Decrypt(encrypted, key, DecryptOptions{})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("round trip mismatch: %q", decrypted)
	}
	other := testSM2Key(t)
	if _, err := Decrypt(encrypted, other, DecryptOptions{}); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong SM2 key error = %v, want ErrDecrypt", err)
	}
}

// TestEncryptDecryptElement covers element replacement and restoration. |
// TestEncryptDecryptElement 覆盖元素替换与还原。
func TestEncryptDecryptElement(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	doc := []byte(`<root xmlns:p="urn:p"><p:secret ID="s1">hello &amp; bye</p:secret><keep>k</keep></root>`)
	encrypted, err := EncryptElement(doc, "s1", key, EncryptOptions{Algorithm: encAES256GCMURI, ID: "ed1"})
	if err != nil {
		t.Fatalf("EncryptElement: %v", err)
	}
	if !bytes.Contains(encrypted, []byte("EncryptedData")) || !bytes.Contains(encrypted, []byte(`Id="ed1"`)) {
		t.Fatalf("unexpected encrypted document: %s", encrypted)
	}
	if bytes.Contains(encrypted, []byte("hello")) {
		t.Fatalf("plaintext survived encryption: %s", encrypted)
	}
	decrypted, err := DecryptElement(encrypted, key, DecryptOptions{})
	if err != nil {
		t.Fatalf("DecryptElement: %v", err)
	}
	if !bytes.Contains(decrypted, []byte("p:secret")) || !bytes.Contains(decrypted, []byte("hello &amp; bye")) {
		t.Fatalf("decrypted element missing content: %s", decrypted)
	}
	if !bytes.Contains(decrypted, []byte("<keep>k</keep>")) {
		t.Fatalf("sibling element was lost: %s", decrypted)
	}
}

// TestExternalEncryptedKey uses a ReferenceList to bind an EncryptedKey outside EncryptedData. |
// TestExternalEncryptedKey 使用 ReferenceList 绑定 EncryptedData 之外的 EncryptedKey。
func TestExternalEncryptedKey(t *testing.T) {
	key := testRSAPrivateKey(t)
	plaintext := []byte("external key reference payload")
	encrypted, err := Encrypt(plaintext, &key.PublicKey, EncryptOptions{Algorithm: encAES256GCMURI, ID: "ed1"})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	doc, err := parseXML(encrypted)
	if err != nil {
		t.Fatalf("parseXML: %v", err)
	}
	keyInfo := doc.root.childByLocal("KeyInfo")
	if keyInfo == nil {
		t.Fatal("EncryptedData has no KeyInfo")
	}
	var encryptedKey *xmlNode
	kept := keyInfo.children[:0]
	for _, child := range keyInfo.children {
		if child.kind == elementNode && child.local == "EncryptedKey" && encryptedKey == nil {
			encryptedKey = child
			continue
		}
		kept = append(kept, child)
	}
	keyInfo.children = kept

	wrapper := newElement("", "root")
	wrapper.addNamespaceDecl("xenc", NamespaceXMLEnc)
	wrapper.addNamespaceDecl("ds", NamespaceXMLDSig)
	wrapper.appendChild(doc.root)
	wrapper.appendChild(encryptedKey)
	out := serializeDocument(&xmlDocument{children: []*xmlNode{wrapper}, root: wrapper})

	decrypted, err := Decrypt(out, key, DecryptOptions{})
	if err != nil {
		t.Fatalf("Decrypt external key: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("round trip mismatch: %q", decrypted)
	}
}

// TestDecryptRejections checks CipherReference, ambiguity, allowlists and tampering. |
// TestDecryptRejections 校验 CipherReference、歧义、允许列表与篡改。
func TestDecryptRejections(t *testing.T) {
	key := bytes.Repeat([]byte{0x24}, 32)
	cipherReference := `<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Id="e1">` +
		`<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>` +
		`<xenc:CipherData><xenc:CipherReference URI="http://example.com/cipher"/></xenc:CipherData>` +
		`</xenc:EncryptedData>`
	if _, err := Decrypt([]byte(cipherReference), key, DecryptOptions{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("CipherReference error = %v, want ErrUnsupported", err)
	}

	plaintext := []byte("allowlist payload")
	encrypted, err := Encrypt(plaintext, key, EncryptOptions{Algorithm: encAES256GCMURI})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := Decrypt(encrypted, key, DecryptOptions{AllowedAlgorithms: []string{encAES128GCMURI}}); !errors.Is(err, ErrAlgorithmNotAllowed) {
		t.Fatalf("algorithm allowlist error = %v, want ErrAlgorithmNotAllowed", err)
	}

	doc, err := parseXML([]byte(`<root>` + string(encrypted) + string(encrypted) + `</root>`))
	if err != nil {
		t.Fatalf("parseXML: %v", err)
	}
	if _, err := Decrypt(serializeDocument(doc), key, DecryptOptions{}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("ambiguous EncryptedData error = %v, want ErrMalformed", err)
	}

	tampered := append([]byte(nil), encrypted...)
	index := bytes.Index(tampered, []byte("<xenc:CipherValue>"))
	if index < 0 {
		t.Fatal("CipherValue not found")
	}
	index += len("<xenc:CipherValue>")
	if tampered[index] == 'A' {
		tampered[index] = 'B'
	} else {
		tampered[index] = 'A'
	}
	if _, err := Decrypt(tampered, key, DecryptOptions{}); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("tampered ciphertext error = %v, want ErrDecrypt", err)
	}

	if _, err := Encrypt(make([]byte, 32), key, EncryptOptions{MaxBytes: 16}); !errors.Is(err, ErrLimit) {
		t.Fatalf("MaxBytes error = %v, want ErrLimit", err)
	}
}

// TestRSAKeyTransportAllowlist checks the key-transport allowlist. | TestRSAKeyTransportAllowlist
// 校验密钥传输允许列表。
func TestRSAKeyTransportAllowlist(t *testing.T) {
	key := testRSAPrivateKey(t)
	encrypted, err := Encrypt([]byte("transport allowlist"), &key.PublicKey, EncryptOptions{Algorithm: encAES256GCMURI})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := Decrypt(encrypted, key, DecryptOptions{AllowedKeyTransports: []string{encAES128KWURI}}); !errors.Is(err, ErrAlgorithmNotAllowed) {
		t.Fatalf("key transport allowlist error = %v, want ErrAlgorithmNotAllowed", err)
	}
}
