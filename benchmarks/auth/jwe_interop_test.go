package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	gojose "github.com/go-jose/go-jose/v4"
	ydjose "github.com/shibingli/ydx/auth/token/jose"
)

// TestJWEInteropWithGoJose checks compact JWE in both directions with RSA-OAEP + A256GCM. |
// TestJWEInteropWithGoJose 检查 RSA-OAEP + A256GCM 紧凑 JWE 的双向兼容性。
func TestJWEInteropWithGoJose(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ydPriv, err := ydjose.FromPrivateKey("rsa-1", priv)
	if err != nil {
		t.Fatalf("FromPrivateKey: %v", err)
	}
	ydPub, err := ydjose.FromPublicKey("rsa-1", &priv.PublicKey)
	if err != nil {
		t.Fatalf("FromPublicKey: %v", err)
	}
	plaintext := []byte(`{"sub":"alice","secret":"benchmark"}`)

	t.Run("ydx-to-go-jose", func(t *testing.T) {
		token, err := ydjose.Encrypt(plaintext, ydPub, ydjose.EncryptOptions{Alg: "RSA-OAEP", Enc: "A256GCM"})
		if err != nil {
			t.Fatalf("ydx Encrypt: %v", err)
		}
		object, err := gojose.ParseEncrypted(token, []gojose.KeyAlgorithm{gojose.RSA_OAEP}, []gojose.ContentEncryption{gojose.A256GCM})
		if err != nil {
			t.Fatalf("go-jose ParseEncrypted: %v", err)
		}
		got, err := object.Decrypt(priv)
		if err != nil {
			t.Fatalf("go-jose Decrypt: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("plaintext mismatch: %q", got)
		}
	})

	t.Run("go-jose-to-ydx", func(t *testing.T) {
		encrypter, err := gojose.NewEncrypter(gojose.A256GCM, gojose.Recipient{Algorithm: gojose.RSA_OAEP, Key: &priv.PublicKey}, nil)
		if err != nil {
			t.Fatalf("go-jose NewEncrypter: %v", err)
		}
		object, err := encrypter.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("go-jose Encrypt: %v", err)
		}
		token, err := object.CompactSerialize()
		if err != nil {
			t.Fatalf("go-jose CompactSerialize: %v", err)
		}
		got, err := ydjose.Decrypt(token, ydPriv, ydjose.DecryptOptions{})
		if err != nil {
			t.Fatalf("ydx Decrypt: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("plaintext mismatch: %q", got)
		}
	})
}
