package jose

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
	"sync"
	"testing"
)

// b64Bytes encodes raw as an unpadded base64url member. | b64Bytes 把 raw 编码为无填充 base64url 成员。
func b64Bytes(raw ...byte) string { return EncodeSegment(raw) }

// TestNilKeyAndUnsupportedKty covers the nil receiver and unknown key type paths. | TestNilKeyAndUnsupportedKty
// 覆盖 nil 接收者与未知密钥类型路径。
func TestNilKeyAndUnsupportedKty(t *testing.T) {
	var nilKey *Key
	if _, err := nilKey.PrivateKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("nil PrivateKey err = %v", err)
	}
	if _, err := nilKey.PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("nil PublicKey err = %v", err)
	}
	if _, err := nilKey.Thumbprint(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("nil Thumbprint err = %v", err)
	}
	if err := nilKey.Validate(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("nil Validate err = %v", err)
	}
	if nilKey.Clone() != nil || nilKey.Public() != nil {
		t.Error("nil Clone/Public 未返回 nil")
	}
	if err := checkKeyAlg(nil, "HS256"); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("checkKeyAlg(nil) err = %v", err)
	}

	bogus := &Key{Kty: "bogus"}
	if _, err := bogus.PrivateKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("bogus PrivateKey err = %v", err)
	}
	if _, err := bogus.PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("bogus PublicKey err = %v", err)
	}
	if err := bogus.Validate(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("bogus Validate err = %v", err)
	}
	if _, err := bogus.Thumbprint(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("bogus Thumbprint err = %v", err)
	}
	if bogus.cacheableKey() {
		t.Error("bogus cacheableKey = true，期望 false")
	}
}

// TestOctKeyBranches covers symmetric key decoding, rebuild semantics and errors. | TestOctKeyBranches
// 覆盖对称密钥解码、重建语义与错误。
func TestOctKeyBranches(t *testing.T) {
	empty := &Key{Kty: KeyTypeOct}
	if _, err := empty.PrivateKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("empty oct PrivateKey err = %v", err)
	}
	if _, err := empty.PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("empty oct PublicKey err = %v", err)
	}
	if err := empty.Validate(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("empty oct Validate err = %v", err)
	}
	if _, err := empty.Thumbprint(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("empty oct Thumbprint err = %v", err)
	}

	bad := &Key{Kty: KeyTypeOct, K: "!!!"}
	if _, err := bad.PrivateKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("bad oct PrivateKey err = %v", err)
	}

	key := &Key{Kty: KeyTypeOct, K: EncodeSegment([]byte("secret-value"))}
	first, err := key.PrivateKey()
	if err != nil {
		t.Fatalf("oct PrivateKey 失败: %v", err)
	}
	secret, ok := first.([]byte)
	if !ok || string(secret) != "secret-value" {
		t.Fatalf("oct PrivateKey = %#v", first)
	}
	// Slice-typed material is rebuilt, so mutating one result must not corrupt the next. | 切片类型的
	// 材料每次重建，因此修改一次结果不会污染下一次。
	secret[0] ^= 0xff
	second, err := key.PrivateKey()
	if err != nil {
		t.Fatalf("oct PrivateKey 第二次失败: %v", err)
	}
	if bytes.Equal(second.([]byte), secret) {
		t.Error("oct PrivateKey 结果被缓存，期望每次重建")
	}
	if _, err := key.Thumbprint(); err != nil {
		t.Errorf("oct Thumbprint err = %v", err)
	}

	if _, err := (&Key{Kty: KeyTypeRSA}).octets(); !errors.Is(err, ErrKeyTypeMismatch) {
		t.Errorf("octets(non-oct) err = %v", err)
	}
}

// TestRSAKeyBranches covers public/private RSA decoding and its error paths. | TestRSAKeyBranches
// 覆盖 RSA 公钥/私钥解码及其错误路径。
func TestRSAKeyBranches(t *testing.T) {
	noN := &Key{Kty: KeyTypeRSA}
	if _, err := noN.PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("RSA no n err = %v", err)
	}
	if err := noN.Validate(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("RSA no n Validate err = %v", err)
	}
	if _, err := noN.Thumbprint(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("RSA no n Thumbprint err = %v", err)
	}

	noE := &Key{Kty: KeyTypeRSA, N: b64Bytes(1)}
	if _, err := noE.PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("RSA no e err = %v", err)
	}
	if _, err := (&Key{Kty: KeyTypeRSA, N: b64Bytes(1), E: "!!!"}).PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("RSA bad e err = %v", err)
	}
	if _, err := (&Key{Kty: KeyTypeRSA, N: b64Bytes(1), E: b64Bytes(0)}).PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("RSA zero e err = %v", err)
	}
	if _, err := (&Key{Kty: KeyTypeRSA, N: b64Bytes(1), E: b64Bytes(1)}).PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("RSA e=1 err = %v", err)
	}
	tooBig := new(big.Int).Lsh(big.NewInt(1), 32).Bytes()
	if _, err := (&Key{Kty: KeyTypeRSA, N: b64Bytes(1), E: EncodeSegment(tooBig)}).PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("RSA e=2^32 err = %v", err)
	}
	if pub, err := (&Key{Kty: KeyTypeRSA, N: b64Bytes(1), E: b64Bytes(3)}).PublicKey(); err != nil || pub.(*rsa.PublicKey).E != 3 {
		t.Errorf("RSA e=3 = (%v, %v)", pub, err)
	}

	// Private key decoding errors. | 私钥解码错误。
	if _, err := (&Key{Kty: KeyTypeRSA}).PrivateKey(); !errors.Is(err, ErrNotPrivateKey) {
		t.Errorf("RSA no d err = %v", err)
	}
	priv := func(n, e, d, p, q string) *Key {
		return &Key{Kty: KeyTypeRSA, N: n, E: e, D: d, P: p, Q: q}
	}
	cases := []struct {
		name string
		key  *Key
	}{
		{"missing n", priv("", b64Bytes(3), b64Bytes(1), b64Bytes(1), b64Bytes(1))},
		{"bad e", priv(b64Bytes(1), "!!!", b64Bytes(1), b64Bytes(1), b64Bytes(1))},
		{"bad d", priv(b64Bytes(1), b64Bytes(3), "!!!", b64Bytes(1), b64Bytes(1))},
		{"bad p", priv(b64Bytes(1), b64Bytes(3), b64Bytes(1), "!!!", b64Bytes(1))},
		{"missing q", priv(b64Bytes(1), b64Bytes(3), b64Bytes(1), b64Bytes(1), "")},
		{"invalid numbers", priv(b64Bytes(1), b64Bytes(3), b64Bytes(1), b64Bytes(2), b64Bytes(2))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.key.PrivateKey(); !errors.Is(err, ErrInvalidKey) {
				t.Errorf("RSA PrivateKey err = %v，期望 ErrInvalidKey", err)
			}
			if err := tc.key.Validate(); !errors.Is(err, ErrInvalidKey) {
				t.Errorf("RSA Validate err = %v，期望 ErrInvalidKey", err)
			}
		})
	}

	badOth := priv(b64Bytes(1), b64Bytes(3), b64Bytes(1), b64Bytes(1), b64Bytes(1))
	badOth.Oth = []OtherPrime{{R: "!!!"}}
	if _, err := badOth.PrivateKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("RSA bad oth err = %v", err)
	}
	badOth.Oth = []OtherPrime{{R: ""}}
	if _, err := badOth.PrivateKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("RSA empty oth err = %v", err)
	}
}

// TestRSAMultiPrimeRoundTrip covers the multi-prime conversion loops. | TestRSAMultiPrimeRoundTrip
// 覆盖多素数转换的两个循环。
func TestRSAMultiPrimeRoundTrip(t *testing.T) {
	priv, err := rsa.GenerateMultiPrimeKey(rand.Reader, 3, 2048)
	if err != nil {
		t.Fatalf("GenerateMultiPrimeKey 失败: %v", err)
	}
	key, err := FromPrivateKey("multi", priv)
	if err != nil {
		t.Fatalf("FromPrivateKey(multi-prime) 失败: %v", err)
	}
	if len(key.Oth) != 1 {
		t.Fatalf("Oth 长度 = %d，期望 1", len(key.Oth))
	}
	back, err := key.PrivateKey()
	if err != nil {
		t.Fatalf("multi-prime PrivateKey 失败: %v", err)
	}
	rebuilt, ok := back.(*rsa.PrivateKey)
	if !ok || len(rebuilt.Primes) != 3 {
		t.Fatalf("重建私钥 = %#v，期望 3 个素数", back)
	}
	if err := rebuilt.Validate(); err != nil {
		t.Errorf("重建私钥校验失败: %v", err)
	}
	if err := key.Validate(); err != nil {
		t.Errorf("多素数 Validate 失败: %v", err)
	}
	if err := key.Public().Validate(); err != nil {
		t.Errorf("多素数公钥 Validate 失败: %v", err)
	}
	if pub, err := key.PublicKey(); err != nil || pub.(*rsa.PublicKey).N.Cmp(priv.N) != 0 {
		t.Errorf("多素数 PublicKey 不匹配: %v", err)
	}

	// A key with fewer than two primes is still converted to a public JWK. | 素数少于两个的密钥仍会
	// 转换为公开 JWK。
	odd := rsaPrivateToKey(&rsa.PrivateKey{PublicKey: rsa.PublicKey{N: big.NewInt(9), E: 3}, D: big.NewInt(1)})
	if odd == nil || odd.N == "" || odd.D != "" {
		t.Errorf("rsaPrivateToKey(no primes) = %+v", odd)
	}
}

// TestECKeyBranches covers EC point and scalar validation. | TestECKeyBranches 覆盖 EC 点与标量校验。
func TestECKeyBranches(t *testing.T) {
	noCrv := &Key{Kty: KeyTypeEC}
	if _, err := noCrv.PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("EC no crv err = %v", err)
	}
	if _, err := noCrv.PrivateKey(); !errors.Is(err, ErrNotPrivateKey) {
		t.Errorf("EC no crv private err = %v", err)
	}
	if err := noCrv.Validate(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("EC no crv Validate err = %v", err)
	}
	if _, err := noCrv.Thumbprint(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("EC no crv Thumbprint err = %v", err)
	}

	noX := &Key{Kty: KeyTypeEC, Crv: CurveP256}
	if _, err := noX.PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("EC no x err = %v", err)
	}
	if _, err := (&Key{Kty: KeyTypeEC, Crv: CurveP256, X: b64Bytes(1)}).PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("EC no y err = %v", err)
	}
	if _, err := (&Key{Kty: KeyTypeEC, Crv: CurveP256, X: b64Bytes(1), Y: b64Bytes(1)}).PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("EC short coordinates err = %v", err)
	}
	zeroPoint := &Key{Kty: KeyTypeEC, Crv: CurveP256, X: b64Bytes(make([]byte, 32)...), Y: b64Bytes(make([]byte, 32)...)}
	if _, err := zeroPoint.PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("EC off-curve err = %v", err)
	}
	if err := zeroPoint.Validate(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("EC off-curve Validate err = %v", err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成 EC 密钥失败: %v", err)
	}
	good, err := FromPrivateKey("ec", priv)
	if err != nil {
		t.Fatalf("FromPrivateKey(EC) 失败: %v", err)
	}
	back, err := good.PrivateKey()
	if err != nil {
		t.Fatalf("EC PrivateKey 失败: %v", err)
	}
	if !back.(*ecdsa.PrivateKey).PublicKey.Equal(&priv.PublicKey) {
		t.Error("EC 重建公钥不匹配")
	}
	if err := good.Validate(); err != nil {
		t.Errorf("EC Validate 失败: %v", err)
	}

	// A pointer-typed key memoizes its derived material. | 指针类型密钥会缓存派生材料。
	pub1, err := good.PublicKey()
	if err != nil {
		t.Fatalf("EC PublicKey 失败: %v", err)
	}
	pub2, err := good.PublicKey()
	if err != nil || pub1 != pub2 {
		t.Errorf("EC PublicKey 未缓存: (%p, %p, %v)", pub1, pub2, err)
	}
	// A clone must not inherit that cache, so editing its fields takes effect. | 克隆不得继承缓存，
	// 因此修改其字段应立即生效。
	clone := good.Clone()
	clone.Y = ""
	if _, err := clone.PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("clone with empty Y err = %v，期望 ErrInvalidKey", err)
	}
	priv1, err := good.PrivateKey()
	if err != nil {
		t.Fatalf("EC PrivateKey 失败: %v", err)
	}
	priv2, _ := good.PrivateKey()
	if priv1 != priv2 {
		t.Error("EC PrivateKey 未缓存")
	}

	dOnly := &Key{Kty: KeyTypeEC, Crv: CurveP256, D: good.D, X: "", Y: ""}
	if _, err := dOnly.PrivateKey(); err != nil {
		t.Errorf("EC d-only PrivateKey 失败: %v", err)
	}
	oneCoordinate := &Key{Kty: KeyTypeEC, Crv: CurveP256, D: good.D, X: good.X}
	if _, err := oneCoordinate.PrivateKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("EC one coordinate err = %v", err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成另一 EC 密钥失败: %v", err)
	}
	otherJWK, err := FromPublicKey("other", &other.PublicKey)
	if err != nil {
		t.Fatalf("FromPublicKey(EC) 失败: %v", err)
	}
	mismatch := &Key{Kty: KeyTypeEC, Crv: CurveP256, D: good.D, X: otherJWK.X, Y: otherJWK.Y}
	if _, err := mismatch.PrivateKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("EC public mismatch err = %v", err)
	}
	if _, err := (&Key{Kty: KeyTypeEC, Crv: CurveP256, D: "!!!"}).PrivateKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("EC bad d err = %v", err)
	}
	if _, err := (&Key{Kty: KeyTypeEC, Crv: CurveP256, D: b64Bytes(make([]byte, 33)...)}).PrivateKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("EC d too long err = %v", err)
	}
	if _, err := (&Key{Kty: KeyTypeEC, Crv: CurveP256, D: b64Bytes(make([]byte, 32)...)}).PrivateKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("EC zero scalar err = %v", err)
	}
}

// TestOKPKeyBranches covers Ed25519 and X25519 material handling. | TestOKPKeyBranches 覆盖
// Ed25519 与 X25519 材料处理。
func TestOKPKeyBranches(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成 Ed25519 密钥失败: %v", err)
	}
	edKey, err := FromPrivateKey("ed", edPriv)
	if err != nil {
		t.Fatalf("FromPrivateKey(Ed25519) 失败: %v", err)
	}
	back, err := edKey.PrivateKey()
	if err != nil || !bytes.Equal(back.(ed25519.PrivateKey), edPriv) {
		t.Fatalf("Ed25519 PrivateKey 往返失败: %v", err)
	}
	if pub, err := edKey.PublicKey(); err != nil || !bytes.Equal(pub.(ed25519.PublicKey), edPub) {
		t.Fatalf("Ed25519 PublicKey 往返失败: %v", err)
	}
	if err := edKey.Validate(); err != nil {
		t.Errorf("Ed25519 Validate 失败: %v", err)
	}

	if _, err := (&Key{Kty: KeyTypeOKP, Crv: CurveEd25519}).PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Ed25519 no x err = %v", err)
	}
	if _, err := (&Key{Kty: KeyTypeOKP, Crv: CurveEd25519, X: b64Bytes(1)}).PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Ed25519 short x err = %v", err)
	}
	if _, err := (&Key{Kty: KeyTypeOKP, Crv: CurveEd25519}).PrivateKey(); !errors.Is(err, ErrNotPrivateKey) {
		t.Errorf("Ed25519 no d err = %v", err)
	}
	if _, err := (&Key{Kty: KeyTypeOKP, Crv: CurveEd25519, D: "!!!"}).PrivateKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Ed25519 bad d err = %v", err)
	}
	if _, err := (&Key{Kty: KeyTypeOKP, Crv: CurveEd25519, D: b64Bytes(1, 2, 3)}).PrivateKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Ed25519 short seed err = %v", err)
	}
	seedOnly := &Key{Kty: KeyTypeOKP, Crv: CurveEd25519, D: EncodeSegment(edPriv.Seed())}
	if _, err := seedOnly.PrivateKey(); err != nil {
		t.Errorf("Ed25519 seed-only PrivateKey 失败: %v", err)
	}
	fullOnly := &Key{Kty: KeyTypeOKP, Crv: CurveEd25519, D: EncodeSegment([]byte(edPriv))}
	if _, err := fullOnly.PrivateKey(); err != nil {
		t.Errorf("Ed25519 full-key PrivateKey 失败: %v", err)
	}
	mismatch := &Key{Kty: KeyTypeOKP, Crv: CurveEd25519, D: EncodeSegment(edPriv.Seed()), X: b64Bytes(make([]byte, 32)...)}
	if _, err := mismatch.PrivateKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Ed25519 x mismatch err = %v", err)
	}
	if err := (&Key{Kty: KeyTypeOKP, Crv: CurveEd25519, X: b64Bytes(1)}).Validate(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Ed25519 Validate short x err = %v", err)
	}
	if err := (&Key{Kty: KeyTypeOKP, Crv: CurveEd25519, X: EncodeSegment(edPub), D: "!!!"}).Validate(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Ed25519 Validate bad d err = %v", err)
	}
	if err := (&Key{Kty: KeyTypeOKP, Crv: CurveEd25519, X: EncodeSegment(edPub)}).Validate(); err != nil {
		t.Errorf("Ed25519 Validate 失败: %v", err)
	}
	if _, err := (&Key{Kty: KeyTypeOKP, Crv: "bogus", X: b64Bytes(1)}).PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("OKP bogus crv err = %v", err)
	}
	if _, err := (&Key{Kty: KeyTypeOKP, Crv: "bogus", D: b64Bytes(1)}).PrivateKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("OKP bogus crv private err = %v", err)
	}
	if err := (&Key{Kty: KeyTypeOKP, Crv: "bogus", X: b64Bytes(1)}).Validate(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("OKP bogus crv Validate err = %v", err)
	}

	xPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成 X25519 密钥失败: %v", err)
	}
	xKey, err := FromPrivateKey("x", xPriv)
	if err != nil {
		t.Fatalf("FromPrivateKey(X25519) 失败: %v", err)
	}
	xBack, err := xKey.PrivateKey()
	if err != nil || !bytes.Equal(xBack.(*ecdh.PrivateKey).Bytes(), xPriv.Bytes()) {
		t.Fatalf("X25519 PrivateKey 往返失败: %v", err)
	}
	xPub, err := xKey.PublicKey()
	if err != nil || !bytes.Equal(xPub.(*ecdh.PublicKey).Bytes(), xPriv.PublicKey().Bytes()) {
		t.Fatalf("X25519 PublicKey 往返失败: %v", err)
	}
	if err := xKey.Validate(); err != nil {
		t.Errorf("X25519 Validate 失败: %v", err)
	}
	if _, err := (&Key{Kty: KeyTypeOKP, Crv: CurveX25519}).PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("X25519 no x err = %v", err)
	}
	if _, err := (&Key{Kty: KeyTypeOKP, Crv: CurveX25519, X: b64Bytes(1)}).PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("X25519 short x err = %v", err)
	}
	if _, err := (&Key{Kty: KeyTypeOKP, Crv: CurveX25519, D: b64Bytes(1, 2, 3)}).PrivateKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("X25519 short d err = %v", err)
	}
	xMismatch := &Key{Kty: KeyTypeOKP, Crv: CurveX25519, D: EncodeSegment(xPriv.Bytes()), X: b64Bytes(make([]byte, 32)...)}
	if _, err := xMismatch.PrivateKey(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("X25519 x mismatch err = %v", err)
	}
	if err := (&Key{Kty: KeyTypeOKP, Crv: CurveX25519, X: b64Bytes(1)}).Validate(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("X25519 Validate short x err = %v", err)
	}
	if err := (&Key{Kty: KeyTypeOKP, Crv: CurveX25519, X: EncodeSegment(xPriv.PublicKey().Bytes()), D: "!!!"}).Validate(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("X25519 Validate bad d err = %v", err)
	}
	if err := (&Key{Kty: KeyTypeOKP, Crv: CurveX25519, X: EncodeSegment(xPriv.PublicKey().Bytes())}).Validate(); err != nil {
		t.Errorf("X25519 Validate 失败: %v", err)
	}
}

// TestThumbprintErrors covers the missing-member rejection of every key type. | TestThumbprintErrors
// 覆盖每种密钥类型的缺失成员拒绝。
func TestThumbprintErrors(t *testing.T) {
	cases := []*Key{
		{Kty: KeyTypeRSA, N: "n"},
		{Kty: KeyTypeEC, Crv: CurveP256, X: "x"},
		{Kty: KeyTypeOKP, Crv: CurveEd25519},
		{Kty: KeyTypeOct},
	}
	for _, key := range cases {
		if _, err := key.Thumbprint(); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("Thumbprint(%+v) err = %v，期望 ErrInvalidKey", key, err)
		}
	}
}

// TestValidateAlgBinding covers the declared-alg compatibility check. | TestValidateAlgBinding 覆盖
// 声明算法兼容性检查。
func TestValidateAlgBinding(t *testing.T) {
	oct := &Key{Kty: KeyTypeOct, K: EncodeSegment(bytesRepeat(0x11, 32)), Alg: "HS256"}
	if err := oct.Validate(); err != nil {
		t.Errorf("HS256 Validate 失败: %v", err)
	}
	oct.Alg = "RS256"
	if err := oct.Validate(); !errors.Is(err, ErrKeyTypeMismatch) {
		t.Errorf("oct RS256 Validate err = %v", err)
	}
	rsaKey := testUnboundRSAKey(t)
	rsaKey.Alg = "NOPE"
	if err := rsaKey.Validate(); !errors.Is(err, ErrAlgNotAllowed) {
		t.Errorf("RSA unknown alg Validate err = %v", err)
	}
	ecPublic := testECPublicJWK(t)
	ec := &Key{Kty: KeyTypeEC, Crv: CurveP256, Alg: "ES384", X: ecPublic.X, Y: ecPublic.Y}
	if err := ec.Validate(); !errors.Is(err, ErrKeyTypeMismatch) {
		t.Errorf("P-256 ES384 Validate err = %v", err)
	}
}

// testECPublicJWK returns a P-256 public JWK. | testECPublicJWK 返回 P-256 公开 JWK。
func testECPublicJWK(t *testing.T) *Key {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成 EC 密钥失败: %v", err)
	}
	k, err := FromPublicKey("ec", &priv.PublicKey)
	if err != nil {
		t.Fatalf("FromPublicKey 失败: %v", err)
	}
	return k
}

// TestCheckKeyAlgTable covers every algorithm family of checkKeyAlg. | TestCheckKeyAlgTable 覆盖
// checkKeyAlg 的每个算法族。
func TestCheckKeyAlgTable(t *testing.T) {
	oct16 := &Key{Kty: KeyTypeOct, K: EncodeSegment(bytesRepeat(1, 16))}
	oct32 := &Key{Kty: KeyTypeOct, K: EncodeSegment(bytesRepeat(1, 32))}
	oct48 := &Key{Kty: KeyTypeOct, K: EncodeSegment(bytesRepeat(1, 48))}
	oct64 := &Key{Kty: KeyTypeOct, K: EncodeSegment(bytesRepeat(1, 64))}
	oct24 := &Key{Kty: KeyTypeOct, K: EncodeSegment(bytesRepeat(1, 24))}
	rsaKey := &Key{Kty: KeyTypeRSA}
	ec256 := &Key{Kty: KeyTypeEC, Crv: CurveP256}
	ec384 := &Key{Kty: KeyTypeEC, Crv: CurveP384}
	ec521 := &Key{Kty: KeyTypeEC, Crv: CurveP521}
	ecBogus := &Key{Kty: KeyTypeEC, Crv: "bogus"}
	ed := &Key{Kty: KeyTypeOKP, Crv: CurveEd25519}
	x25519 := &Key{Kty: KeyTypeOKP, Crv: CurveX25519}

	cases := []struct {
		name string
		key  *Key
		alg  string
		want error
	}{
		{"HS256 oct", oct32, "HS256", nil},
		{"HS384 oct", oct48, "HS384", nil},
		{"HS512 oct", oct64, "HS512", nil},
		{"HS256 weak", oct16, "HS256", ErrWeakKey},
		{"HS256 rsa", rsaKey, "HS256", ErrKeyTypeMismatch},
		{"RS256 rsa", rsaKey, "RS256", nil},
		{"PS512 rsa", rsaKey, "PS512", nil},
		{"RS256 oct", oct32, "RS256", ErrKeyTypeMismatch},
		{"ES256 p256", ec256, "ES256", nil},
		{"ES256 p384", ec384, "ES256", ErrKeyTypeMismatch},
		{"ES384 p384", ec384, "ES384", nil},
		{"ES512 p521", ec521, "ES512", nil},
		{"ES384 oct", oct32, "ES384", ErrKeyTypeMismatch},
		{"EdDSA ed", ed, "EdDSA", nil},
		{"EdDSA rsa", rsaKey, "EdDSA", ErrKeyTypeMismatch},
		{"A128KW", oct16, "A128KW", nil},
		{"A192KW", oct24, "A192KW", nil},
		{"A256KW", oct32, "A256KW", nil},
		{"A128KW wrong size", oct32, "A128KW", ErrWeakKey},
		{"A128KW rsa", rsaKey, "A128KW", ErrKeyTypeMismatch},
		{"dir oct", oct32, "dir", nil},
		{"dir rsa", rsaKey, "dir", ErrKeyTypeMismatch},
		{"ECDH-ES p256", ec256, "ECDH-ES", nil},
		{"ECDH-ES x25519", x25519, "ECDH-ES+A128KW", nil},
		{"ECDH-ES bogus", ecBogus, "ECDH-ES", ErrKeyTypeMismatch},
		{"ECDH-ES rsa", rsaKey, "ECDH-ES", ErrKeyTypeMismatch},
		{"unknown", oct32, "NOPE", ErrAlgNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkKeyAlg(tc.key, tc.alg)
			if tc.want == nil {
				if err != nil {
					t.Errorf("checkKeyAlg err = %v，期望成功", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("checkKeyAlg err = %v，期望 %v", err, tc.want)
			}
		})
	}
}

// TestDecodeHelpers covers member and exponent decoding plus curve mapping. | TestDecodeHelpers 覆盖
// 成员与指数解码以及曲线映射。
func TestDecodeHelpers(t *testing.T) {
	if _, err := decodeMember("n", ""); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("decodeMember empty err = %v", err)
	}
	if _, err := decodeMember("n", "!!!"); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("decodeMember bad err = %v", err)
	}
	if _, err := decodeExponent(""); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("decodeExponent empty err = %v", err)
	}
	if _, err := decodeExponent("!!!"); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("decodeExponent bad err = %v", err)
	}
	if _, err := decodeExponent(b64Bytes(0)); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("decodeExponent zero err = %v", err)
	}
	if e, err := decodeExponent(b64Bytes(3)); err != nil || e != 3 {
		t.Errorf("decodeExponent(3) = (%d, %v)", e, err)
	}
	if _, err := ecCurve("bogus"); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("ecCurve bogus err = %v", err)
	}
	if name, ok := ecCurveName(nil); ok || name != "" {
		t.Errorf("ecCurveName(nil) = (%q, %v)", name, ok)
	}
	if name, ok := ecCurveName(elliptic.P224()); ok || name != "" {
		t.Errorf("ecCurveName(P224) = (%q, %v)", name, ok)
	}
	for _, tc := range []struct {
		curve elliptic.Curve
		want  string
	}{{elliptic.P256(), CurveP256}, {elliptic.P384(), CurveP384}, {elliptic.P521(), CurveP521}} {
		if name, ok := ecCurveName(tc.curve); !ok || name != tc.want {
			t.Errorf("ecCurveName(%v) = (%q, %v)", tc.curve.Params().Name, name, ok)
		}
	}

	if isECDHKey(nil) {
		t.Error("isECDHKey(nil) = true")
	}
	for _, tc := range []struct {
		key  *Key
		want bool
	}{
		{&Key{Kty: KeyTypeOKP, Crv: CurveX25519}, true},
		{&Key{Kty: KeyTypeOKP, Crv: CurveEd25519}, false},
		{&Key{Kty: KeyTypeEC, Crv: CurveP256}, true},
		{&Key{Kty: KeyTypeEC, Crv: CurveP384}, true},
		{&Key{Kty: KeyTypeEC, Crv: CurveP521}, true},
		{&Key{Kty: KeyTypeEC, Crv: "bogus"}, false},
		{&Key{Kty: KeyTypeRSA}, false},
	} {
		if got := isECDHKey(tc.key); got != tc.want {
			t.Errorf("isECDHKey(%+v) = %v，期望 %v", tc.key, got, tc.want)
		}
	}
}

// TestGenerateKeyAndCurveHelpers covers generator rejections and curve helpers. | TestGenerateKeyAndCurveHelpers
// 覆盖生成器拒绝与曲线辅助函数。
func TestGenerateKeyAndCurveHelpers(t *testing.T) {
	if _, err := GenerateKey("RS256", 1024); !errors.Is(err, ErrWeakKey) {
		t.Errorf("GenerateKey(RS256,1024) err = %v", err)
	}
	if _, err := GenerateKey("HS256", 128); !errors.Is(err, ErrWeakKey) {
		t.Errorf("GenerateKey(HS256,128) err = %v", err)
	}
	if _, err := GenerateKey("NOPE", 0); !errors.Is(err, ErrAlgNotAllowed) {
		t.Errorf("GenerateKey(NOPE) err = %v", err)
	}
	if _, err := GenerateKey("ECDH-ES", 123); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("GenerateKey(ECDH-ES,123) err = %v", err)
	}
	if _, err := ecCurveForAlg("NOPE"); !errors.Is(err, ErrAlgNotAllowed) {
		t.Errorf("ecCurveForAlg(NOPE) err = %v", err)
	}
	if _, err := ecdhCurveForBits(123); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("ecdhCurveForBits(123) err = %v", err)
	}
	for _, bits := range []int{0, 256, 384, 521} {
		if _, err := ecdhCurveForBits(bits); err != nil {
			t.Errorf("ecdhCurveForBits(%d) err = %v", bits, err)
		}
	}
	if isX25519Curve(nil) {
		t.Error("isX25519Curve(nil) = true")
	}
	if isX25519Curve(ecdh.P256()) {
		t.Error("isX25519Curve(P256) = true")
	}
	if !isX25519Curve(ecdh.X25519()) {
		t.Error("isX25519Curve(X25519) = false")
	}
}

// TestFromKeyConvertersReject covers every unsupported or invalid input of the converters. |
// TestFromKeyConvertersReject 覆盖转换器的每个不支持或非法输入。
func TestFromKeyConvertersReject(t *testing.T) {
	if _, err := FromPrivateKey("bad", &rsa.PrivateKey{}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("FromPrivateKey(zero RSA) err = %v", err)
	}
	var nilEC *ecdsa.PrivateKey
	if _, err := FromPrivateKey("nil", nilEC); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("FromPrivateKey(nil EC) err = %v", err)
	}
	if _, err := FromPrivateKey("zero", &ecdsa.PrivateKey{}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("FromPrivateKey(zero EC) err = %v", err)
	}
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("生成 P-224 密钥失败: %v", err)
	}
	if _, err := FromPrivateKey("p224", p224); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("FromPrivateKey(P224) err = %v", err)
	}
	if _, err := FromPrivateKey("short", ed25519.PrivateKey(make([]byte, 5))); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("FromPrivateKey(short Ed25519) err = %v", err)
	}
	var nilECDH *ecdh.PrivateKey
	if _, err := FromPrivateKey("nil", nilECDH); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("FromPrivateKey(nil ECDH) err = %v", err)
	}
	p256, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成 P-256 ECDH 密钥失败: %v", err)
	}
	if _, err := FromPrivateKey("p256", p256); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("FromPrivateKey(ECDH P256) err = %v", err)
	}
	if _, err := FromPrivateKey("empty", []byte{}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("FromPrivateKey(empty bytes) err = %v", err)
	}
	if _, err := FromPrivateKey("empty", ""); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("FromPrivateKey(empty string) err = %v", err)
	}
	if _, err := FromPrivateKey("bad", 42); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("FromPrivateKey(42) err = %v", err)
	}

	if _, err := FromPublicKey("bad", &rsa.PublicKey{}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("FromPublicKey(zero RSA) err = %v", err)
	}
	if _, err := FromPublicKey("bad", &rsa.PublicKey{N: big.NewInt(3), E: 0}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("FromPublicKey(E=0) err = %v", err)
	}
	var nilECPub *ecdsa.PublicKey
	if _, err := FromPublicKey("nil", nilECPub); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("FromPublicKey(nil EC) err = %v", err)
	}
	if _, err := FromPublicKey("p224", &p224.PublicKey); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("FromPublicKey(P224) err = %v", err)
	}
	if _, err := FromPublicKey("short", ed25519.PublicKey(make([]byte, 5))); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("FromPublicKey(short Ed25519) err = %v", err)
	}
	var nilECDHPub *ecdh.PublicKey
	if _, err := FromPublicKey("nil", nilECDHPub); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("FromPublicKey(nil ECDH) err = %v", err)
	}
	if _, err := FromPublicKey("p256", p256.PublicKey()); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("FromPublicKey(ECDH P256) err = %v", err)
	}
	if _, err := FromPublicKey("empty", []byte{}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("FromPublicKey(empty bytes) err = %v", err)
	}
	if _, err := FromPublicKey("empty", ""); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("FromPublicKey(empty string) err = %v", err)
	}
	if _, err := FromPublicKey("bad", 42); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("FromPublicKey(42) err = %v", err)
	}
}

// TestKeyCacheConcurrent exercises the memoized derived-key cache under the race detector. |
// TestKeyCacheConcurrent 在竞态检测器下验证派生密钥缓存。
func TestKeyCacheConcurrent(t *testing.T) {
	ecKey := mustGenerate(t, "ES256")
	rsaKey := testUnboundedRSA(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				if _, err := ecKey.PrivateKey(); err != nil {
					t.Errorf("EC PrivateKey 并发失败: %v", err)
					return
				}
				if _, err := ecKey.PublicKey(); err != nil {
					t.Errorf("EC PublicKey 并发失败: %v", err)
					return
				}
				if _, err := rsaKey.PrivateKey(); err != nil {
					t.Errorf("RSA PrivateKey 并发失败: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// testUnboundedRSA returns an unbound RSA key without taking the shared test helper's name. |
// testUnboundedRSA 返回未绑定 RSA 密钥，避免与共享测试辅助重名。
func testUnboundedRSA(t *testing.T) *Key {
	t.Helper()
	return testUnboundRSAKey(t)
}
