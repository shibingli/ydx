package xmlsig

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"hash"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/guomi"
)

// newSHA1Hash returns a SHA-1 hash. | newSHA1Hash 返回 SHA-1 摘要。
func newSHA1Hash() hash.Hash { return sha1.New() }

// newSHA256Hash returns a SHA-256 hash. | newSHA256Hash 返回 SHA-256 摘要。
func newSHA256Hash() hash.Hash { return sha256.New() }

// blockMode identifies a data-encryption construction. | blockMode 标识数据加密构造。
type blockMode uint8

const (
	blockAESCBC blockMode = iota + 1
	blockAESGCM
	blockSM4CBC
	blockSM4GCM
)

// blockCipherSpec describes one data-encryption algorithm. | blockCipherSpec 描述一种数据加密算法。
type blockCipherSpec struct {
	uri    string
	mode   blockMode
	keyLen int
}

// blockCipherSpecs maps data-encryption URIs to specifications. | blockCipherSpecs 把数据加密 URI
// 映射为规格。
var blockCipherSpecs = map[string]blockCipherSpec{
	encAES128CBCURI: {uri: encAES128CBCURI, mode: blockAESCBC, keyLen: 16},
	encAES192CBCURI: {uri: encAES192CBCURI, mode: blockAESCBC, keyLen: 24},
	encAES256CBCURI: {uri: encAES256CBCURI, mode: blockAESCBC, keyLen: 32},
	encAES128GCMURI: {uri: encAES128GCMURI, mode: blockAESGCM, keyLen: 16},
	encAES192GCMURI: {uri: encAES192GCMURI, mode: blockAESGCM, keyLen: 24},
	encAES256GCMURI: {uri: encAES256GCMURI, mode: blockAESGCM, keyLen: 32},
	encSM4CBCURI:    {uri: encSM4CBCURI, mode: blockSM4CBC, keyLen: guomi.SM4KeySize},
	encSM4GCMURI:    {uri: encSM4GCMURI, mode: blockSM4GCM, keyLen: guomi.SM4KeySize},
}

// defaultEncryptionURIs is the decryption data-algorithm allowlist. | defaultEncryptionURIs 是解密
// 数据算法的允许列表。
var defaultEncryptionURIs = []string{
	encAES128CBCURI, encAES192CBCURI, encAES256CBCURI,
	encAES128GCMURI, encAES192GCMURI, encAES256GCMURI,
	encSM4CBCURI, encSM4GCMURI,
}

// blockCipherSpecForURI resolves and authorizes a data-encryption URI. | blockCipherSpecForURI 解析
// 并授权数据加密 URI。
func blockCipherSpecForURI(uri string, allowed []string) (blockCipherSpec, error) {
	spec, ok := blockCipherSpecs[uri]
	if !ok {
		return blockCipherSpec{}, errs.Detail(ErrUnsupported, "encryption algorithm %q is not supported | 不支持加密算法 %q", uri, uri)
	}
	if !algorithmAllowed(uri, allowed, defaultEncryptionURIs) {
		return blockCipherSpec{}, errs.Detail(ErrAlgorithmNotAllowed, "encryption algorithm %q is not allowed | 加密算法 %q 不被允许", uri, uri)
	}
	return spec, nil
}

// defaultBlockCipherURI is AES-256-GCM. | defaultBlockCipherURI 为 AES-256-GCM。
const defaultBlockCipherURI = encAES256GCMURI

// transportKind identifies a key-transport construction. | transportKind 标识密钥传输构造。
type transportKind uint8

const (
	transportRSA15 transportKind = iota + 1
	transportRSAOAEP
	transportSM2
)

// transportSpec describes one key-transport algorithm. | transportSpec 描述一种密钥传输算法。
type transportSpec struct {
	uri  string
	kind transportKind
}

// keyTransportSpecs maps key-transport URIs to specifications. | keyTransportSpecs 把密钥传输 URI
// 映射为规格。
var keyTransportSpecs = map[string]transportSpec{
	encRSA15URI:      {uri: encRSA15URI, kind: transportRSA15},
	encRSAOAEPURI:    {uri: encRSAOAEPURI, kind: transportRSAOAEP},
	encRSAOAEP11URI:  {uri: encRSAOAEP11URI, kind: transportRSAOAEP},
	encSM2URI:        {uri: encSM2URI, kind: transportSM2},
	encSM2EncryptURI: {uri: encSM2EncryptURI, kind: transportSM2},
}

// defaultRSAKeyTransportURI is RSA-OAEP with SHA-256 parameters. | defaultRSAKeyTransportURI 为
// 使用 SHA-256 参数的 RSA-OAEP。
const defaultRSAKeyTransportURI = encRSAOAEP11URI

// defaultSM2KeyTransportURI is SM2 key transport. | defaultSM2KeyTransportURI 为 SM2 密钥传输。
const defaultSM2KeyTransportURI = encSM2URI

// keyWrapKeySizes maps AES key-wrap URIs to their KEK sizes. | keyWrapKeySizes 把 AES 密钥包装
// URI 映射为 KEK 长度。
var keyWrapKeySizes = map[string]int{
	encAES128KWURI: 16,
	encAES192KWURI: 24,
	encAES256KWURI: 32,
}

// randomBytes returns n cryptographically random bytes. | randomBytes 返回 n 个密码学随机字节。
func randomBytes(n int) ([]byte, error) {
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		return nil, errs.Wrap(err, ErrEncrypt)
	}
	return out, nil
}

// encryptBlock encrypts plaintext under key according to spec. | encryptBlock 按 spec 使用 key
// 加密 plaintext。
func encryptBlock(spec blockCipherSpec, key, plaintext []byte) ([]byte, error) {
	switch spec.mode {
	case blockAESCBC, blockSM4CBC:
		var block cipher.Block
		var err error
		if spec.mode == blockAESCBC {
			block, err = aes.NewCipher(key)
		} else {
			block, err = guomi.NewCipher(key)
		}
		if err != nil {
			return nil, errs.Wrap(err, ErrEncrypt)
		}
		iv, err := randomBytes(block.BlockSize())
		if err != nil {
			return nil, err
		}
		padded := pkcs7Pad(plaintext, block.BlockSize())
		out := make([]byte, len(iv)+len(padded))
		copy(out, iv)
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out[len(iv):], padded)
		return out, nil
	case blockAESGCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, errs.Wrap(err, ErrEncrypt)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, errs.Wrap(err, ErrEncrypt)
		}
		nonce, err := randomBytes(aead.NonceSize())
		if err != nil {
			return nil, err
		}
		return aead.Seal(nonce, nonce, plaintext, nil), nil
	case blockSM4GCM:
		nonce, err := randomBytes(guomi.SM4GCMNonceSize)
		if err != nil {
			return nil, err
		}
		sealed, err := guomi.SealGCM(key, nonce, plaintext, nil)
		if err != nil {
			return nil, errs.Wrap(err, ErrEncrypt)
		}
		return append(append([]byte(nil), nonce...), sealed...), nil
	default:
		return nil, errs.Detail(ErrUnsupported, "unsupported block mode | 不支持的块模式")
	}
}

// decryptBlock decrypts ciphertext under key according to spec. All structural, padding and
// authentication failures return ErrDecrypt to avoid oracles. | decryptBlock 按 spec 使用 key 解密
// ciphertext。所有结构、填充与认证失败都返回 ErrDecrypt，以避免预言。
func decryptBlock(spec blockCipherSpec, key, ciphertext []byte) ([]byte, error) {
	switch spec.mode {
	case blockAESCBC, blockSM4CBC:
		var block cipher.Block
		var err error
		if spec.mode == blockAESCBC {
			block, err = aes.NewCipher(key)
		} else {
			block, err = guomi.NewCipher(key)
		}
		if err != nil {
			return nil, errs.Detail(ErrDecrypt, "invalid content-encryption key | 内容加密密钥非法")
		}
		bs := block.BlockSize()
		if len(ciphertext) < 2*bs || len(ciphertext)%bs != 0 {
			return nil, errs.Detail(ErrDecrypt, "invalid CBC ciphertext length | CBC 密文长度非法")
		}
		iv := ciphertext[:bs]
		padded := make([]byte, len(ciphertext)-bs)
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(padded, ciphertext[bs:])
		return pkcs7Unpad(padded, bs)
	case blockAESGCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, errs.Detail(ErrDecrypt, "invalid content-encryption key | 内容加密密钥非法")
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, errs.Detail(ErrDecrypt, "GCM initialization failed | GCM 初始化失败")
		}
		if len(ciphertext) < aead.NonceSize()+aead.Overhead() {
			return nil, errs.Detail(ErrDecrypt, "invalid GCM ciphertext length | GCM 密文长度非法")
		}
		nonce := ciphertext[:aead.NonceSize()]
		plaintext, err := aead.Open(nil, nonce, ciphertext[aead.NonceSize():], nil)
		if err != nil {
			return nil, errs.Detail(ErrDecrypt, "GCM authentication failed | GCM 认证失败")
		}
		return plaintext, nil
	case blockSM4GCM:
		if len(ciphertext) < guomi.SM4GCMNonceSize+guomi.SM4GCMTagSize {
			return nil, errs.Detail(ErrDecrypt, "invalid SM4-GCM ciphertext length | SM4-GCM 密文长度非法")
		}
		nonce := ciphertext[:guomi.SM4GCMNonceSize]
		plaintext, err := guomi.OpenGCM(key, nonce, ciphertext[guomi.SM4GCMNonceSize:], nil)
		if err != nil {
			return nil, errs.Detail(ErrDecrypt, "SM4-GCM authentication failed | SM4-GCM 认证失败")
		}
		return plaintext, nil
	default:
		return nil, errs.Detail(ErrUnsupported, "unsupported block mode | 不支持的块模式")
	}
}

// pkcs7Pad pads data to a multiple of blockSize. | pkcs7Pad 把 data 填充到 blockSize 的整数倍。
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+padding)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(padding)
	}
	return out
}

// pkcs7Unpad removes and validates PKCS#7 padding. | pkcs7Unpad 移除并校验 PKCS#7 填充。
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errs.Detail(ErrDecrypt, "invalid padding | 填充非法")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > blockSize || padding > len(data) {
		return nil, errs.Detail(ErrDecrypt, "invalid padding | 填充非法")
	}
	var mismatch byte
	for _, c := range data[len(data)-padding:] {
		mismatch |= c ^ byte(padding)
	}
	if mismatch != 0 {
		return nil, errs.Detail(ErrDecrypt, "invalid padding | 填充非法")
	}
	return data[:len(data)-padding], nil
}

// keyWrapSizeFor resolves and checks an AES key-wrap URI against the KEK length. | keyWrapSizeFor
// 解析 AES 密钥包装 URI 并检查 KEK 长度。
func keyWrapSizeFor(uri string, kekLen int) (int, error) {
	if uri == "" {
		switch kekLen {
		case 16:
			return 16, nil
		case 24:
			return 24, nil
		case 32:
			return 32, nil
		default:
			return 0, errs.Detail(ErrKeyMismatch, "key-wrap KEK must be 16, 24 or 32 bytes | 密钥包装 KEK 必须为 16、24 或 32 字节")
		}
	}
	size, ok := keyWrapKeySizes[uri]
	if !ok {
		return 0, errs.Detail(ErrUnsupported, "key-wrap algorithm %q is not supported | 不支持密钥包装算法 %q", uri, uri)
	}
	if size != kekLen {
		return 0, errs.Detail(ErrKeyMismatch, "KEK length %d does not match %s | KEK 长度 %d 与 %s 不匹配", kekLen, uri, kekLen, uri)
	}
	return size, nil
}

// keyWrapDefaultURI returns the key-wrap URI matching a KEK size. | keyWrapDefaultURI 返回与 KEK
// 长度匹配的密钥包装 URI。
func keyWrapDefaultURI(kekLen int) string {
	switch kekLen {
	case 16:
		return encAES128KWURI
	case 24:
		return encAES192KWURI
	case 32:
		return encAES256KWURI
	default:
		return ""
	}
}

// aesKeyWrap performs RFC 3394 AES key wrap. | aesKeyWrap 执行 RFC 3394 AES 密钥包装。
func aesKeyWrap(kek, cek []byte) ([]byte, error) {
	if len(cek)%8 != 0 || len(cek) < 16 || (len(kek) != 16 && len(kek) != 24 && len(kek) != 32) {
		return nil, errs.Detail(ErrKeyMismatch, "invalid AES key-wrap input | AES 密钥包装输入非法")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, errs.Wrap(err, ErrEncrypt)
	}
	n := len(cek) / 8
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = append([]byte(nil), cek[i*8:(i+1)*8]...)
	}
	a := []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	var buf [16]byte
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			copy(buf[:8], a)
			copy(buf[8:], r[i])
			block.Encrypt(buf[:], buf[:])
			t := uint64(n*j + i + 1)
			binary.BigEndian.PutUint64(a, binary.BigEndian.Uint64(buf[:8])^t)
			copy(r[i], buf[8:])
		}
	}
	out := make([]byte, 8+len(cek))
	copy(out, a)
	for i := 0; i < n; i++ {
		copy(out[8+i*8:], r[i])
	}
	return out, nil
}

// aesKeyUnwrap performs RFC 3394 AES key unwrap. | aesKeyUnwrap 执行 RFC 3394 AES 密钥解包。
func aesKeyUnwrap(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped)%8 != 0 || len(wrapped) < 24 {
		return nil, errs.Detail(ErrDecrypt, "invalid wrapped key length | 包装密钥长度非法")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, errs.Detail(ErrDecrypt, "invalid KEK | KEK 非法")
	}
	n := len(wrapped)/8 - 1
	a := append([]byte(nil), wrapped[:8]...)
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = append([]byte(nil), wrapped[8+i*8:16+i*8]...)
	}
	var buf [16]byte
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			t := uint64(n*j + i + 1)
			binary.BigEndian.PutUint64(buf[:8], binary.BigEndian.Uint64(a)^t)
			copy(buf[8:], r[i])
			block.Decrypt(buf[:], buf[:])
			copy(a, buf[:8])
			copy(r[i], buf[8:])
		}
	}
	if !bytes.Equal(a, []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}) {
		return nil, errs.Detail(ErrDecrypt, "key unwrap integrity check failed | 密钥解包完整性校验失败")
	}
	out := make([]byte, n*8)
	for i := 0; i < n; i++ {
		copy(out[i*8:], r[i])
	}
	return out, nil
}

// rsaTransport decides which RSA padding to use for encryption. | rsaTransport 决定加密时使用的
// RSA 填充。
func rsaTransport(allowRSA15 bool, requested string) (transportSpec, error) {
	switch requested {
	case encRSA15URI:
		if !allowRSA15 {
			return transportSpec{}, errs.Detail(ErrAlgorithmNotAllowed, "RSA PKCS#1 v1.5 key transport is disabled | RSA PKCS#1 v1.5 密钥传输已禁用")
		}
		return keyTransportSpecs[encRSA15URI], nil
	case encRSAOAEPURI, encRSAOAEP11URI:
		return keyTransportSpecs[requested], nil
	case "":
		return keyTransportSpecs[defaultRSAKeyTransportURI], nil
	default:
		return transportSpec{}, errs.Detail(ErrUnsupported, "key transport %q is not supported for RSA keys | RSA 密钥不支持密钥传输 %q", requested, requested)
	}
}

// encryptRSAKey transports cek under an RSA public key. | encryptRSAKey 在 RSA 公钥下传输 cek。
func encryptRSAKey(pub *rsa.PublicKey, cek []byte, allowRSA15 bool, requested string) ([]byte, string, error) {
	spec, err := rsaTransport(allowRSA15, requested)
	if err != nil {
		return nil, "", err
	}
	switch spec.kind {
	case transportRSA15:
		out, err := rsa.EncryptPKCS1v15(rand.Reader, pub, cek)
		if err != nil {
			return nil, "", errs.Wrap(err, ErrEncrypt)
		}
		return out, spec.uri, nil
	case transportRSAOAEP:
		hash := cryptoHashForOAEPURI(spec.uri)
		out, err := rsa.EncryptOAEP(hash(), rand.Reader, pub, cek, nil)
		if err != nil {
			return nil, "", errs.Wrap(err, ErrEncrypt)
		}
		return out, spec.uri, nil
	default:
		return nil, "", errs.Detail(ErrUnsupported, "unsupported RSA transport | 不支持的 RSA 传输")
	}
}

// cryptoHashForOAEPURI returns the OAEP hash constructor for a transport URI. | cryptoHashForOAEPURI
// 返回传输 URI 的 OAEP 摘要构造器。
func cryptoHashForOAEPURI(uri string) func() hash.Hash {
	if uri == encRSAOAEPURI {
		return newSHA1Hash
	}
	return newSHA256Hash
}
