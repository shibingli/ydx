package xmlsig

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/guomi"
)

// digestSpec describes one supported digest algorithm. | digestSpec 描述一种受支持的摘要算法。
type digestSpec struct {
	uri     string
	newHash func() hash.Hash
	size    int
	hash    crypto.Hash
	sm3     bool
}

// digestSpecs maps digest URIs to specifications. | digestSpecs 把摘要 URI 映射为规格。
var digestSpecs = map[string]digestSpec{
	digestSHA1URI:      {uri: digestSHA1URI, newHash: sha1.New, size: sha1.Size, hash: crypto.SHA1},
	digestSHA256URI:    {uri: digestSHA256URI, newHash: sha256.New, size: sha256.Size, hash: crypto.SHA256},
	digestSHA384URI:    {uri: digestSHA384URI, newHash: sha512.New384, size: sha512.Size384, hash: crypto.SHA384},
	digestSHA512URI:    {uri: digestSHA512URI, newHash: sha512.New, size: sha512.Size, hash: crypto.SHA512},
	digestSM3URI:       {uri: digestSM3URI, newHash: guomi.New, size: guomi.SM3Size, sm3: true},
	digestSHA256AltURI: {uri: digestSHA256AltURI, newHash: sha256.New, size: sha256.Size, hash: crypto.SHA256},
	digestSHA512AltURI: {uri: digestSHA512AltURI, newHash: sha512.New, size: sha512.Size, hash: crypto.SHA512},
}

// defaultDigestURIs is the verification allowlist used when the caller supplies none. SHA-1 is
// deliberately absent and must be enabled explicitly. | defaultDigestURIs 是调用方未提供时使用的
// 校验允许列表。SHA-1 被刻意排除，必须显式启用。
var defaultDigestURIs = []string{
	digestSHA256URI, digestSHA384URI, digestSHA512URI, digestSM3URI,
	digestSHA256AltURI, digestSHA512AltURI,
}

// digestSpecForURI resolves and authorizes a digest URI. | digestSpecForURI 解析并授权摘要 URI。
func digestSpecForURI(uri string, allowed []string) (digestSpec, error) {
	spec, ok := digestSpecs[uri]
	if !ok {
		return digestSpec{}, errs.Detail(ErrUnsupported, "digest algorithm %q is not supported | 不支持摘要算法 %q", uri, uri)
	}
	if !algorithmAllowed(uri, allowed, defaultDigestURIs) {
		return digestSpec{}, errs.Detail(ErrAlgorithmNotAllowed, "digest algorithm %q is not allowed | 摘要算法 %q 不被允许", uri, uri)
	}
	return spec, nil
}

// computeDigest returns the digest of data. | computeDigest 返回 data 的摘要。
func computeDigest(spec digestSpec, data []byte) []byte {
	h := spec.newHash()
	_, _ = h.Write(data)
	return h.Sum(nil)
}

// computeHMAC returns the keyed digest of data. | computeHMAC 返回 data 的带密钥摘要。
func computeHMAC(spec digestSpec, key, data []byte) []byte {
	if spec.sm3 {
		sum := guomi.HMAC(key, data)
		return sum[:]
	}
	mac := hmac.New(spec.newHash, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

// signatureKind identifies the math behind a SignatureMethod. | signatureKind 标识 SignatureMethod
// 背后的密码学类别。
type signatureKind uint8

const (
	sigKindRSA signatureKind = iota + 1
	sigKindRSAPSS
	sigKindECDSA
	sigKindEd25519
	sigKindHMAC
	sigKindSM2
)

// signatureSpec describes one supported SignatureMethod. | signatureSpec 描述一种受支持的
// SignatureMethod。
type signatureSpec struct {
	uri    string
	kind   signatureKind
	digest digestSpec
	hash   crypto.Hash
}

// signatureSpecs maps SignatureMethod URIs to specifications. | signatureSpecs 把 SignatureMethod
// URI 映射为规格。
var signatureSpecs = map[string]signatureSpec{
	sigRSASHA1URI:      {uri: sigRSASHA1URI, kind: sigKindRSA, digest: digestSpecs[digestSHA1URI], hash: crypto.SHA1},
	sigRSASHA256URI:    {uri: sigRSASHA256URI, kind: sigKindRSA, digest: digestSpecs[digestSHA256URI], hash: crypto.SHA256},
	sigRSASHA384URI:    {uri: sigRSASHA384URI, kind: sigKindRSA, digest: digestSpecs[digestSHA384URI], hash: crypto.SHA384},
	sigRSASHA512URI:    {uri: sigRSASHA512URI, kind: sigKindRSA, digest: digestSpecs[digestSHA512URI], hash: crypto.SHA512},
	sigRSAPSSURI:       {uri: sigRSAPSSURI, kind: sigKindRSAPSS, digest: digestSpecs[digestSHA256URI], hash: crypto.SHA256},
	sigRSAPSSSHA256URI: {uri: sigRSAPSSSHA256URI, kind: sigKindRSAPSS, digest: digestSpecs[digestSHA256URI], hash: crypto.SHA256},
	sigRSAPSSSHA384URI: {uri: sigRSAPSSSHA384URI, kind: sigKindRSAPSS, digest: digestSpecs[digestSHA384URI], hash: crypto.SHA384},
	sigRSAPSSSHA512URI: {uri: sigRSAPSSSHA512URI, kind: sigKindRSAPSS, digest: digestSpecs[digestSHA512URI], hash: crypto.SHA512},
	sigECDSASHA1URI:    {uri: sigECDSASHA1URI, kind: sigKindECDSA, digest: digestSpecs[digestSHA1URI], hash: crypto.SHA1},
	sigECDSASHA256URI:  {uri: sigECDSASHA256URI, kind: sigKindECDSA, digest: digestSpecs[digestSHA256URI], hash: crypto.SHA256},
	sigECDSASHA384URI:  {uri: sigECDSASHA384URI, kind: sigKindECDSA, digest: digestSpecs[digestSHA384URI], hash: crypto.SHA384},
	sigECDSASHA512URI:  {uri: sigECDSASHA512URI, kind: sigKindECDSA, digest: digestSpecs[digestSHA512URI], hash: crypto.SHA512},
	sigEd25519URI:      {uri: sigEd25519URI, kind: sigKindEd25519},
	sigEd25519ShortURI: {uri: sigEd25519ShortURI, kind: sigKindEd25519},
	sigHMACSHA1URI:     {uri: sigHMACSHA1URI, kind: sigKindHMAC, digest: digestSpecs[digestSHA1URI], hash: crypto.SHA1},
	sigHMACSHA256URI:   {uri: sigHMACSHA256URI, kind: sigKindHMAC, digest: digestSpecs[digestSHA256URI], hash: crypto.SHA256},
	sigHMACSHA384URI:   {uri: sigHMACSHA384URI, kind: sigKindHMAC, digest: digestSpecs[digestSHA384URI], hash: crypto.SHA384},
	sigHMACSHA512URI:   {uri: sigHMACSHA512URI, kind: sigKindHMAC, digest: digestSpecs[digestSHA512URI], hash: crypto.SHA512},
	sigHMACSM3URI:      {uri: sigHMACSM3URI, kind: sigKindHMAC, digest: digestSpecs[digestSM3URI]},
	sigSM2SM3URI:       {uri: sigSM2SM3URI, kind: sigKindSM2},
	sigSM2SM3ShortURI:  {uri: sigSM2SM3ShortURI, kind: sigKindSM2},
}

// defaultSignatureURIs is the verification allowlist used when the caller supplies none. SHA-1
// and HMAC methods are deliberately absent. | defaultSignatureURIs 是调用方未提供时使用的校验
// 允许列表。SHA-1 与 HMAC 方法被刻意排除。
var defaultSignatureURIs = []string{
	sigRSASHA256URI, sigRSASHA384URI, sigRSASHA512URI,
	sigRSAPSSURI, sigRSAPSSSHA256URI, sigRSAPSSSHA384URI, sigRSAPSSSHA512URI,
	sigECDSASHA256URI, sigECDSASHA384URI, sigECDSASHA512URI,
	sigEd25519URI, sigEd25519ShortURI,
	sigSM2SM3URI, sigSM2SM3ShortURI,
}

// signatureSpecForURI resolves and authorizes a SignatureMethod URI. | signatureSpecForURI 解析并
// 授权 SignatureMethod URI。
func signatureSpecForURI(uri string, allowed []string) (signatureSpec, error) {
	spec, ok := signatureSpecs[uri]
	if !ok {
		return signatureSpec{}, errs.Detail(ErrUnsupported, "signature algorithm %q is not supported | 不支持签名算法 %q", uri, uri)
	}
	if !algorithmAllowed(uri, allowed, defaultSignatureURIs) {
		return signatureSpec{}, errs.Detail(ErrAlgorithmNotAllowed, "signature algorithm %q is not allowed | 签名算法 %q 不被允许", uri, uri)
	}
	return spec, nil
}

// algorithmAllowed applies an explicit allowlist, or the package default when allowed is empty. |
// algorithmAllowed 应用显式允许列表；allowed 为空时使用包默认值。
func algorithmAllowed(uri string, allowed, defaults []string) bool {
	list := allowed
	if len(list) == 0 {
		list = defaults
	}
	for _, candidate := range list {
		if candidate == uri {
			return true
		}
	}
	return false
}
