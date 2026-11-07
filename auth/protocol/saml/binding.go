package saml

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/guomi"
)

// XML Signature algorithm URIs used by the HTTP-Redirect binding. | HTTP-Redirect 绑定使用的 XML 签名算法 URI。
const (
	// SigAlgRSASHA256 is RSA PKCS#1 v1.5 with SHA-256. | SigAlgRSASHA256 是 RSA PKCS#1 v1.5 + SHA-256。
	SigAlgRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	// SigAlgRSASHA384 is RSA PKCS#1 v1.5 with SHA-384. | SigAlgRSASHA384 是 RSA PKCS#1 v1.5 + SHA-384。
	SigAlgRSASHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	// SigAlgRSASHA512 is RSA PKCS#1 v1.5 with SHA-512. | SigAlgRSASHA512 是 RSA PKCS#1 v1.5 + SHA-512。
	SigAlgRSASHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	// SigAlgRSAPSSSHA256 is RSA-PSS with SHA-256. | SigAlgRSAPSSSHA256 是 RSA-PSS + SHA-256。
	SigAlgRSAPSSSHA256 = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1"
	// SigAlgECDSASHA256 is ECDSA with SHA-256. | SigAlgECDSASHA256 是 ECDSA + SHA-256。
	SigAlgECDSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	// SigAlgECDSASHA384 is ECDSA with SHA-384. | SigAlgECDSASHA384 是 ECDSA + SHA-384。
	SigAlgECDSASHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	// SigAlgECDSASHA512 is ECDSA with SHA-512. | SigAlgECDSASHA512 是 ECDSA + SHA-512。
	SigAlgECDSASHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
	// SigAlgEd25519 is EdDSA with Ed25519. | SigAlgEd25519 是 EdDSA + Ed25519。
	SigAlgEd25519 = "http://www.w3.org/2001/04/xmldsig-more#eddsa-ed25519"
	// SigAlgSM2SM3 is SM2 with SM3 for Chinese deployments. | SigAlgSM2SM3 是中国部署使用的 SM2 + SM3。
	SigAlgSM2SM3 = "http://www.w3.org/2001/04/xmldsig-more#sm2-sm3"
	// SigAlgHMACSHA256 is HMAC-SHA256 for test and legacy deployments. | SigAlgHMACSHA256 是用于测试与遗留部署的 HMAC-SHA256。
	SigAlgHMACSHA256 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"
)

// SAML message bounds protect bindings from decompression and form-body exhaustion. |
// SAML 消息上限保护绑定免受解压缩与表单体耗尽攻击。
const (
	// MaxSAMLMessageBytes bounds one decoded or inflated SAML message. | MaxSAMLMessageBytes 约束
	// 单个解码或解压后的 SAML 消息大小。
	MaxSAMLMessageBytes = 16 << 20
	// MaxSAMLFormBytes bounds one HTTP-POST form body. | MaxSAMLFormBytes 约束单个 HTTP-POST
	// 表单体大小。
	MaxSAMLFormBytes = 32 << 20
)

// boundFormBody limits a request body before form parsing. | boundFormBody 在解析表单前限制请求体。
func boundFormBody(w http.ResponseWriter, r *http.Request) {
	if r == nil || r.Body == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxSAMLFormBytes)
}

// checkFormBody rejects a declared oversized form body. | checkFormBody 拒绝声明的超大表单体。
func checkFormBody(r *http.Request) error {
	if r == nil || r.ContentLength <= MaxSAMLFormBytes {
		return nil
	}
	return errs.Detail(ErrLimit, "SAML form body exceeds %d bytes | SAML 表单体超过 %d 字节", MaxSAMLFormBytes, MaxSAMLFormBytes)
}

// formParseError maps body-limit failures to ErrLimit. | formParseError 把正文大小超限映射为 ErrLimit。
func formParseError(err error) error {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		return errs.Detail(ErrLimit, "SAML form body exceeds %d bytes | SAML 表单体超过 %d 字节", MaxSAMLFormBytes, MaxSAMLFormBytes)
	}
	return errs.Wrap(err, ErrInvalidBinding)
}

// EncodePost returns the base64 form used by the HTTP-POST binding. | EncodePost 返回 HTTP-POST 绑定使用的 base64 形式。
func EncodePost(data []byte) string { return base64.StdEncoding.EncodeToString(data) }

// DecodePost decodes the base64 form used by the HTTP-POST binding. Whitespace inside the value
// and missing padding are tolerated. | DecodePost 解码 HTTP-POST 绑定使用的 base64 形式。容忍值中
// 的空白与缺失的填充。
func DecodePost(value string) ([]byte, error) {
	return decodeSAMLBase64(value)
}

// EncodeRedirect deflates and base64-encodes data for the HTTP-Redirect binding. | EncodeRedirect 为
// HTTP-Redirect 绑定压缩并 base64 编码 data。
func EncodeRedirect(data []byte) (string, error) {
	var compressed bytes.Buffer
	writer, err := flate.NewWriter(&compressed, flate.DefaultCompression)
	if err != nil {
		return "", errs.Wrap(err, ErrInvalidBinding)
	}
	if _, err := writer.Write(data); err != nil {
		return "", errs.Wrap(err, ErrInvalidBinding)
	}
	if err := writer.Close(); err != nil {
		return "", errs.Wrap(err, ErrInvalidBinding)
	}
	return base64.StdEncoding.EncodeToString(compressed.Bytes()), nil
}

// DecodeRedirect inflates an HTTP-Redirect binding value. The value may be URL-escaped again and
// may use zlib instead of raw DEFLATE. Inflated output is bounded by MaxSAMLMessageBytes. |
// DecodeRedirect 解压 HTTP-Redirect 绑定值。值可再次经过 URL 转义，也可使用 zlib 而非原始 DEFLATE。
// 解压输出受 MaxSAMLMessageBytes 约束。
func DecodeRedirect(value string) ([]byte, error) {
	decoded, err := url.QueryUnescape(strings.TrimSpace(value))
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidBinding)
	}
	raw, err := decodeSAMLBase64(decoded)
	if err != nil {
		return nil, err
	}
	inflated, ferr := inflate(raw)
	if ferr == nil {
		return inflated, nil
	}
	if errors.Is(ferr, ErrLimit) {
		return nil, ferr
	}
	// A few providers use zlib instead of raw DEFLATE. | 少数提供方使用 zlib 而非原始 DEFLATE。
	reader, zerr := zlib.NewReader(bytes.NewReader(raw))
	if zerr != nil {
		return nil, errs.Wrap(ferr, ErrInvalidBinding)
	}
	defer func() { _ = reader.Close() }()
	inflated, rerr := readAllLimited(reader, MaxSAMLMessageBytes)
	if rerr != nil {
		return nil, rerr
	}
	return inflated, nil
}

// inflate inflates raw DEFLATE data with a hard output bound. | inflate 在硬性输出上限下解压原始
// DEFLATE 数据。
func inflate(data []byte) ([]byte, error) {
	reader := flate.NewReader(bytes.NewReader(data))
	defer func() { _ = reader.Close() }()
	return readAllLimited(reader, MaxSAMLMessageBytes)
}

// readAllLimited reads at most limit bytes and reports ErrLimit when the stream is longer. |
// readAllLimited 最多读取 limit 字节；流更长时返回 ErrLimit。
func readAllLimited(reader io.Reader, limit int64) ([]byte, error) {
	out, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidBinding)
	}
	if int64(len(out)) > limit {
		return nil, errs.Detail(ErrLimit, "SAML message exceeds %d bytes | SAML 消息超过 %d 字节", limit, limit)
	}
	return out, nil
}

// decodeSAMLBase64 tolerates wrapped whitespace, literal spaces produced by '+' decoding and
// missing padding. | decodeSAMLBase64 容忍换行空白、由 '+' 解码产生的字面空格与缺失的填充。
func decodeSAMLBase64(value string) ([]byte, error) {
	compact := strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', '\t':
			return -1
		default:
			return r
		}
	}, value)
	if compact == "" {
		return nil, errs.Detail(ErrInvalidBinding, "SAML message is empty | SAML 消息为空")
	}
	decoded, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		// Some providers send '+' as a literal space in the query string. | 一些提供方在查询串中把
		// '+' 发送为字面空格。
		decoded, err = base64.StdEncoding.DecodeString(strings.ReplaceAll(compact, " ", "+"))
	}
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(strings.ReplaceAll(compact, " ", "+"))
	}
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidBinding)
	}
	if len(decoded) > MaxSAMLMessageBytes {
		return nil, errs.Detail(ErrLimit, "SAML message exceeds %d bytes | SAML 消息超过 %d 字节", MaxSAMLMessageBytes, MaxSAMLMessageBytes)
	}
	return decoded, nil
}

// RedirectSigningString builds the exact string covered by an HTTP-Redirect signature. | RedirectSigningString
// 构建 HTTP-Redirect 签名覆盖的精确字符串。
func RedirectSigningString(request, relayState, sigAlg string) string {
	return RedirectSigningStringFor("SAMLRequest", request, relayState, sigAlg)
}

// RedirectSigningStringFor builds the redirect signing string for the named message parameter. |
// RedirectSigningStringFor 为指定的消息参数构建重定向签名字符串。
func RedirectSigningStringFor(parameter, request, relayState, sigAlg string) string {
	var b strings.Builder
	b.WriteString(parameter)
	b.WriteByte('=')
	b.WriteString(url.QueryEscape(request))
	if relayState != "" {
		b.WriteString("&RelayState=")
		b.WriteString(url.QueryEscape(relayState))
	}
	b.WriteString("&SigAlg=")
	b.WriteString(url.QueryEscape(sigAlg))
	return b.String()
}

// redirectMessageParameters lists the message parameter names accepted by redirect signing. |
// redirectMessageParameters 列出重定向签名接受的消息参数名。
var redirectMessageParameters = map[string]struct{}{
	"SAMLRequest":  {},
	"SAMLResponse": {},
}

// validateRedirectParameter rejects parameter names that could break the signed query layout. |
// validateRedirectParameter 拒绝可能破坏签名查询布局的参数名。
func validateRedirectParameter(parameter string) error {
	if _, ok := redirectMessageParameters[parameter]; !ok {
		return errs.Detail(ErrInvalidBinding, "unsupported redirect message parameter %q | 不支持的重定向消息参数 %q", parameter, parameter)
	}
	return nil
}

// SignRedirect adds SigAlg and Signature to a SAMLRequest redirect query. | SignRedirect 把 SigAlg
// 与 Signature 加入 SAMLRequest 重定向查询。
func SignRedirect(params url.Values, key any, sigAlg string, relayState string) error {
	return SignRedirectMessage(params, "SAMLRequest", key, sigAlg, relayState)
}

// SignRedirectMessage adds SigAlg and Signature for the named message parameter. | SignRedirectMessage
// 为指定的消息参数加入 SigAlg 与 Signature。
func SignRedirectMessage(params url.Values, parameter string, key any, sigAlg string, relayState string) error {
	if err := validateRedirectParameter(parameter); err != nil {
		return err
	}
	if sigAlg == "" {
		return errs.Detail(ErrInvalidBinding, "SigAlg is missing | 缺少 SigAlg")
	}
	if params.Get(parameter) == "" {
		return errs.Detail(ErrInvalidBinding, "%s is missing | 缺少 %s", parameter, parameter)
	}
	signing := RedirectSigningStringFor(parameter, params.Get(parameter), relayState, sigAlg)
	signature, err := signRedirectBytes(signing, key, sigAlg)
	if err != nil {
		return err
	}
	params.Set("SigAlg", sigAlg)
	params.Set("Signature", base64.StdEncoding.EncodeToString(signature))
	return nil
}

// VerifyRedirect verifies the HTTP-Redirect signature of a SAMLRequest query. | VerifyRedirect 校验
// SAMLRequest 查询的 HTTP-Redirect 签名。
func VerifyRedirect(params url.Values, certificates []*x509.Certificate, hmacKey []byte, sm2Key *guomi.PublicKey, relayState string) error {
	return VerifyRedirectMessage(params, "SAMLRequest", certificates, hmacKey, sm2Key, relayState)
}

// VerifyRedirectMessage verifies the HTTP-Redirect signature for the named message parameter. |
// VerifyRedirectMessage 校验指定消息参数的 HTTP-Redirect 签名。
func VerifyRedirectMessage(params url.Values, parameter string, certificates []*x509.Certificate, hmacKey []byte, sm2Key *guomi.PublicKey, relayState string) error {
	if err := validateRedirectParameter(parameter); err != nil {
		return err
	}
	if params.Get(parameter) == "" {
		return errs.Detail(ErrInvalidBinding, "%s is missing | 缺少 %s", parameter, parameter)
	}
	sigAlg := params.Get("SigAlg")
	signature, err := decodeSAMLBase64(params.Get("Signature"))
	if err != nil || sigAlg == "" || len(signature) == 0 {
		return errs.Detail(ErrInvalidSignature, "redirect signature is missing | 缺少重定向签名")
	}
	if _, _, err := redirectAlgorithm(sigAlg); err != nil {
		return err
	}
	signing := RedirectSigningStringFor(parameter, params.Get(parameter), relayState, sigAlg)
	return verifyRedirectSignature(signing, signature, sigAlg, certificates, hmacKey, sm2Key)
}

// VerifyRedirectRawQuery verifies a redirect query using the exact raw URL encoding found in the
// query string, which preserves provider-specific escaping such as %20 versus '+'. | VerifyRedirectRawQuery
// 使用查询串中的精确原始 URL 编码校验重定向查询，从而保留 %20 与 '+' 等提供方特有转义。
func VerifyRedirectRawQuery(rawQuery, parameter string, certificates []*x509.Certificate, hmacKey []byte, sm2Key *guomi.PublicKey) error {
	if err := validateRedirectParameter(parameter); err != nil {
		return err
	}
	request, ok := rawQueryValue(rawQuery, parameter)
	if !ok || request == "" {
		return errs.Detail(ErrInvalidBinding, "%s is missing | 缺少 %s", parameter, parameter)
	}
	rawSigAlg, ok := rawQueryValue(rawQuery, "SigAlg")
	if !ok || rawSigAlg == "" {
		return errs.Detail(ErrInvalidSignature, "SigAlg is missing | 缺少 SigAlg")
	}
	sigAlg, err := url.QueryUnescape(rawSigAlg)
	if err != nil {
		return errs.Wrap(err, ErrInvalidBinding)
	}
	rawSignature, ok := rawQueryValue(rawQuery, "Signature")
	if !ok || rawSignature == "" {
		return errs.Detail(ErrInvalidSignature, "redirect signature is missing | 缺少重定向签名")
	}
	decodedSignature, err := url.QueryUnescape(rawSignature)
	if err != nil {
		return errs.Wrap(err, ErrInvalidBinding)
	}
	signature, err := decodeSAMLBase64(decodedSignature)
	if err != nil || len(signature) == 0 {
		return errs.Detail(ErrInvalidSignature, "redirect signature is missing | 缺少重定向签名")
	}
	if _, _, err := redirectAlgorithm(sigAlg); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString(parameter)
	b.WriteByte('=')
	b.WriteString(request)
	if relayState, ok := rawQueryValue(rawQuery, "RelayState"); ok {
		b.WriteString("&RelayState=")
		b.WriteString(relayState)
	}
	b.WriteString("&SigAlg=")
	b.WriteString(rawSigAlg)
	return verifyRedirectSignature(b.String(), signature, sigAlg, certificates, hmacKey, sm2Key)
}

// rawQueryValue returns the raw, still-encoded value of key in rawQuery. | rawQueryValue 返回 rawQuery
// 中 key 的原始未解码值。
func rawQueryValue(rawQuery, key string) (string, bool) {
	for _, pair := range strings.Split(rawQuery, "&") {
		name, value, _ := strings.Cut(pair, "=")
		if name == key {
			return value, true
		}
	}
	return "", false
}

// verifyRedirectSignature verifies one redirect signature with the configured key material. |
// verifyRedirectSignature 使用已配置的密钥材料校验单个重定向签名。
func verifyRedirectSignature(signing string, signature []byte, sigAlg string, certificates []*x509.Certificate, hmacKey []byte, sm2Key *guomi.PublicKey) error {
	if hmacKey != nil {
		return verifyHMACRedirect(signing, signature, hmacKey, sigAlg)
	}
	if sm2Key != nil && sigAlg == SigAlgSM2SM3 {
		ok, err := guomi.Verify(sm2Key, []byte(signing), signature)
		if err != nil || !ok {
			return ErrInvalidSignature
		}
		return nil
	}
	for _, cert := range certificates {
		if cert == nil {
			continue
		}
		if err := verifyRedirectWithKey(signing, signature, cert.PublicKey, sigAlg); err == nil {
			return nil
		}
	}
	return errs.Detail(ErrInvalidSignature, "no certificate verified the redirect signature | 没有证书通过重定向签名校验")
}

// signRedirectBytes signs the redirect string. | signRedirectBytes 对重定向字符串签名。
func signRedirectBytes(signing string, key any, sigAlg string) ([]byte, error) {
	hash, family, err := redirectAlgorithm(sigAlg)
	if err != nil {
		return nil, err
	}
	if family == "sm2" {
		priv, ok := key.(*guomi.PrivateKey)
		if !ok {
			return nil, errs.Detail(ErrInvalidSignature, "redirect signature needs an SM2 private key | 重定向签名需要 SM2 私钥")
		}
		return guomi.Sign(priv, []byte(signing))
	}
	digest, err := digestBytes(signing, hash)
	if err != nil {
		return nil, err
	}
	switch family {
	case "rsa":
		priv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errs.Detail(ErrInvalidSignature, "redirect signature needs an RSA private key | 重定向签名需要 RSA 私钥")
		}
		return rsa.SignPKCS1v15(rand.Reader, priv, hash, digest)
	case "rsa-pss":
		priv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errs.Detail(ErrInvalidSignature, "redirect signature needs an RSA private key | 重定向签名需要 RSA 私钥")
		}
		return rsa.SignPSS(rand.Reader, priv, hash, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hash})
	case "ecdsa":
		priv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errs.Detail(ErrInvalidSignature, "redirect signature needs an ECDSA private key | 重定向签名需要 ECDSA 私钥")
		}
		return ecdsa.SignASN1(rand.Reader, priv, digest)
	case "ed25519":
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, errs.Detail(ErrInvalidSignature, "redirect signature needs an Ed25519 private key | 重定向签名需要 Ed25519 私钥")
		}
		return ed25519.Sign(priv, []byte(signing)), nil
	case "hmac":
		secret, ok := key.([]byte)
		if !ok {
			return nil, errs.Detail(ErrInvalidSignature, "redirect HMAC needs a []byte key | 重定向 HMAC 需要 []byte 密钥")
		}
		mac := hmac.New(hash.New, secret)
		mac.Write([]byte(signing))
		return mac.Sum(nil), nil
	default:
		return nil, errs.Detail(ErrInvalidBinding, "unsupported redirect signature %[1]q | 不支持的重定向签名 %[1]q", sigAlg)
	}
}

// verifyRedirectWithKey verifies a redirect signature with a public key. | verifyRedirectWithKey 用公钥校验重定向签名。
func verifyRedirectWithKey(signing string, signature []byte, public any, sigAlg string) error {
	hash, family, err := redirectAlgorithm(sigAlg)
	if err != nil {
		return err
	}
	digest, err := digestBytes(signing, hash)
	if err != nil {
		return err
	}
	switch family {
	case "rsa":
		key, ok := public.(*rsa.PublicKey)
		if !ok {
			return ErrInvalidSignature
		}
		return rsa.VerifyPKCS1v15(key, hash, digest, signature)
	case "rsa-pss":
		key, ok := public.(*rsa.PublicKey)
		if !ok {
			return ErrInvalidSignature
		}
		return rsa.VerifyPSS(key, hash, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: hash})
	case "ecdsa":
		key, ok := public.(*ecdsa.PublicKey)
		if !ok {
			return ErrInvalidSignature
		}
		if !ecdsa.VerifyASN1(key, digest, signature) {
			return ErrInvalidSignature
		}
		return nil
	case "ed25519":
		key, ok := public.(ed25519.PublicKey)
		if !ok {
			return ErrInvalidSignature
		}
		if !ed25519.Verify(key, []byte(signing), signature) {
			return ErrInvalidSignature
		}
		return nil
	default:
		return ErrInvalidSignature
	}
}

// verifyHMACRedirect verifies an HMAC redirect signature. | verifyHMACRedirect 校验 HMAC 重定向签名。
func verifyHMACRedirect(signing string, signature, secret []byte, sigAlg string) error {
	hash, family, err := redirectAlgorithm(sigAlg)
	if err != nil || family != "hmac" {
		return ErrInvalidSignature
	}
	mac := hmac.New(hash.New, secret)
	mac.Write([]byte(signing))
	if !hmac.Equal(mac.Sum(nil), signature) {
		return ErrInvalidSignature
	}
	return nil
}

// redirectAlgorithm maps a redirect signature URI to a hash and key family. | redirectAlgorithm 把
// 重定向签名 URI 映射为哈希与密钥族。
func redirectAlgorithm(sigAlg string) (crypto.Hash, string, error) {
	switch sigAlg {
	case SigAlgRSASHA256:
		return crypto.SHA256, "rsa", nil
	case SigAlgRSASHA384:
		return crypto.SHA384, "rsa", nil
	case SigAlgRSASHA512:
		return crypto.SHA512, "rsa", nil
	case SigAlgRSAPSSSHA256:
		return crypto.SHA256, "rsa-pss", nil
	case SigAlgECDSASHA256:
		return crypto.SHA256, "ecdsa", nil
	case SigAlgECDSASHA384:
		return crypto.SHA384, "ecdsa", nil
	case SigAlgECDSASHA512:
		return crypto.SHA512, "ecdsa", nil
	case SigAlgEd25519:
		return crypto.SHA512, "ed25519", nil
	case SigAlgSM2SM3:
		return 0, "sm2", nil
	case SigAlgHMACSHA256:
		return crypto.SHA256, "hmac", nil
	default:
		return 0, "", errs.Detail(ErrInvalidBinding, "unsupported signature algorithm %[1]q | 不支持的签名算法 %[1]q", sigAlg)
	}
}

// digestBytes hashes value with hash. | digestBytes 用 hash 对 value 求摘要。
func digestBytes(value string, hash crypto.Hash) ([]byte, error) {
	if !hash.Available() {
		return nil, errs.Detail(ErrInvalidBinding, "hash is unavailable | 哈希不可用")
	}
	h := hash.New()
	h.Write([]byte(value))
	return h.Sum(nil), nil
}

// PostFormHTML returns an auto-submitting SAML POST form. | PostFormHTML 返回自动提交的 SAML POST 表单。
func PostFormHTML(action, parameter, value, relayState string) string {
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>Continue</title></head><body>")
	b.WriteString("<form id=\"saml\" method=\"post\" action=\"")
	b.WriteString(htmlEscape(action))
	b.WriteString("\"><input type=\"hidden\" name=\"")
	b.WriteString(htmlEscape(parameter))
	b.WriteString("\" value=\"")
	b.WriteString(htmlEscape(value))
	b.WriteString("\">")
	if relayState != "" {
		b.WriteString("<input type=\"hidden\" name=\"RelayState\" value=\"")
		b.WriteString(htmlEscape(relayState))
		b.WriteString("\">")
	}
	b.WriteString("</form><script>document.getElementById('saml').submit()</script></body></html>")
	return b.String()
}

// WritePostForm writes the auto-submitting SAML POST form. | WritePostForm 写入自动提交的 SAML POST 表单。
func WritePostForm(w http.ResponseWriter, action, parameter, value, relayState string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(PostFormHTML(action, parameter, value, relayState)))
}

// htmlEscape escapes a string for HTML text and attribute context. | htmlEscape 为 HTML 文本与属性上下文转义字符串。
func htmlEscape(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&#34;")
		case '\'':
			b.WriteString("&#39;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
