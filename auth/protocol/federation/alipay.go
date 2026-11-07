package federation

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"sort"
	"strings"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
)

// SignAlipayRSA2 returns a Base64 RSA2 (SHA256withRSA) signature over the sorted,
// non-empty, non-sign parameters of an Alipay OpenAPI request. | SignAlipayRSA2 返回支付宝
// OpenAPI 请求中排序后非空且非 sign 参数的 Base64 RSA2（SHA256withRSA）签名。
func SignAlipayRSA2(params map[string]string, privateKeyPEM string) (string, error) {
	key, err := parseAlipayPrivateKey(privateKeyPEM)
	if err != nil {
		return "", err
	}
	content := alipayCanonicalString(params)
	digest := sha256.Sum256([]byte(content))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", errs.Detail(ErrSigning, "RSA2 signature failed | RSA2 签名失败")
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// signAlipayRequest signs params and stores the Base64 signature in params["sign"].
// signAlipayRequest 对 params 签名并把 Base64 签名写入 params["sign"]。
func signAlipayRequest(params map[string]string, privateKey string) error {
	if len(params) == 0 {
		return errs.Detail(ErrSigning, "alipay parameters are empty | 支付宝参数为空")
	}
	if strings.TrimSpace(privateKey) == "" {
		return errs.Detail(ErrSigning, "alipay private key is empty | 支付宝私钥为空")
	}
	signature, err := SignAlipayRSA2(params, privateKey)
	if err != nil {
		return err
	}
	params["sign"] = signature
	return nil
}

// alipayCanonicalString builds the Alipay signing string. | alipayCanonicalString 构建支付宝签名串。
func alipayCanonicalString(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for key, value := range params {
		if key == "sign" || value == "" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var builder strings.Builder
	for index, key := range keys {
		if index > 0 {
			builder.WriteByte('&')
		}
		builder.WriteString(key)
		builder.WriteByte('=')
		builder.WriteString(params[key])
	}
	return builder.String()
}

// parseAlipayPrivateKey parses a PEM or Base64 DER PKCS#8/PKCS#1 RSA private key.
// parseAlipayPrivateKey 解析 PEM 或 Base64 DER 的 PKCS#8/PKCS#1 RSA 私钥。
func parseAlipayPrivateKey(value string) (*rsa.PrivateKey, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errs.Detail(ErrSigning, "alipay private key is empty | 支付宝私钥为空")
	}
	if block, _ := pem.Decode([]byte(value)); block != nil {
		if key, err := parseRSAKeyDER(block.Bytes); err == nil {
			return key, nil
		}
		return nil, errs.Detail(ErrSigning, "alipay PEM private key is invalid | 支付宝 PEM 私钥非法")
	}
	compact := strings.Join(strings.Fields(value), "")
	der, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		der, err = base64.RawStdEncoding.DecodeString(compact)
	}
	if err != nil {
		return nil, errs.Detail(ErrSigning, "alipay private key is not PEM or Base64 DER | 支付宝私钥不是 PEM 或 Base64 DER")
	}
	key, err := parseRSAKeyDER(der)
	if err != nil {
		return nil, errs.Detail(ErrSigning, "alipay DER private key is invalid | 支付宝 DER 私钥非法")
	}
	return key, nil
}

// parseRSAKeyDER parses PKCS#8 or PKCS#1 DER. | parseRSAKeyDER 解析 PKCS#8 或 PKCS#1 DER。
func parseRSAKeyDER(der []byte) (*rsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
	}
	key, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return nil, err
	}
	return key, nil
}
