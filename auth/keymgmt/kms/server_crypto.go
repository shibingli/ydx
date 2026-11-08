package kms

import (
	"crypto"
	"net/http"
	"strings"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
)

// encryptJSON is the POST /encrypt request body. | encryptJSON 是 POST /encrypt 请求体。
type encryptJSON struct {
	// KeyID is the key identifier or alias. | KeyID 是密钥标识或别名。
	KeyID string `json:"keyId"`
	// Plaintext is standard Base64 plaintext. | Plaintext 是标准 Base64 明文。
	Plaintext string `json:"plaintext"`
	// AAD is optional standard Base64 associated data. | AAD 是可选标准 Base64 关联数据。
	AAD string `json:"aad"`
}

// decryptJSON is the POST /decrypt request body. | decryptJSON 是 POST /decrypt 请求体。
type decryptJSON struct {
	// KeyID is the key identifier or alias. | KeyID 是密钥标识或别名。
	KeyID string `json:"keyId"`
	// Ciphertext is standard Base64 KMS1 ciphertext. | Ciphertext 是标准 Base64 KMS1 密文。
	Ciphertext string `json:"ciphertext"`
	// AAD is optional standard Base64 associated data. | AAD 是可选标准 Base64 关联数据。
	AAD string `json:"aad"`
}

// signJSON is the POST /sign and POST /verify request body. | signJSON 是 POST /sign 与 POST /verify
// 请求体。
type signJSON struct {
	// KeyID is the key identifier or alias. | KeyID 是密钥标识或别名。
	KeyID string `json:"keyId"`
	// Data is standard Base64 input; for verify it is the signed message. | Data 是标准 Base64 输入；
	// 验签时是签名消息。
	Data string `json:"data"`
	// Signature is standard Base64 signature for verify. | Signature 是验签用的标准 Base64 签名。
	Signature string `json:"signature"`
	// Digest declares that Data is already a digest. | Digest 声明 Data 已是摘要。
	Digest bool `json:"digest"`
	// Hash selects SHA256 (default), SHA384 or SHA512. | Hash 选择 SHA256（默认）、SHA384 或 SHA512。
	Hash string `json:"hash"`
	// PSS selects RSA-PSS instead of PKCS#1 v1.5. | PSS 选择 RSA-PSS 而非 PKCS#1 v1.5。
	PSS bool `json:"pss"`
}

// generateDataKeyJSON is the POST /generate-data-key request body. | generateDataKeyJSON 是
// POST /generate-data-key 请求体。
type generateDataKeyJSON struct {
	// KeyID is the wrapping key identifier or alias. | KeyID 是包装密钥标识或别名。
	KeyID string `json:"keyId"`
	// Length is the DEK size; 0 means 32 bytes. | Length 是 DEK 长度；0 表示 32 字节。
	Length int `json:"length"`
	// AAD is optional standard Base64 associated data. | AAD 是可选标准 Base64 关联数据。
	AAD string `json:"aad"`
}

// randomJSON is the POST /random request body. | randomJSON 是 POST /random 请求体。
type randomJSON struct {
	// Length is the requested byte count. | Length 是请求的字节数。
	Length int `json:"length"`
}

// ciphertextResponse is the POST /encrypt response body. | ciphertextResponse 是 POST /encrypt 响应体。
type ciphertextResponse struct {
	// Ciphertext is standard Base64 KMS1 ciphertext. | Ciphertext 是标准 Base64 KMS1 密文。
	Ciphertext string `json:"ciphertext"`
}

// plaintextResponse is the POST /decrypt response body. | plaintextResponse 是 POST /decrypt 响应体。
type plaintextResponse struct {
	// Plaintext is standard Base64 plaintext. | Plaintext 是标准 Base64 明文。
	Plaintext string `json:"plaintext"`
}

// signatureResponse is the POST /sign response body. | signatureResponse 是 POST /sign 响应体。
type signatureResponse struct {
	// Signature is standard Base64 signature bytes. | Signature 是标准 Base64 签名字节。
	Signature string `json:"signature"`
	// Algorithm is the key algorithm label. | Algorithm 是密钥算法标签。
	Algorithm string `json:"algorithm,omitempty"`
}

// verifyResponse is the POST /verify response body. | verifyResponse 是 POST /verify 响应体。
type verifyResponse struct {
	// Valid reports whether the signature verified. | Valid 报告签名是否通过校验。
	Valid bool `json:"valid"`
}

// dataKeyResponse is the POST /generate-data-key response body. | dataKeyResponse 是
// POST /generate-data-key 响应体。
type dataKeyResponse struct {
	// Plaintext is standard Base64 DEK plaintext. | Plaintext 是标准 Base64 DEK 明文。
	Plaintext string `json:"plaintext"`
	// Wrapped is standard Base64 KMSW wrapped DEK. | Wrapped 是标准 Base64 KMSW 包装 DEK。
	Wrapped string `json:"wrapped"`
	// KeyID is the wrapping key identifier. | KeyID 是包装密钥标识。
	KeyID string `json:"keyId"`
	// KeyVersion is the wrapping key version. | KeyVersion 是包装密钥版本。
	KeyVersion uint32 `json:"keyVersion"`
}

// randomResponse is the POST /random response body. | randomResponse 是 POST /random 响应体。
type randomResponse struct {
	// Random is standard Base64 random bytes. | Random 是标准 Base64 随机字节。
	Random string `json:"random"`
}

// auditListResponse is the GET /audit response body. | auditListResponse 是 GET /audit 响应体。
type auditListResponse struct {
	// Events holds matching audit events. | Events 保存匹配的审计事件。
	Events []*AuditEvent `json:"events"`
	// Count is the number of returned events. | Count 是返回的事件数量。
	Count int `json:"count"`
}

// handleEncrypt serves POST /encrypt. | handleEncrypt 处理 POST /encrypt。
func (s *Server) handleEncrypt(w http.ResponseWriter, r *http.Request) {
	var body encryptJSON
	if err := s.decodeJSON(w, r, &body); err != nil {
		writeError(w, err)
		return
	}
	plaintext, err := decodeBase64(body.Plaintext, "plaintext")
	if err != nil {
		writeError(w, err)
		return
	}
	aad, err := decodeBase64(body.AAD, "aad")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.authorize(r, ActionEncrypt, body.KeyID); err != nil {
		writeError(w, err)
		return
	}
	ciphertext, err := s.service.Encrypt(s.requestContext(r), body.KeyID, plaintext, aad)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ciphertextResponse{Ciphertext: base64.StdEncoding.EncodeToString(ciphertext)})
}

// handleDecrypt serves POST /decrypt. | handleDecrypt 处理 POST /decrypt。
func (s *Server) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	var body decryptJSON
	if err := s.decodeJSON(w, r, &body); err != nil {
		writeError(w, err)
		return
	}
	ciphertext, err := decodeBase64(body.Ciphertext, "ciphertext")
	if err != nil {
		writeError(w, err)
		return
	}
	aad, err := decodeBase64(body.AAD, "aad")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.authorize(r, ActionDecrypt, body.KeyID); err != nil {
		writeError(w, err)
		return
	}
	plaintext, err := s.service.Decrypt(s.requestContext(r), body.KeyID, ciphertext, aad)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, plaintextResponse{Plaintext: base64.StdEncoding.EncodeToString(plaintext)})
}

// handleSign serves POST /sign. | handleSign 处理 POST /sign。
func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	var body signJSON
	if err := s.decodeJSON(w, r, &body); err != nil {
		writeError(w, err)
		return
	}
	data, err := decodeBase64(body.Data, "data")
	if err != nil {
		writeError(w, err)
		return
	}
	options, err := signOptionsFromJSON(body)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.authorize(r, ActionSign, body.KeyID); err != nil {
		writeError(w, err)
		return
	}
	ctx := s.requestContext(r)
	signature, err := s.service.Sign(ctx, body.KeyID, data, options...)
	if err != nil {
		writeError(w, err)
		return
	}
	algorithm := ""
	if key, keyErr := s.service.Resolve(ctx, body.KeyID); keyErr == nil {
		algorithm = key.Algorithm
	}
	writeJSON(w, http.StatusOK, signatureResponse{Signature: base64.StdEncoding.EncodeToString(signature), Algorithm: algorithm})
}

// handleVerify serves POST /verify. | handleVerify 处理 POST /verify。
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var body signJSON
	if err := s.decodeJSON(w, r, &body); err != nil {
		writeError(w, err)
		return
	}
	data, err := decodeBase64(body.Data, "data")
	if err != nil {
		writeError(w, err)
		return
	}
	signature, err := decodeBase64(body.Signature, "signature")
	if err != nil {
		writeError(w, err)
		return
	}
	options, err := signOptionsFromJSON(body)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.authorize(r, ActionVerify, body.KeyID); err != nil {
		writeError(w, err)
		return
	}
	valid, err := s.service.Verify(s.requestContext(r), body.KeyID, data, signature, options...)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, verifyResponse{Valid: valid})
}

// handleGenerateDataKey serves POST /generate-data-key. | handleGenerateDataKey 处理 POST /generate-data-key。
func (s *Server) handleGenerateDataKey(w http.ResponseWriter, r *http.Request) {
	var body generateDataKeyJSON
	if err := s.decodeJSON(w, r, &body); err != nil {
		writeError(w, err)
		return
	}
	aad, err := decodeBase64(body.AAD, "aad")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.authorize(r, ActionGenerateDataKey, body.KeyID); err != nil {
		writeError(w, err)
		return
	}
	key, err := s.service.GenerateDataKey(s.requestContext(r), body.KeyID, body.Length, aad)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, dataKeyResponse{
		Plaintext:  base64.StdEncoding.EncodeToString(key.Plaintext),
		Wrapped:    base64.StdEncoding.EncodeToString(key.Wrapped),
		KeyID:      key.KeyID,
		KeyVersion: key.KeyVersion,
	})
}

// handleRandom serves POST /random. | handleRandom 处理 POST /random。
func (s *Server) handleRandom(w http.ResponseWriter, r *http.Request) {
	var body randomJSON
	if err := s.decodeJSON(w, r, &body); err != nil {
		writeError(w, err)
		return
	}
	if err := s.authorize(r, ActionRandom, ""); err != nil {
		writeError(w, err)
		return
	}
	random, err := s.service.GenerateRandom(s.requestContext(r), body.Length)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, randomResponse{Random: base64.StdEncoding.EncodeToString(random)})
}

// handleListAudit serves GET /audit. | handleListAudit 处理 GET /audit。
func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	filter, err := auditFilterFromQuery(r)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.authorize(r, ActionAudit, filter.KeyID); err != nil {
		writeError(w, err)
		return
	}
	events, err := s.service.ListAudit(s.requestContext(r), filter)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, auditListResponse{Events: events, Count: len(events)})
}

// signOptionsFromJSON converts JSON signature knobs to SignOption values. | signOptionsFromJSON 把
// JSON 签名开关转换为 SignOption。
func signOptionsFromJSON(body signJSON) ([]SignOption, error) {
	options := make([]SignOption, 0, 3)
	if body.Digest {
		options = append(options, WithDigest())
	}
	if body.PSS {
		options = append(options, WithPSS())
	}
	switch strings.ToUpper(strings.TrimSpace(body.Hash)) {
	case "", "SHA256", "SHA-256":
		options = append(options, WithHash(crypto.SHA256))
	case "SHA384", "SHA-384":
		options = append(options, WithHash(crypto.SHA384))
	case "SHA512", "SHA-512":
		options = append(options, WithHash(crypto.SHA512))
	default:
		return nil, errs.Detail(ErrInvalidRequest, "unsupported hash %[1]q | 不支持的摘要 %[1]q", body.Hash)
	}
	return options, nil
}

// auditFilterFromQuery builds an AuditFilter from URL query parameters. | auditFilterFromQuery 由 URL
// 查询参数构建 AuditFilter。
func auditFilterFromQuery(r *http.Request) (AuditFilter, error) {
	query := r.URL.Query()
	offset, err := queryInt(r, "offset")
	if err != nil {
		return AuditFilter{}, err
	}
	limit, err := queryInt(r, "limit")
	if err != nil {
		return AuditFilter{}, err
	}
	since, err := queryTime(r, "since")
	if err != nil {
		return AuditFilter{}, err
	}
	until, err := queryTime(r, "until")
	if err != nil {
		return AuditFilter{}, err
	}
	descending := false
	switch strings.ToLower(strings.TrimSpace(query.Get("descending"))) {
	case "", "false", "0":
	case "true", "1":
		descending = true
	default:
		return AuditFilter{}, errs.Detail(ErrInvalidRequest, "query descending must be boolean | 查询参数 descending 必须为布尔值")
	}
	return AuditFilter{
		Operation:  strings.TrimSpace(query.Get("operation")),
		KeyID:      strings.TrimSpace(query.Get("keyId")),
		Actor:      strings.TrimSpace(query.Get("actor")),
		Outcome:    strings.TrimSpace(query.Get("outcome")),
		Since:      since,
		Until:      until,
		Offset:     offset,
		Limit:      limit,
		Descending: descending,
	}, nil
}
