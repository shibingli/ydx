package kmip

import "github.com/shibingli/ydx/errs"

// EncryptRequest is a KMIP Encrypt request payload. | EncryptRequest 是 KMIP Encrypt 请求负载。
type EncryptRequest struct {
	// UniqueIdentifier identifies the encryption key. | UniqueIdentifier 标识加密密钥。
	UniqueIdentifier string
	// CryptographicParameters holds optional encryption parameters. | CryptographicParameters 保存可选加密参数。
	CryptographicParameters *CryptographicParameters
	// Data is the plaintext. | Data 是明文。
	Data []byte
	// IVCounterNonce is an optional IV, counter or nonce. | IVCounterNonce 是可选 IV、计数器或随机数。
	IVCounterNonce []byte
	// CorrelationValue correlates streaming encryption calls. | CorrelationValue 关联流式加密调用。
	CorrelationValue []byte
	// InitIndicator marks the first call of a streaming operation. | InitIndicator 标记流式操作的第一次调用。
	InitIndicator *bool
	// FinalIndicator marks the last call of a streaming operation. | FinalIndicator 标记流式操作的最后一次调用。
	FinalIndicator *bool
	// AuthenticatedEncryptionAdditionalData is optional AEAD associated data. | AuthenticatedEncryptionAdditionalData 是可选 AEAD 关联数据。
	AuthenticatedEncryptionAdditionalData []byte
}

// Item encodes the Encrypt request payload. | Item 编码 Encrypt 请求负载。
func (p EncryptRequest) Item() (Item, error) {
	children := appendText(nil, TagUniqueIdentifier, p.UniqueIdentifier)
	if p.CryptographicParameters != nil {
		children = append(children, p.CryptographicParameters.Item())
	}
	children = appendBytes(children, TagData, p.Data)
	children = appendBytes(children, TagIVCounterNonce, p.IVCounterNonce)
	children = appendBytes(children, TagCorrelationValue, p.CorrelationValue)
	children = appendBoolPtr(children, TagInitIndicator, p.InitIndicator)
	children = appendBoolPtr(children, TagFinalIndicator, p.FinalIndicator)
	children = appendBytes(children, TagAuthenticatedEncryptionAdditionalData, p.AuthenticatedEncryptionAdditionalData)
	return payloadItem(TagRequestPayload, children...), nil
}

// DecodeEncryptRequest decodes an Encrypt request payload. | DecodeEncryptRequest 解码 Encrypt 请求负载。
func DecodeEncryptRequest(item Item) (EncryptRequest, error) {
	if item.Type != TypeStructure {
		return EncryptRequest{}, errs.Detail(ErrMalformed, "Encrypt request payload is not a structure | Encrypt 请求负载不是结构")
	}
	var out EncryptRequest
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	out.CryptographicParameters, err = optionalCryptographicParameters(item)
	if err != nil {
		return out, err
	}
	out.Data, err = childBytes(item, TagData)
	if err != nil {
		return out, err
	}
	out.IVCounterNonce, err = childBytes(item, TagIVCounterNonce)
	if err != nil {
		return out, err
	}
	out.CorrelationValue, err = childBytes(item, TagCorrelationValue)
	if err != nil {
		return out, err
	}
	out.InitIndicator, err = childBoolPtr(item, TagInitIndicator)
	if err != nil {
		return out, err
	}
	out.FinalIndicator, err = childBoolPtr(item, TagFinalIndicator)
	if err != nil {
		return out, err
	}
	out.AuthenticatedEncryptionAdditionalData, err = childBytes(item, TagAuthenticatedEncryptionAdditionalData)
	if err != nil {
		return out, err
	}
	return out, nil
}

// EncryptResponse is a KMIP Encrypt response payload. | EncryptResponse 是 KMIP Encrypt 响应负载。
type EncryptResponse struct {
	// UniqueIdentifier is the encryption key identifier. | UniqueIdentifier 是加密密钥标识符。
	UniqueIdentifier string
	// Data is the ciphertext. | Data 是密文。
	Data []byte
	// IVCounterNonce is the IV, counter or nonce used. | IVCounterNonce 是使用的 IV、计数器或随机数。
	IVCounterNonce []byte
	// CorrelationValue correlates streaming encryption calls. | CorrelationValue 关联流式加密调用。
	CorrelationValue []byte
	// AuthenticatedEncryptionTag is the AEAD tag. | AuthenticatedEncryptionTag 是 AEAD 标签。
	AuthenticatedEncryptionTag []byte
}

// Item encodes the Encrypt response payload. | Item 编码 Encrypt 响应负载。
func (p EncryptResponse) Item() (Item, error) {
	children := []Item{NewTextString(TagUniqueIdentifier, p.UniqueIdentifier)}
	children = appendBytes(children, TagData, p.Data)
	children = appendBytes(children, TagIVCounterNonce, p.IVCounterNonce)
	children = appendBytes(children, TagCorrelationValue, p.CorrelationValue)
	children = appendBytes(children, TagAuthenticatedEncryptionTag, p.AuthenticatedEncryptionTag)
	return payloadItem(TagResponsePayload, children...), nil
}

// DecodeEncryptResponse decodes an Encrypt response payload. | DecodeEncryptResponse 解码 Encrypt 响应负载。
func DecodeEncryptResponse(item Item) (EncryptResponse, error) {
	if item.Type != TypeStructure {
		return EncryptResponse{}, errs.Detail(ErrMalformed, "Encrypt response payload is not a structure | Encrypt 响应负载不是结构")
	}
	var out EncryptResponse
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	if out.Data, err = childBytes(item, TagData); err != nil {
		return out, err
	}
	if out.IVCounterNonce, err = childBytes(item, TagIVCounterNonce); err != nil {
		return out, err
	}
	if out.CorrelationValue, err = childBytes(item, TagCorrelationValue); err != nil {
		return out, err
	}
	if out.AuthenticatedEncryptionTag, err = childBytes(item, TagAuthenticatedEncryptionTag); err != nil {
		return out, err
	}
	return out, nil
}

// DecryptRequest is a KMIP Decrypt request payload. | DecryptRequest 是 KMIP Decrypt 请求负载。
type DecryptRequest struct {
	// UniqueIdentifier identifies the decryption key. | UniqueIdentifier 标识解密密钥。
	UniqueIdentifier string
	// CryptographicParameters holds optional decryption parameters. | CryptographicParameters 保存可选解密参数。
	CryptographicParameters *CryptographicParameters
	// Data is the ciphertext. | Data 是密文。
	Data []byte
	// IVCounterNonce is an optional IV, counter or nonce. | IVCounterNonce 是可选 IV、计数器或随机数。
	IVCounterNonce []byte
	// CorrelationValue correlates streaming decryption calls. | CorrelationValue 关联流式解密调用。
	CorrelationValue []byte
	// InitIndicator marks the first call of a streaming operation. | InitIndicator 标记流式操作的第一次调用。
	InitIndicator *bool
	// FinalIndicator marks the last call of a streaming operation. | FinalIndicator 标记流式操作的最后一次调用。
	FinalIndicator *bool
	// AuthenticatedEncryptionAdditionalData is optional AEAD associated data. | AuthenticatedEncryptionAdditionalData 是可选 AEAD 关联数据。
	AuthenticatedEncryptionAdditionalData []byte
	// AuthenticatedEncryptionTag is the AEAD tag. | AuthenticatedEncryptionTag 是 AEAD 标签。
	AuthenticatedEncryptionTag []byte
}

// Item encodes the Decrypt request payload. | Item 编码 Decrypt 请求负载。
func (p DecryptRequest) Item() (Item, error) {
	children := appendText(nil, TagUniqueIdentifier, p.UniqueIdentifier)
	if p.CryptographicParameters != nil {
		children = append(children, p.CryptographicParameters.Item())
	}
	children = appendBytes(children, TagData, p.Data)
	children = appendBytes(children, TagIVCounterNonce, p.IVCounterNonce)
	children = appendBytes(children, TagCorrelationValue, p.CorrelationValue)
	children = appendBoolPtr(children, TagInitIndicator, p.InitIndicator)
	children = appendBoolPtr(children, TagFinalIndicator, p.FinalIndicator)
	children = appendBytes(children, TagAuthenticatedEncryptionAdditionalData, p.AuthenticatedEncryptionAdditionalData)
	children = appendBytes(children, TagAuthenticatedEncryptionTag, p.AuthenticatedEncryptionTag)
	return payloadItem(TagRequestPayload, children...), nil
}

// DecodeDecryptRequest decodes a Decrypt request payload. | DecodeDecryptRequest 解码 Decrypt 请求负载。
func DecodeDecryptRequest(item Item) (DecryptRequest, error) {
	if item.Type != TypeStructure {
		return DecryptRequest{}, errs.Detail(ErrMalformed, "Decrypt request payload is not a structure | Decrypt 请求负载不是结构")
	}
	var out DecryptRequest
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	out.CryptographicParameters, err = optionalCryptographicParameters(item)
	if err != nil {
		return out, err
	}
	if out.Data, err = childBytes(item, TagData); err != nil {
		return out, err
	}
	if out.IVCounterNonce, err = childBytes(item, TagIVCounterNonce); err != nil {
		return out, err
	}
	if out.CorrelationValue, err = childBytes(item, TagCorrelationValue); err != nil {
		return out, err
	}
	out.InitIndicator, err = childBoolPtr(item, TagInitIndicator)
	if err != nil {
		return out, err
	}
	out.FinalIndicator, err = childBoolPtr(item, TagFinalIndicator)
	if err != nil {
		return out, err
	}
	if out.AuthenticatedEncryptionAdditionalData, err = childBytes(item, TagAuthenticatedEncryptionAdditionalData); err != nil {
		return out, err
	}
	if out.AuthenticatedEncryptionTag, err = childBytes(item, TagAuthenticatedEncryptionTag); err != nil {
		return out, err
	}
	return out, nil
}

// DecryptResponse is a KMIP Decrypt response payload. | DecryptResponse 是 KMIP Decrypt 响应负载。
type DecryptResponse struct {
	// UniqueIdentifier is the decryption key identifier. | UniqueIdentifier 是解密密钥标识符。
	UniqueIdentifier string
	// Data is the plaintext. | Data 是明文。
	Data []byte
	// CorrelationValue correlates streaming decryption calls. | CorrelationValue 关联流式解密调用。
	CorrelationValue []byte
}

// Item encodes the Decrypt response payload. | Item 编码 Decrypt 响应负载。
func (p DecryptResponse) Item() (Item, error) {
	children := []Item{NewTextString(TagUniqueIdentifier, p.UniqueIdentifier)}
	children = appendBytes(children, TagData, p.Data)
	children = appendBytes(children, TagCorrelationValue, p.CorrelationValue)
	return payloadItem(TagResponsePayload, children...), nil
}

// DecodeDecryptResponse decodes a Decrypt response payload. | DecodeDecryptResponse 解码 Decrypt 响应负载。
func DecodeDecryptResponse(item Item) (DecryptResponse, error) {
	if item.Type != TypeStructure {
		return DecryptResponse{}, errs.Detail(ErrMalformed, "Decrypt response payload is not a structure | Decrypt 响应负载不是结构")
	}
	var out DecryptResponse
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	if out.Data, err = childBytes(item, TagData); err != nil {
		return out, err
	}
	if out.CorrelationValue, err = childBytes(item, TagCorrelationValue); err != nil {
		return out, err
	}
	return out, nil
}

// SignRequest is a KMIP Sign request payload. | SignRequest 是 KMIP Sign 请求负载。
type SignRequest struct {
	// UniqueIdentifier identifies the signing key. | UniqueIdentifier 标识签名密钥。
	UniqueIdentifier string
	// CryptographicParameters holds optional signature parameters. | CryptographicParameters 保存可选签名参数。
	CryptographicParameters *CryptographicParameters
	// Data is the data to sign. | Data 是要签名的数据。
	Data []byte
	// DigestedData is the pre-hashed data; when set Data must be empty. | DigestedData 是预哈希数据；设置后 Data 必须为空。
	DigestedData []byte
	// CorrelationValue correlates streaming signing calls. | CorrelationValue 关联流式签名调用。
	CorrelationValue []byte
	// InitIndicator marks the first call of a streaming operation. | InitIndicator 标记流式操作的第一次调用。
	InitIndicator *bool
	// FinalIndicator marks the last call of a streaming operation. | FinalIndicator 标记流式操作的最后一次调用。
	FinalIndicator *bool
}

// Item encodes the Sign request payload. | Item 编码 Sign 请求负载。
func (p SignRequest) Item() (Item, error) {
	children := appendText(nil, TagUniqueIdentifier, p.UniqueIdentifier)
	if p.CryptographicParameters != nil {
		children = append(children, p.CryptographicParameters.Item())
	}
	children = appendBytes(children, TagData, p.Data)
	children = appendBytes(children, TagDigestedData, p.DigestedData)
	children = appendBytes(children, TagCorrelationValue, p.CorrelationValue)
	children = appendBoolPtr(children, TagInitIndicator, p.InitIndicator)
	children = appendBoolPtr(children, TagFinalIndicator, p.FinalIndicator)
	return payloadItem(TagRequestPayload, children...), nil
}

// DecodeSignRequest decodes a Sign request payload. | DecodeSignRequest 解码 Sign 请求负载。
func DecodeSignRequest(item Item) (SignRequest, error) {
	if item.Type != TypeStructure {
		return SignRequest{}, errs.Detail(ErrMalformed, "Sign request payload is not a structure | Sign 请求负载不是结构")
	}
	var out SignRequest
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	out.CryptographicParameters, err = optionalCryptographicParameters(item)
	if err != nil {
		return out, err
	}
	if out.Data, err = childBytes(item, TagData); err != nil {
		return out, err
	}
	if out.DigestedData, err = childBytes(item, TagDigestedData); err != nil {
		return out, err
	}
	if out.CorrelationValue, err = childBytes(item, TagCorrelationValue); err != nil {
		return out, err
	}
	out.InitIndicator, err = childBoolPtr(item, TagInitIndicator)
	if err != nil {
		return out, err
	}
	out.FinalIndicator, err = childBoolPtr(item, TagFinalIndicator)
	if err != nil {
		return out, err
	}
	return out, nil
}

// SignResponse is a KMIP Sign response payload. | SignResponse 是 KMIP Sign 响应负载。
type SignResponse struct {
	// UniqueIdentifier is the signing key identifier. | UniqueIdentifier 是签名密钥标识符。
	UniqueIdentifier string
	// SignatureData is the signature. | SignatureData 是签名。
	SignatureData []byte
	// CorrelationValue correlates streaming signing calls. | CorrelationValue 关联流式签名调用。
	CorrelationValue []byte
}

// Item encodes the Sign response payload. | Item 编码 Sign 响应负载。
func (p SignResponse) Item() (Item, error) {
	children := []Item{NewTextString(TagUniqueIdentifier, p.UniqueIdentifier)}
	children = appendBytes(children, TagSignatureData, p.SignatureData)
	children = appendBytes(children, TagCorrelationValue, p.CorrelationValue)
	return payloadItem(TagResponsePayload, children...), nil
}

// DecodeSignResponse decodes a Sign response payload. | DecodeSignResponse 解码 Sign 响应负载。
func DecodeSignResponse(item Item) (SignResponse, error) {
	if item.Type != TypeStructure {
		return SignResponse{}, errs.Detail(ErrMalformed, "Sign response payload is not a structure | Sign 响应负载不是结构")
	}
	var out SignResponse
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	if out.SignatureData, err = childBytes(item, TagSignatureData); err != nil {
		return out, err
	}
	if out.CorrelationValue, err = childBytes(item, TagCorrelationValue); err != nil {
		return out, err
	}
	return out, nil
}

// VerifyRequest is a KMIP Verify request payload. | VerifyRequest 是 KMIP Verify 请求负载。
type VerifyRequest struct {
	// UniqueIdentifier identifies the verification key. | UniqueIdentifier 标识验证密钥。
	UniqueIdentifier string
	// CryptographicParameters holds optional verification parameters. | CryptographicParameters 保存可选验证参数。
	CryptographicParameters *CryptographicParameters
	// Data is the signed data. | Data 是已签名数据。
	Data []byte
	// DigestedData is the pre-hashed data; when set Data must be empty. | DigestedData 是预哈希数据；设置后 Data 必须为空。
	DigestedData []byte
	// SignatureData is the signature. | SignatureData 是签名。
	SignatureData []byte
	// CorrelationValue correlates streaming verification calls. | CorrelationValue 关联流式验证调用。
	CorrelationValue []byte
	// InitIndicator marks the first call of a streaming operation. | InitIndicator 标记流式操作的第一次调用。
	InitIndicator *bool
	// FinalIndicator marks the last call of a streaming operation. | FinalIndicator 标记流式操作的最后一次调用。
	FinalIndicator *bool
}

// Item encodes the Verify request payload. | Item 编码 Verify 请求负载。
func (p VerifyRequest) Item() (Item, error) {
	children := appendText(nil, TagUniqueIdentifier, p.UniqueIdentifier)
	if p.CryptographicParameters != nil {
		children = append(children, p.CryptographicParameters.Item())
	}
	children = appendBytes(children, TagData, p.Data)
	children = appendBytes(children, TagDigestedData, p.DigestedData)
	children = appendBytes(children, TagSignatureData, p.SignatureData)
	children = appendBytes(children, TagCorrelationValue, p.CorrelationValue)
	children = appendBoolPtr(children, TagInitIndicator, p.InitIndicator)
	children = appendBoolPtr(children, TagFinalIndicator, p.FinalIndicator)
	return payloadItem(TagRequestPayload, children...), nil
}

// DecodeVerifyRequest decodes a Verify request payload. | DecodeVerifyRequest 解码 Verify 请求负载。
func DecodeVerifyRequest(item Item) (VerifyRequest, error) {
	if item.Type != TypeStructure {
		return VerifyRequest{}, errs.Detail(ErrMalformed, "Verify request payload is not a structure | Verify 请求负载不是结构")
	}
	var out VerifyRequest
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	out.CryptographicParameters, err = optionalCryptographicParameters(item)
	if err != nil {
		return out, err
	}
	if out.Data, err = childBytes(item, TagData); err != nil {
		return out, err
	}
	if out.DigestedData, err = childBytes(item, TagDigestedData); err != nil {
		return out, err
	}
	if out.SignatureData, err = childBytes(item, TagSignatureData); err != nil {
		return out, err
	}
	if out.CorrelationValue, err = childBytes(item, TagCorrelationValue); err != nil {
		return out, err
	}
	out.InitIndicator, err = childBoolPtr(item, TagInitIndicator)
	if err != nil {
		return out, err
	}
	out.FinalIndicator, err = childBoolPtr(item, TagFinalIndicator)
	if err != nil {
		return out, err
	}
	return out, nil
}

// VerifyResponse is a KMIP Verify response payload. | VerifyResponse 是 KMIP Verify 响应负载。
type VerifyResponse struct {
	// UniqueIdentifier is the verification key identifier. | UniqueIdentifier 是验证密钥标识符。
	UniqueIdentifier string
	// ValidityIndicator reports signature validity. | ValidityIndicator 报告签名有效性。
	ValidityIndicator ValidityIndicator
	// Data is optional recovered data. | Data 是可选恢复数据。
	Data []byte
	// CorrelationValue correlates streaming verification calls. | CorrelationValue 关联流式验证调用。
	CorrelationValue []byte
}

// Item encodes the Verify response payload. | Item 编码 Verify 响应负载。
func (p VerifyResponse) Item() (Item, error) {
	children := []Item{
		NewTextString(TagUniqueIdentifier, p.UniqueIdentifier),
		NewEnumeration(TagValidityIndicator, uint32(p.ValidityIndicator)),
	}
	children = appendBytes(children, TagData, p.Data)
	children = appendBytes(children, TagCorrelationValue, p.CorrelationValue)
	return payloadItem(TagResponsePayload, children...), nil
}

// DecodeVerifyResponse decodes a Verify response payload. | DecodeVerifyResponse 解码 Verify 响应负载。
func DecodeVerifyResponse(item Item) (VerifyResponse, error) {
	if item.Type != TypeStructure {
		return VerifyResponse{}, errs.Detail(ErrMalformed, "Verify response payload is not a structure | Verify 响应负载不是结构")
	}
	var out VerifyResponse
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	indicator, err := childEnumeration(item, TagValidityIndicator)
	if err != nil {
		return out, err
	}
	out.ValidityIndicator = ValidityIndicator(indicator)
	if out.Data, err = childBytes(item, TagData); err != nil {
		return out, err
	}
	if out.CorrelationValue, err = childBytes(item, TagCorrelationValue); err != nil {
		return out, err
	}
	return out, nil
}

// MACRequest is a KMIP MAC request payload. | MACRequest 是 KMIP MAC 请求负载。
type MACRequest struct {
	// UniqueIdentifier identifies the MAC key. | UniqueIdentifier 标识 MAC 密钥。
	UniqueIdentifier string
	// CryptographicParameters holds optional MAC parameters. | CryptographicParameters 保存可选 MAC 参数。
	CryptographicParameters *CryptographicParameters
	// Data is the data to authenticate. | Data 是要认证的数据。
	Data []byte
	// CorrelationValue correlates streaming MAC calls. | CorrelationValue 关联流式 MAC 调用。
	CorrelationValue []byte
	// InitIndicator marks the first call of a streaming operation. | InitIndicator 标记流式操作的第一次调用。
	InitIndicator *bool
	// FinalIndicator marks the last call of a streaming operation. | FinalIndicator 标记流式操作的最后一次调用。
	FinalIndicator *bool
}

// Item encodes the MAC request payload. | Item 编码 MAC 请求负载。
func (p MACRequest) Item() (Item, error) {
	children := appendText(nil, TagUniqueIdentifier, p.UniqueIdentifier)
	if p.CryptographicParameters != nil {
		children = append(children, p.CryptographicParameters.Item())
	}
	children = appendBytes(children, TagData, p.Data)
	children = appendBytes(children, TagCorrelationValue, p.CorrelationValue)
	children = appendBoolPtr(children, TagInitIndicator, p.InitIndicator)
	children = appendBoolPtr(children, TagFinalIndicator, p.FinalIndicator)
	return payloadItem(TagRequestPayload, children...), nil
}

// DecodeMACRequest decodes a MAC request payload. | DecodeMACRequest 解码 MAC 请求负载。
func DecodeMACRequest(item Item) (MACRequest, error) {
	if item.Type != TypeStructure {
		return MACRequest{}, errs.Detail(ErrMalformed, "MAC request payload is not a structure | MAC 请求负载不是结构")
	}
	var out MACRequest
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	out.CryptographicParameters, err = optionalCryptographicParameters(item)
	if err != nil {
		return out, err
	}
	if out.Data, err = childBytes(item, TagData); err != nil {
		return out, err
	}
	if out.CorrelationValue, err = childBytes(item, TagCorrelationValue); err != nil {
		return out, err
	}
	out.InitIndicator, err = childBoolPtr(item, TagInitIndicator)
	if err != nil {
		return out, err
	}
	out.FinalIndicator, err = childBoolPtr(item, TagFinalIndicator)
	if err != nil {
		return out, err
	}
	return out, nil
}

// MACResponse is a KMIP MAC response payload. | MACResponse 是 KMIP MAC 响应负载。
type MACResponse struct {
	// UniqueIdentifier is the MAC key identifier. | UniqueIdentifier 是 MAC 密钥标识符。
	UniqueIdentifier string
	// MACData is the MAC value. | MACData 是 MAC 值。
	MACData []byte
	// CorrelationValue correlates streaming MAC calls. | CorrelationValue 关联流式 MAC 调用。
	CorrelationValue []byte
}

// Item encodes the MAC response payload. | Item 编码 MAC 响应负载。
func (p MACResponse) Item() (Item, error) {
	children := []Item{NewTextString(TagUniqueIdentifier, p.UniqueIdentifier)}
	children = appendBytes(children, TagMACData, p.MACData)
	children = appendBytes(children, TagCorrelationValue, p.CorrelationValue)
	return payloadItem(TagResponsePayload, children...), nil
}

// DecodeMACResponse decodes a MAC response payload. | DecodeMACResponse 解码 MAC 响应负载。
func DecodeMACResponse(item Item) (MACResponse, error) {
	if item.Type != TypeStructure {
		return MACResponse{}, errs.Detail(ErrMalformed, "MAC response payload is not a structure | MAC 响应负载不是结构")
	}
	var out MACResponse
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	if out.MACData, err = childBytes(item, TagMACData); err != nil {
		return out, err
	}
	if out.CorrelationValue, err = childBytes(item, TagCorrelationValue); err != nil {
		return out, err
	}
	return out, nil
}

// MACVerifyRequest is a KMIP MAC Verify request payload. | MACVerifyRequest 是 KMIP MAC Verify 请求负载。
type MACVerifyRequest struct {
	// UniqueIdentifier identifies the MAC key. | UniqueIdentifier 标识 MAC 密钥。
	UniqueIdentifier string
	// CryptographicParameters holds optional MAC parameters. | CryptographicParameters 保存可选 MAC 参数。
	CryptographicParameters *CryptographicParameters
	// Data is the authenticated data. | Data 是已认证数据。
	Data []byte
	// MACData is the MAC value to verify. | MACData 是要验证的 MAC 值。
	MACData []byte
	// CorrelationValue correlates streaming MAC calls. | CorrelationValue 关联流式 MAC 调用。
	CorrelationValue []byte
	// InitIndicator marks the first call of a streaming operation. | InitIndicator 标记流式操作的第一次调用。
	InitIndicator *bool
	// FinalIndicator marks the last call of a streaming operation. | FinalIndicator 标记流式操作的最后一次调用。
	FinalIndicator *bool
}

// Item encodes the MAC Verify request payload. | Item 编码 MAC Verify 请求负载。
func (p MACVerifyRequest) Item() (Item, error) {
	children := appendText(nil, TagUniqueIdentifier, p.UniqueIdentifier)
	if p.CryptographicParameters != nil {
		children = append(children, p.CryptographicParameters.Item())
	}
	children = appendBytes(children, TagData, p.Data)
	children = appendBytes(children, TagMACData, p.MACData)
	children = appendBytes(children, TagCorrelationValue, p.CorrelationValue)
	children = appendBoolPtr(children, TagInitIndicator, p.InitIndicator)
	children = appendBoolPtr(children, TagFinalIndicator, p.FinalIndicator)
	return payloadItem(TagRequestPayload, children...), nil
}

// DecodeMACVerifyRequest decodes a MAC Verify request payload. | DecodeMACVerifyRequest 解码 MAC Verify 请求负载。
func DecodeMACVerifyRequest(item Item) (MACVerifyRequest, error) {
	if item.Type != TypeStructure {
		return MACVerifyRequest{}, errs.Detail(ErrMalformed, "MAC Verify request payload is not a structure | MAC Verify 请求负载不是结构")
	}
	var out MACVerifyRequest
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	out.CryptographicParameters, err = optionalCryptographicParameters(item)
	if err != nil {
		return out, err
	}
	if out.Data, err = childBytes(item, TagData); err != nil {
		return out, err
	}
	if out.MACData, err = childBytes(item, TagMACData); err != nil {
		return out, err
	}
	if out.CorrelationValue, err = childBytes(item, TagCorrelationValue); err != nil {
		return out, err
	}
	out.InitIndicator, err = childBoolPtr(item, TagInitIndicator)
	if err != nil {
		return out, err
	}
	out.FinalIndicator, err = childBoolPtr(item, TagFinalIndicator)
	if err != nil {
		return out, err
	}
	return out, nil
}

// MACVerifyResponse is a KMIP MAC Verify response payload. | MACVerifyResponse 是 KMIP MAC Verify 响应负载。
type MACVerifyResponse struct {
	// UniqueIdentifier is the MAC key identifier. | UniqueIdentifier 是 MAC 密钥标识符。
	UniqueIdentifier string
	// ValidityIndicator reports MAC validity. | ValidityIndicator 报告 MAC 有效性。
	ValidityIndicator ValidityIndicator
	// CorrelationValue correlates streaming MAC calls. | CorrelationValue 关联流式 MAC 调用。
	CorrelationValue []byte
}

// Item encodes the MAC Verify response payload. | Item 编码 MAC Verify 响应负载。
func (p MACVerifyResponse) Item() (Item, error) {
	children := []Item{
		NewTextString(TagUniqueIdentifier, p.UniqueIdentifier),
		NewEnumeration(TagValidityIndicator, uint32(p.ValidityIndicator)),
	}
	children = appendBytes(children, TagCorrelationValue, p.CorrelationValue)
	return payloadItem(TagResponsePayload, children...), nil
}

// DecodeMACVerifyResponse decodes a MAC Verify response payload. | DecodeMACVerifyResponse 解码 MAC Verify 响应负载。
func DecodeMACVerifyResponse(item Item) (MACVerifyResponse, error) {
	if item.Type != TypeStructure {
		return MACVerifyResponse{}, errs.Detail(ErrMalformed, "MAC Verify response payload is not a structure | MAC Verify 响应负载不是结构")
	}
	var out MACVerifyResponse
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	indicator, err := childEnumeration(item, TagValidityIndicator)
	if err != nil {
		return out, err
	}
	out.ValidityIndicator = ValidityIndicator(indicator)
	if out.CorrelationValue, err = childBytes(item, TagCorrelationValue); err != nil {
		return out, err
	}
	return out, nil
}

// WrapKeyRequest is a ydx extension request that wraps a stored key. | WrapKeyRequest 是封装存储密钥的 ydx 扩展请求。
type WrapKeyRequest struct {
	// UniqueIdentifier identifies the key to wrap. | UniqueIdentifier 标识要封装的密钥。
	UniqueIdentifier string
	// KeyWrappingSpecification describes the wrapping. | KeyWrappingSpecification 描述封装方式。
	KeyWrappingSpecification KeyWrappingSpecification
}

// Item encodes the Wrap Key request payload. | Item 编码 Wrap Key 请求负载。
func (p WrapKeyRequest) Item() (Item, error) {
	spec, err := p.KeyWrappingSpecification.Item()
	if err != nil {
		return Item{}, err
	}
	return payloadItem(TagRequestPayload,
		NewTextString(TagUniqueIdentifier, p.UniqueIdentifier),
		spec,
	), nil
}

// DecodeWrapKeyRequest decodes a Wrap Key request payload. | DecodeWrapKeyRequest 解码 Wrap Key 请求负载。
func DecodeWrapKeyRequest(item Item) (WrapKeyRequest, error) {
	if item.Type != TypeStructure {
		return WrapKeyRequest{}, errs.Detail(ErrMalformed, "Wrap Key request payload is not a structure | Wrap Key 请求负载不是结构")
	}
	var out WrapKeyRequest
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	spec, ok := item.Child(TagKeyWrappingSpecification)
	if !ok {
		return out, errs.Detail(ErrMalformed, "Wrap Key request has no Key Wrapping Specification | Wrap Key 请求没有密钥封装规格")
	}
	out.KeyWrappingSpecification, err = DecodeKeyWrappingSpecification(spec)
	if err != nil {
		return out, err
	}
	return out, nil
}

// WrapKeyResponse is a ydx extension response carrying a wrapped key object. | WrapKeyResponse 是携带已封装密钥对象的 ydx 扩展响应。
type WrapKeyResponse struct {
	// UniqueIdentifier is the wrapped key identifier. | UniqueIdentifier 是已封装密钥标识符。
	UniqueIdentifier string
	// Object is the wrapped key object. | Object 是已封装密钥对象。
	Object Object
}

// Item encodes the Wrap Key response payload. | Item 编码 Wrap Key 响应负载。
func (p WrapKeyResponse) Item() (Item, error) {
	object, err := p.Object.Item()
	if err != nil {
		return Item{}, err
	}
	return payloadItem(TagResponsePayload,
		NewTextString(TagUniqueIdentifier, p.UniqueIdentifier),
		object,
	), nil
}

// DecodeWrapKeyResponse decodes a Wrap Key response payload. | DecodeWrapKeyResponse 解码 Wrap Key 响应负载。
func DecodeWrapKeyResponse(item Item) (WrapKeyResponse, error) {
	if item.Type != TypeStructure {
		return WrapKeyResponse{}, errs.Detail(ErrMalformed, "Wrap Key response payload is not a structure | Wrap Key 响应负载不是结构")
	}
	var out WrapKeyResponse
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	for _, child := range item.Children {
		if child.Type != TypeStructure {
			continue
		}
		switch child.Tag {
		case TagSymmetricKey, TagPublicKey, TagPrivateKey, TagSecretData, TagCertificate, TagTemplate, TagOpaqueObject:
			out.Object, err = DecodeObject(child)
			if err != nil {
				return out, err
			}
		}
	}
	if out.Object.Type == 0 {
		return out, errs.Detail(ErrMalformed, "Wrap Key response has no Object | Wrap Key 响应没有对象")
	}
	if out.UniqueIdentifier == "" {
		return out, errs.Detail(ErrMalformed, "Wrap Key response has no Unique Identifier | Wrap Key 响应没有唯一标识符")
	}
	return out, nil
}

// UnwrapKeyRequest is a ydx extension request that unwraps a wrapped key object. | UnwrapKeyRequest 是解封已封装密钥对象的 ydx 扩展请求。
type UnwrapKeyRequest struct {
	// Object is the wrapped key object. | Object 是已封装密钥对象。
	Object Object
	// TemplateAttribute carries attributes for the new stored key. | TemplateAttribute 携带新存储密钥的属性。
	TemplateAttribute TemplateAttribute
}

// Item encodes the Unwrap Key request payload. | Item 编码 Unwrap Key 请求负载。
func (p UnwrapKeyRequest) Item() (Item, error) {
	object, err := p.Object.Item()
	if err != nil {
		return Item{}, err
	}
	tmpl, err := p.TemplateAttribute.Item()
	if err != nil {
		return Item{}, err
	}
	return payloadItem(TagRequestPayload, object, tmpl), nil
}

// DecodeUnwrapKeyRequest decodes an Unwrap Key request payload. | DecodeUnwrapKeyRequest 解码 Unwrap Key 请求负载。
func DecodeUnwrapKeyRequest(item Item) (UnwrapKeyRequest, error) {
	if item.Type != TypeStructure {
		return UnwrapKeyRequest{}, errs.Detail(ErrMalformed, "Unwrap Key request payload is not a structure | Unwrap Key 请求负载不是结构")
	}
	var out UnwrapKeyRequest
	var err error
	for _, child := range item.Children {
		switch child.Tag {
		case TagSymmetricKey, TagPublicKey, TagPrivateKey, TagSecretData, TagCertificate, TagTemplate, TagOpaqueObject:
			out.Object, err = DecodeObject(child)
			if err != nil {
				return out, err
			}
		case TagTemplateAttribute:
			out.TemplateAttribute, err = DecodeTemplateAttribute(child)
			if err != nil {
				return out, err
			}
		}
	}
	if out.Object.Type == 0 {
		return out, errs.Detail(ErrMalformed, "Unwrap Key request has no Object | Unwrap Key 请求没有对象")
	}
	return out, nil
}

// UnwrapKeyResponse is a ydx extension response for an unwrapped key. | UnwrapKeyResponse 是解封密钥的 ydx 扩展响应。
type UnwrapKeyResponse struct {
	// UniqueIdentifier is the new stored key identifier. | UniqueIdentifier 是新存储密钥标识符。
	UniqueIdentifier string
	// ObjectType is the new object type. | ObjectType 是新对象类型。
	ObjectType ObjectType
}

// Item encodes the Unwrap Key response payload. | Item 编码 Unwrap Key 响应负载。
func (p UnwrapKeyResponse) Item() (Item, error) {
	return payloadItem(TagResponsePayload,
		NewTextString(TagUniqueIdentifier, p.UniqueIdentifier),
		NewEnumeration(TagObjectType, uint32(p.ObjectType)),
	), nil
}

// DecodeUnwrapKeyResponse decodes an Unwrap Key response payload. | DecodeUnwrapKeyResponse 解码 Unwrap Key 响应负载。
func DecodeUnwrapKeyResponse(item Item) (UnwrapKeyResponse, error) {
	if item.Type != TypeStructure {
		return UnwrapKeyResponse{}, errs.Detail(ErrMalformed, "Unwrap Key response payload is not a structure | Unwrap Key 响应负载不是结构")
	}
	var out UnwrapKeyResponse
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	if out.UniqueIdentifier == "" {
		return out, errs.Detail(ErrMalformed, "Unwrap Key response has no Unique Identifier | Unwrap Key 响应没有唯一标识符")
	}
	out.ObjectType, err = decodeObjectTypeChild(item, true)
	if err != nil {
		return out, err
	}
	return out, nil
}

// optionalCryptographicParameters extracts optional Cryptographic Parameters. | optionalCryptographicParameters 提取可选密码参数。
func optionalCryptographicParameters(item Item) (*CryptographicParameters, error) {
	child, ok := item.Child(TagCryptographicParameters)
	if !ok {
		return nil, nil
	}
	v, err := DecodeCryptographicParameters(child)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// childBoolPtr reads an optional boolean pointer. | childBoolPtr 读取可选布尔指针。
func childBoolPtr(item Item, tag Tag) (*bool, error) {
	child, ok := item.Child(tag)
	if !ok {
		return nil, nil
	}
	v, err := child.AsBoolean()
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// appendBoolPtr appends an optional boolean pointer. | appendBoolPtr 追加可选布尔指针。
func appendBoolPtr(children []Item, tag Tag, value *bool) []Item {
	if value == nil {
		return children
	}
	return append(children, NewBoolean(tag, *value))
}
