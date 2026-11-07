package kmip

import (
	"github.com/shibingli/ydx/errs"
)

// handleEncrypt implements Encrypt. | handleEncrypt 实现 Encrypt。
func (s *Server) handleEncrypt(request EncryptRequest) (Item, error) {
	record, err := s.loadActive(request.UniqueIdentifier, UsageMaskEncrypt)
	if err != nil {
		return Item{}, err
	}
	kb, err := recordKeyBlock(&record)
	if err != nil {
		return Item{}, err
	}
	var params CryptographicParameters
	if request.CryptographicParameters != nil {
		params = *request.CryptographicParameters
	}
	data, iv, tag, err := encryptKeyBlock(*kb, params, request.Data, request.IVCounterNonce,
		request.AuthenticatedEncryptionAdditionalData)
	if err != nil {
		return Item{}, err
	}
	return EncryptResponse{
		UniqueIdentifier:           record.UniqueIdentifier,
		Data:                       data,
		IVCounterNonce:             iv,
		CorrelationValue:           request.CorrelationValue,
		AuthenticatedEncryptionTag: tag,
	}.Item()
}

// handleDecrypt implements Decrypt. | handleDecrypt 实现 Decrypt。
func (s *Server) handleDecrypt(request DecryptRequest) (Item, error) {
	record, err := s.loadActive(request.UniqueIdentifier, UsageMaskDecrypt)
	if err != nil {
		return Item{}, err
	}
	kb, err := recordKeyBlock(&record)
	if err != nil {
		return Item{}, err
	}
	var params CryptographicParameters
	if request.CryptographicParameters != nil {
		params = *request.CryptographicParameters
	}
	data, err := decryptKeyBlock(*kb, params, request.Data, request.IVCounterNonce,
		request.AuthenticatedEncryptionTag, request.AuthenticatedEncryptionAdditionalData)
	if err != nil {
		return Item{}, err
	}
	return DecryptResponse{
		UniqueIdentifier: record.UniqueIdentifier,
		Data:             data,
		CorrelationValue: request.CorrelationValue,
	}.Item()
}

// handleSign implements Sign. | handleSign 实现 Sign。
func (s *Server) handleSign(request SignRequest) (Item, error) {
	if len(request.Data) > 0 && len(request.DigestedData) > 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "Sign accepts either Data or Digested Data, not both | Sign 只接受 Data 或 Digested Data 之一")
	}
	record, err := s.loadActive(request.UniqueIdentifier, UsageMaskSign)
	if err != nil {
		return Item{}, err
	}
	kb, err := recordKeyBlock(&record)
	if err != nil {
		return Item{}, err
	}
	var params CryptographicParameters
	if request.CryptographicParameters != nil {
		params = *request.CryptographicParameters
	}
	signature, err := signKeyBlock(*kb, params, request.Data, request.DigestedData)
	if err != nil {
		return Item{}, err
	}
	return SignResponse{
		UniqueIdentifier: record.UniqueIdentifier,
		SignatureData:    signature,
		CorrelationValue: request.CorrelationValue,
	}.Item()
}

// handleVerify implements Verify. An invalid signature is reported through Validity Indicator, not an error. | handleVerify
// 实现 Verify；签名无效通过 Validity Indicator 报告，而不是错误。
func (s *Server) handleVerify(request VerifyRequest) (Item, error) {
	if len(request.Data) > 0 && len(request.DigestedData) > 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "Verify accepts either Data or Digested Data, not both | Verify 只接受 Data 或 Digested Data 之一")
	}
	record, err := s.loadActive(request.UniqueIdentifier, UsageMaskVerify)
	if err != nil {
		return Item{}, err
	}
	kb, err := recordKeyBlock(&record)
	if err != nil {
		return Item{}, err
	}
	var params CryptographicParameters
	if request.CryptographicParameters != nil {
		params = *request.CryptographicParameters
	}
	valid, err := verifyKeyBlock(*kb, params, request.Data, request.DigestedData, request.SignatureData)
	if err != nil {
		return Item{}, err
	}
	indicator := ValidityIndicatorInvalid
	if valid {
		indicator = ValidityIndicatorValid
	}
	return VerifyResponse{
		UniqueIdentifier:  record.UniqueIdentifier,
		ValidityIndicator: indicator,
		CorrelationValue:  request.CorrelationValue,
	}.Item()
}

// handleMAC implements MAC. | handleMAC 实现 MAC。
func (s *Server) handleMAC(request MACRequest) (Item, error) {
	record, err := s.loadActive(request.UniqueIdentifier, UsageMaskMACGenerate)
	if err != nil {
		return Item{}, err
	}
	kb, err := recordKeyBlock(&record)
	if err != nil {
		return Item{}, err
	}
	var params CryptographicParameters
	if request.CryptographicParameters != nil {
		params = *request.CryptographicParameters
	}
	mac, err := macKeyBlock(*kb, params, request.Data)
	if err != nil {
		return Item{}, err
	}
	return MACResponse{
		UniqueIdentifier: record.UniqueIdentifier,
		MACData:          mac,
		CorrelationValue: request.CorrelationValue,
	}.Item()
}

// handleMACVerify implements MAC Verify with a constant-time comparison. | handleMACVerify 使用常量时间比较实现 MAC Verify。
func (s *Server) handleMACVerify(request MACVerifyRequest) (Item, error) {
	record, err := s.loadActive(request.UniqueIdentifier, UsageMaskMACVerify)
	if err != nil {
		return Item{}, err
	}
	kb, err := recordKeyBlock(&record)
	if err != nil {
		return Item{}, err
	}
	var params CryptographicParameters
	if request.CryptographicParameters != nil {
		params = *request.CryptographicParameters
	}
	valid, err := macVerifyKeyBlock(*kb, params, request.Data, request.MACData)
	if err != nil {
		return Item{}, err
	}
	indicator := ValidityIndicatorInvalid
	if valid {
		indicator = ValidityIndicatorValid
	}
	return MACVerifyResponse{
		UniqueIdentifier:  record.UniqueIdentifier,
		ValidityIndicator: indicator,
		CorrelationValue:  request.CorrelationValue,
	}.Item()
}

// handleWrapKey implements the ydx Wrap Key extension. | handleWrapKey 实现 ydx Wrap Key 扩展。
func (s *Server) handleWrapKey(request WrapKeyRequest) (Item, error) {
	return s.handleWrapKeyForVersion(request, DefaultProtocolVersion)
}

// handleWrapKeyForVersion implements Wrap Key using the payload shape of version. | handleWrapKeyForVersion 使用
// version 的负载形状实现 Wrap Key。
func (s *Server) handleWrapKeyForVersion(request WrapKeyRequest, version ProtocolVersion) (Item, error) {
	record, err := s.loadRecord(request.UniqueIdentifier)
	if err != nil {
		return Item{}, err
	}
	if record.Object == nil || record.State == StateDestroyed {
		return Item{}, errs.Detail(ErrState, "object %q was destroyed | 对象 %q 已销毁", record.UniqueIdentifier, record.UniqueIdentifier)
	}
	if !record.Extractable {
		return Item{}, resultErrorFor(ResultStatusOperationFailed, ResultReasonNotExtractable,
			"object is not extractable | 对象不可导出")
	}
	if request.KeyWrappingSpecification.EncryptionKeyInformation == nil {
		return Item{}, errs.Detail(ErrInvalidRequest, "wrapping specification has no encryption key | 封装规格没有加密密钥")
	}
	kb, err := recordKeyBlock(&record)
	if err != nil {
		return Item{}, err
	}
	wrappingRecord, err := s.loadActive(request.KeyWrappingSpecification.EncryptionKeyInformation.UniqueIdentifier, UsageMaskWrapKey)
	if err != nil {
		return Item{}, err
	}
	wrappingBlock, err := recordKeyBlock(&wrappingRecord)
	if err != nil {
		return Item{}, err
	}
	wrapped, err := wrapKeyBlock(*kb, *wrappingBlock, request.KeyWrappingSpecification)
	if err != nil {
		return Item{}, err
	}
	object, err := objectWithKeyBlock(record.Object.Type, *record.Object, wrapped)
	if err != nil {
		return Item{}, err
	}
	return WrapKeyResponse{UniqueIdentifier: record.UniqueIdentifier, Object: object}.ItemForVersion(version)
}

// handleUnwrapKey implements the ydx Unwrap Key extension. | handleUnwrapKey 实现 ydx Unwrap Key 扩展。
func (s *Server) handleUnwrapKey(request UnwrapKeyRequest) (Item, error) {
	wrapped, err := request.Object.KeyBlock()
	if err != nil {
		return Item{}, err
	}
	if wrapped.Wrapping == nil || wrapped.Wrapping.EncryptionKeyInformation == nil {
		return Item{}, errs.Detail(ErrInvalidRequest, "object is not wrapped with an encryption key | 对象未使用加密密钥封装")
	}
	wrappingRecord, err := s.loadActive(wrapped.Wrapping.EncryptionKeyInformation.UniqueIdentifier, UsageMaskUnwrapKey)
	if err != nil {
		return Item{}, err
	}
	wrappingBlock, err := recordKeyBlock(&wrappingRecord)
	if err != nil {
		return Item{}, err
	}
	unwrapped, err := unwrapKeyBlock(*wrapped, *wrappingBlock)
	if err != nil {
		return Item{}, err
	}
	parsed, err := parseKeyBlock(unwrapped)
	if err != nil {
		zeroizeKeyBlock(&unwrapped)
		return Item{}, err
	}
	parsed.zeroize()
	uid, err := newUniqueIdentifier()
	if err != nil {
		zeroizeKeyBlock(&unwrapped)
		return Item{}, err
	}
	object, err := objectWithKeyBlock(request.Object.Type, request.Object, unwrapped)
	if err != nil {
		zeroizeKeyBlock(&unwrapped)
		return Item{}, err
	}
	record, err := recordFromTemplate(s.now(), uid, object, request.TemplateAttribute, true)
	if err != nil {
		zeroizeKeyBlock(&unwrapped)
		return Item{}, err
	}
	defer record.Object.Zeroize()
	if err := s.store.Create(s.ctx, record); err != nil {
		return Item{}, err
	}
	return UnwrapKeyResponse{UniqueIdentifier: uid, ObjectType: request.Object.Type}.Item()
}
