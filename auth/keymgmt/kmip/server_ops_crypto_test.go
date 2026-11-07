package kmip

import (
	"bytes"
	"errors"
	"testing"
)

// hmacKey creates and activates an HMAC-SHA256 symmetric key. | hmacKey 创建并激活 HMAC-SHA256 对称密钥。
func hmacKey(t *testing.T, server *Server) string {
	t.Helper()
	item := runOp(t, server, OpCreate, CreateRequest{
		ObjectType: ObjectTypeSymmetricKey,
		TemplateAttribute: TemplateAttribute{Attributes: AttributeList{
			NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmHMACSHA256)),
			NewIntegerAttribute(AttributeCryptographicLength, 256),
		}},
	})
	response, err := DecodeCreateResponse(item)
	if err != nil {
		t.Fatalf("DecodeCreateResponse: %v", err)
	}
	activateKey(t, server, response.UniqueIdentifier)
	return response.UniqueIdentifier
}

// TestServerEncryptDecrypt covers AES-GCM and AES-CBC through the server handlers. |
// TestServerEncryptDecrypt 通过服务器处理器覆盖 AES-GCM 与 AES-CBC。
func TestServerEncryptDecrypt(t *testing.T) {
	server := newTestServer(t)
	uid := createSymmetric(t, server)
	if item := runOpItem(t, server, OpEncrypt, EncryptRequest{UniqueIdentifier: uid, Data: []byte("inactive")}); !errors.Is(item.Err(), ErrIllegalOperation) {
		t.Fatalf("inactive Encrypt error = %v | 非活动加密错误 = %v", item.Err(), item.Err())
	}
	activateKey(t, server, uid)
	plaintext := []byte("server side AES-GCM payload")
	gcm := CryptographicParameters{BlockCipherMode: BlockCipherModeGCM, RandomIV: true}
	encrypted, err := DecodeEncryptResponse(runOp(t, server, OpEncrypt, EncryptRequest{
		UniqueIdentifier: uid, CryptographicParameters: &gcm, Data: plaintext,
	}))
	if err != nil || len(encrypted.Data) == 0 || len(encrypted.IVCounterNonce) != 12 || len(encrypted.AuthenticatedEncryptionTag) != 16 {
		t.Fatalf("GCM Encrypt = %+v, %v | GCM 加密 = %+v，%v", encrypted, err, encrypted, err)
	}
	decrypted, err := DecodeDecryptResponse(runOp(t, server, OpDecrypt, DecryptRequest{
		UniqueIdentifier:           uid,
		CryptographicParameters:    &gcm,
		Data:                       encrypted.Data,
		IVCounterNonce:             encrypted.IVCounterNonce,
		AuthenticatedEncryptionTag: encrypted.AuthenticatedEncryptionTag,
	}))
	if err != nil || !bytes.Equal(decrypted.Data, plaintext) {
		t.Fatalf("GCM Decrypt = %q, %v | GCM 解密 = %q，%v", decrypted.Data, err, decrypted.Data, err)
	}
	if item := runOpItem(t, server, OpDecrypt, DecryptRequest{
		UniqueIdentifier: uid, CryptographicParameters: &gcm, Data: encrypted.Data,
		IVCounterNonce: encrypted.IVCounterNonce, AuthenticatedEncryptionTag: []byte("bad-tag"),
	}); !errors.Is(item.Err(), ErrCryptographic) {
		t.Fatalf("tampered GCM error = %v | 篡改 GCM 错误 = %v", item.Err(), item.Err())
	}

	cbc := CryptographicParameters{BlockCipherMode: BlockCipherModeCBC, PaddingMethod: PaddingMethodPKCS5}
	iv := bytes.Repeat([]byte{0x42}, 16)
	cbcPlaintext := []byte("CBC mode payload that spans blocks")
	cbcEncrypted, err := DecodeEncryptResponse(runOp(t, server, OpEncrypt, EncryptRequest{
		UniqueIdentifier: uid, CryptographicParameters: &cbc, Data: cbcPlaintext, IVCounterNonce: iv,
	}))
	if err != nil || len(cbcEncrypted.Data) == 0 {
		t.Fatalf("CBC Encrypt = %+v, %v | CBC 加密 = %+v，%v", cbcEncrypted, err, cbcEncrypted, err)
	}
	cbcDecrypted, err := DecodeDecryptResponse(runOp(t, server, OpDecrypt, DecryptRequest{
		UniqueIdentifier: uid, CryptographicParameters: &cbc, Data: cbcEncrypted.Data, IVCounterNonce: iv,
	}))
	if err != nil || !bytes.Equal(cbcDecrypted.Data, cbcPlaintext) {
		t.Fatalf("CBC Decrypt = %q, %v | CBC 解密 = %q，%v", cbcDecrypted.Data, err, cbcDecrypted.Data, err)
	}
	if _, err := server.handleEncrypt(EncryptRequest{
		UniqueIdentifier: uid, CryptographicParameters: &CryptographicParameters{IVLength: -1, BlockCipherMode: BlockCipherModeGCM}, Data: []byte("x"),
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("negative IV length error = %v | 负 IV 长度错误 = %v", err, err)
	}
	if item := runOpItem(t, server, OpEncrypt, EncryptRequest{UniqueIdentifier: "missing", Data: []byte("x")}); !errors.Is(item.Err(), ErrItemNotFound) {
		t.Fatalf("missing Encrypt key error = %v | 缺失加密密钥错误 = %v", item.Err(), item.Err())
	}
}

// TestServerSignVerifyMAC covers RSA, ECDSA, Ed25519, SM2 and HMAC through the server handlers. |
// TestServerSignVerifyMAC 通过服务器处理器覆盖 RSA、ECDSA、Ed25519、SM2 与 HMAC。
func TestServerSignVerifyMAC(t *testing.T) {
	server := newTestServer(t)
	data := []byte("handler signature payload")
	tampered := []byte("handler signature payload!")

	rsaPrivate, rsaPublic := createKeyPair(t, server, AlgorithmRSA, 2048)
	activateKey(t, server, rsaPrivate)
	activateKey(t, server, rsaPublic)
	rsaParams := CryptographicParameters{DigitalSignatureAlgorithm: DigitalSignatureRSAPKCS1SHA256}
	signature, err := DecodeSignResponse(runOp(t, server, OpSign, SignRequest{
		UniqueIdentifier: rsaPrivate, CryptographicParameters: &rsaParams, Data: data,
	}))
	if err != nil || len(signature.SignatureData) == 0 {
		t.Fatalf("RSA Sign = %+v, %v | RSA 签名 = %+v，%v", signature, err, signature, err)
	}
	valid, err := DecodeVerifyResponse(runOp(t, server, OpSignatureVerify, VerifyRequest{
		UniqueIdentifier: rsaPublic, CryptographicParameters: &rsaParams, Data: data, SignatureData: signature.SignatureData,
	}))
	if err != nil || valid.ValidityIndicator != ValidityIndicatorValid {
		t.Fatalf("RSA Verify = %+v, %v | RSA 验签 = %+v，%v", valid, err, valid, err)
	}
	invalid, err := DecodeVerifyResponse(runOp(t, server, OpSignatureVerify, VerifyRequest{
		UniqueIdentifier: rsaPublic, CryptographicParameters: &rsaParams, Data: tampered, SignatureData: signature.SignatureData,
	}))
	if err != nil || invalid.ValidityIndicator != ValidityIndicatorInvalid {
		t.Fatalf("RSA tampered Verify = %+v, %v | RSA 篡改验签 = %+v，%v", invalid, err, invalid, err)
	}
	if item := runOpItem(t, server, OpSign, SignRequest{UniqueIdentifier: rsaPrivate, Data: data, DigestedData: []byte{1}}); !errors.Is(item.Err(), ErrMalformed) {
		t.Fatalf("both data and digest error = %v | 同时提供数据与摘要错误 = %v", item.Err(), item.Err())
	}
	if item := runOpItem(t, server, OpSignatureVerify, VerifyRequest{UniqueIdentifier: rsaPublic, Data: data, DigestedData: []byte{1}}); !errors.Is(item.Err(), ErrMalformed) {
		t.Fatalf("verify both data and digest error = %v | 验签同时提供数据与摘要错误 = %v", item.Err(), item.Err())
	}

	for _, testCase := range []struct {
		name      string
		algorithm CryptographicAlgorithm
		signature DigitalSignatureAlgorithm
	}{
		{"ECDSA", AlgorithmECDSA, DigitalSignatureECDSASHA256},
		{"Ed25519", AlgorithmEd25519, DigitalSignatureEd25519},
		{"SM2", AlgorithmSM2, DigitalSignatureSM2SM3},
	} {
		privateID, publicID := createKeyPair(t, server, testCase.algorithm, 256)
		activateKey(t, server, privateID)
		activateKey(t, server, publicID)
		params := CryptographicParameters{DigitalSignatureAlgorithm: testCase.signature}
		signed, err := DecodeSignResponse(runOp(t, server, OpSign, SignRequest{UniqueIdentifier: privateID, CryptographicParameters: &params, Data: data}))
		if err != nil {
			t.Fatalf("%s Sign: %v | %s 签名失败：%v", testCase.name, err, testCase.name, err)
		}
		verified, err := DecodeVerifyResponse(runOp(t, server, OpSignatureVerify, VerifyRequest{
			UniqueIdentifier: publicID, CryptographicParameters: &params, Data: data, SignatureData: signed.SignatureData,
		}))
		if err != nil || verified.ValidityIndicator != ValidityIndicatorValid {
			t.Fatalf("%s Verify = %+v, %v | %s 验签 = %+v，%v", testCase.name, verified, err, testCase.name, verified, err)
		}
		if item := runOpItem(t, server, OpSign, SignRequest{UniqueIdentifier: publicID, CryptographicParameters: &params, Data: data}); !errors.Is(item.Err(), ErrUsageMask) {
			t.Fatalf("%s public Sign error = %v | %s 公钥签名错误 = %v", testCase.name, item.Err(), testCase.name, item.Err())
		}
	}

	macUID := hmacKey(t, server)
	mac, err := DecodeMACResponse(runOp(t, server, OpMAC, MACRequest{UniqueIdentifier: macUID, Data: data}))
	if err != nil || len(mac.MACData) != 32 {
		t.Fatalf("MAC = %+v, %v | MAC = %+v，%v", mac, err, mac, err)
	}
	macValid, err := DecodeMACVerifyResponse(runOp(t, server, OpMACVerify, MACVerifyRequest{UniqueIdentifier: macUID, Data: data, MACData: mac.MACData}))
	if err != nil || macValid.ValidityIndicator != ValidityIndicatorValid {
		t.Fatalf("MAC Verify = %+v, %v | MAC 验证 = %+v，%v", macValid, err, macValid, err)
	}
	macInvalid, err := DecodeMACVerifyResponse(runOp(t, server, OpMACVerify, MACVerifyRequest{UniqueIdentifier: macUID, Data: tampered, MACData: mac.MACData}))
	if err != nil || macInvalid.ValidityIndicator != ValidityIndicatorInvalid {
		t.Fatalf("MAC tampered Verify = %+v, %v | MAC 篡改验证 = %+v，%v", macInvalid, err, macInvalid, err)
	}
	if item := runOpItem(t, server, OpMAC, MACRequest{UniqueIdentifier: "missing", Data: data}); !errors.Is(item.Err(), ErrItemNotFound) {
		t.Fatalf("missing MAC key error = %v | 缺失 MAC 密钥错误 = %v", item.Err(), item.Err())
	}
}

// TestServerWrapUnwrapKey covers the ydx WrapKey and UnwrapKey extensions end to end. |
// TestServerWrapUnwrapKey 端到端覆盖 ydx WrapKey 与 UnwrapKey 扩展。
func TestServerWrapUnwrapKey(t *testing.T) {
	server := newTestServer(t)
	wrapping := createSymmetric(t, server)
	activateKey(t, server, wrapping)
	target := createSymmetric(t, server)
	activateKey(t, server, target)
	spec := KeyWrappingSpecification{
		WrappingMethod:           WrappingMethodEncrypt,
		EncryptionKeyInformation: &EncryptionKeyInformation{UniqueIdentifier: wrapping},
	}
	wrapItem := runOp(t, server, OpWrapKey, WrapKeyRequest{UniqueIdentifier: target, KeyWrappingSpecification: spec})
	wrapped, err := DecodeWrapKeyResponse(wrapItem)
	if err != nil {
		t.Fatalf("DecodeWrapKeyResponse: %v", err)
	}
	wrappedBlock, err := wrapped.Object.KeyBlock()
	if err != nil || wrappedBlock.Wrapping == nil || wrappedBlock.Wrapping.EncryptionKeyInformation == nil {
		t.Fatalf("wrapped block = %+v, %v | 已封装块 = %+v，%v", wrappedBlock, err, wrappedBlock, err)
	}
	unwrappedItem := runOp(t, server, OpUnwrapKey, UnwrapKeyRequest{
		Object: wrapped.Object,
		TemplateAttribute: TemplateAttribute{Attributes: AttributeList{
			NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmAES)),
			NewIntegerAttribute(AttributeCryptographicLength, 256),
		}},
	})
	unwrapped, err := DecodeUnwrapKeyResponse(unwrappedItem)
	if err != nil || unwrapped.UniqueIdentifier == "" || unwrapped.ObjectType != ObjectTypeSymmetricKey {
		t.Fatalf("DecodeUnwrapKeyResponse = %+v, %v | 解封响应 = %+v，%v", unwrapped, err, unwrapped, err)
	}
	activateKey(t, server, unwrapped.UniqueIdentifier)
	plaintext := []byte("round trip across wrap")
	encrypted, err := DecodeEncryptResponse(runOp(t, server, OpEncrypt, EncryptRequest{UniqueIdentifier: target, Data: plaintext}))
	if err != nil {
		t.Fatalf("Encrypt with original: %v | 原密钥加密失败：%v", err, err)
	}
	decrypted, err := DecodeDecryptResponse(runOp(t, server, OpDecrypt, DecryptRequest{
		UniqueIdentifier:           unwrapped.UniqueIdentifier,
		Data:                       encrypted.Data,
		IVCounterNonce:             encrypted.IVCounterNonce,
		AuthenticatedEncryptionTag: encrypted.AuthenticatedEncryptionTag,
	}))
	if err != nil || !bytes.Equal(decrypted.Data, plaintext) {
		t.Fatalf("Decrypt with unwrapped = %q, %v | 解封密钥解密 = %q，%v", decrypted.Data, err, decrypted.Data, err)
	}

	if item := runOpItem(t, server, OpWrapKey, WrapKeyRequest{UniqueIdentifier: target, KeyWrappingSpecification: KeyWrappingSpecification{WrappingMethod: WrappingMethodEncrypt}}); !errors.Is(item.Err(), ErrMalformed) {
		t.Fatalf("wrap without key error = %v | 无封装密钥错误 = %v", item.Err(), item.Err())
	}
	if item := runOpItem(t, server, OpWrapKey, WrapKeyRequest{UniqueIdentifier: "missing", KeyWrappingSpecification: spec}); !errors.Is(item.Err(), ErrItemNotFound) {
		t.Fatalf("wrap missing object error = %v | 封装缺失对象错误 = %v", item.Err(), item.Err())
	}
	plainObject := NewSymmetricKeyObject(rawKeyBlock(AlgorithmAES, testKeyMaterial()))
	if item := runOpItem(t, server, OpUnwrapKey, UnwrapKeyRequest{Object: plainObject}); !errors.Is(item.Err(), ErrMalformed) {
		t.Fatalf("unwrap plain object error = %v | 解封未封装对象错误 = %v", item.Err(), item.Err())
	}
	nonExtractable := runOp(t, server, OpRegister, RegisterRequest{
		ObjectType:        ObjectTypeSymmetricKey,
		TemplateAttribute: TemplateAttribute{Attributes: AttributeList{NewBooleanAttribute(AttributeExtractable, false)}},
		Object:            NewSymmetricKeyObject(rawKeyBlock(AlgorithmAES, testKeyMaterial())),
	})
	nonExtractableResponse, err := DecodeRegisterResponse(nonExtractable)
	if err != nil {
		t.Fatalf("DecodeRegisterResponse: %v", err)
	}
	if item := runOpItem(t, server, OpWrapKey, WrapKeyRequest{UniqueIdentifier: nonExtractableResponse.UniqueIdentifier, KeyWrappingSpecification: spec}); !errors.Is(item.Err(), ErrPermissionDenied) {
		t.Fatalf("wrap non-extractable error = %v | 封装不可导出对象错误 = %v", item.Err(), item.Err())
	}
	inactive := createSymmetric(t, server)
	if item := runOpItem(t, server, OpWrapKey, WrapKeyRequest{
		UniqueIdentifier: target,
		KeyWrappingSpecification: KeyWrappingSpecification{
			WrappingMethod:           WrappingMethodEncrypt,
			EncryptionKeyInformation: &EncryptionKeyInformation{UniqueIdentifier: inactive},
		},
	}); !errors.Is(item.Err(), ErrIllegalOperation) {
		t.Fatalf("wrap with inactive key error = %v | 使用非活动密钥封装错误 = %v", item.Err(), item.Err())
	}
}
