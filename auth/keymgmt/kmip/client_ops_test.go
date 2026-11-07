package kmip

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// TestClientOperationsOverTCP exercises every client operation against a real TCP server. |
// TestClientOperationsOverTCP 通过真实 TCP 服务器覆盖每个客户端操作。
func TestClientOperationsOverTCP(t *testing.T) {
	_, address := startTestServer(t)
	client := dialTestClient(t, address)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	created, err := client.Create(ctx, CreateRequest{ObjectType: ObjectTypeSymmetricKey, TemplateAttribute: symmetricTemplate()})
	if err != nil {
		t.Fatalf("Create: %v | 创建失败：%v", err, err)
	}
	if _, err := client.Activate(ctx, ActivateRequest{UniqueIdentifier: created.UniqueIdentifier}); err != nil {
		t.Fatalf("Activate: %v | 激活失败：%v", err, err)
	}
	attributes, err := client.GetAttributes(ctx, GetAttributesRequest{
		UniqueIdentifier: created.UniqueIdentifier,
		AttributeNames:   []string{AttributeCryptographicAlgorithm},
	})
	if err != nil || len(attributes.AttributeList) == 0 {
		t.Fatalf("GetAttributes = %+v, %v | 获取属性 = %+v，%v", attributes, err, attributes, err)
	}
	names, err := client.GetAttributeList(ctx, GetAttributeListRequest{UniqueIdentifier: created.UniqueIdentifier})
	if err != nil || len(names.AttributeNames) == 0 {
		t.Fatalf("GetAttributeList = %+v, %v | 获取属性列表 = %+v，%v", names, err, names, err)
	}

	gcm := CryptographicParameters{BlockCipherMode: BlockCipherModeGCM, RandomIV: true}
	plaintext := []byte("client side crypto payload")
	encrypted, err := client.Encrypt(ctx, EncryptRequest{
		UniqueIdentifier: created.UniqueIdentifier, CryptographicParameters: &gcm, Data: plaintext,
	})
	if err != nil || len(encrypted.Data) == 0 || len(encrypted.IVCounterNonce) == 0 {
		t.Fatalf("Encrypt = %+v, %v | 加密 = %+v，%v", encrypted, err, encrypted, err)
	}
	decrypted, err := client.Decrypt(ctx, DecryptRequest{
		UniqueIdentifier:           created.UniqueIdentifier,
		CryptographicParameters:    &gcm,
		Data:                       encrypted.Data,
		IVCounterNonce:             encrypted.IVCounterNonce,
		AuthenticatedEncryptionTag: encrypted.AuthenticatedEncryptionTag,
	})
	if err != nil || !bytes.Equal(decrypted.Data, plaintext) {
		t.Fatalf("Decrypt = %q, %v | 解密 = %q，%v", decrypted.Data, err, decrypted.Data, err)
	}

	pair, err := client.CreateKeyPair(ctx, CreateKeyPairRequest{CommonTemplateAttribute: &TemplateAttribute{Attributes: AttributeList{
		NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmRSA)),
		NewIntegerAttribute(AttributeCryptographicLength, 2048),
	}}})
	if err != nil || pair.PrivateKeyUniqueIdentifier == "" || pair.PublicKeyUniqueIdentifier == "" {
		t.Fatalf("CreateKeyPair = %+v, %v | 创建密钥对 = %+v，%v", pair, err, pair, err)
	}
	for _, uid := range []string{pair.PrivateKeyUniqueIdentifier, pair.PublicKeyUniqueIdentifier} {
		if _, err := client.Activate(ctx, ActivateRequest{UniqueIdentifier: uid}); err != nil {
			t.Fatalf("Activate key pair member: %v | 激活密钥对成员失败：%v", err, err)
		}
	}
	rsaParams := CryptographicParameters{DigitalSignatureAlgorithm: DigitalSignatureRSAPKCS1SHA256}
	signed, err := client.Sign(ctx, SignRequest{
		UniqueIdentifier: pair.PrivateKeyUniqueIdentifier, CryptographicParameters: &rsaParams, Data: plaintext,
	})
	if err != nil || len(signed.SignatureData) == 0 {
		t.Fatalf("Sign = %+v, %v | 签名 = %+v，%v", signed, err, signed, err)
	}
	verified, err := client.Verify(ctx, VerifyRequest{
		UniqueIdentifier: pair.PublicKeyUniqueIdentifier, CryptographicParameters: &rsaParams,
		Data: plaintext, SignatureData: signed.SignatureData,
	})
	if err != nil || verified.ValidityIndicator != ValidityIndicatorValid {
		t.Fatalf("Verify = %+v, %v | 验签 = %+v，%v", verified, err, verified, err)
	}

	registered, err := client.Register(ctx, RegisterRequest{
		ObjectType: ObjectTypeSymmetricKey,
		TemplateAttribute: TemplateAttribute{Attributes: AttributeList{
			NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmHMACSHA256)),
			NewIntegerAttribute(AttributeCryptographicLength, 256),
		}},
		Object: NewSymmetricKeyObject(rawKeyBlock(AlgorithmHMACSHA256, bytes.Repeat([]byte{0x11}, 32))),
	})
	if err != nil || registered.UniqueIdentifier == "" {
		t.Fatalf("Register = %+v, %v | 注册 = %+v，%v", registered, err, registered, err)
	}
	if _, err := client.Activate(ctx, ActivateRequest{UniqueIdentifier: registered.UniqueIdentifier}); err != nil {
		t.Fatalf("Activate registered key: %v | 激活注册密钥失败：%v", err, err)
	}
	mac, err := client.MAC(ctx, MACRequest{UniqueIdentifier: registered.UniqueIdentifier, Data: plaintext})
	if err != nil || len(mac.MACData) == 0 {
		t.Fatalf("MAC = %+v, %v | MAC = %+v，%v", mac, err, mac, err)
	}
	macValid, err := client.MACVerify(ctx, MACVerifyRequest{
		UniqueIdentifier: registered.UniqueIdentifier, Data: plaintext, MACData: mac.MACData,
	})
	if err != nil || macValid.ValidityIndicator != ValidityIndicatorValid {
		t.Fatalf("MACVerify = %+v, %v | MAC 验证 = %+v，%v", macValid, err, macValid, err)
	}

	located, err := client.Locate(ctx, LocateRequest{Attributes: AttributeList{
		NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmAES)),
		NewIntegerAttribute(AttributeCryptographicLength, 256),
	}})
	if err != nil || !containsString(located.UniqueIdentifiers, created.UniqueIdentifier) {
		t.Fatalf("Locate = %+v, %v | 定位 = %+v，%v", located, err, located, err)
	}
	derived, err := client.DeriveKey(ctx, DeriveKeyRequest{
		ObjectType:        ObjectTypeSymmetricKey,
		UniqueIdentifiers: []string{created.UniqueIdentifier},
		DerivationMethod:  DerivationMethodHKDF,
		DerivationParameters: DerivationParameters{
			DerivationData: []byte("client context"),
			Salt:           []byte("client salt"),
		},
		TemplateAttribute: TemplateAttribute{Attributes: AttributeList{
			NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmAES)),
			NewIntegerAttribute(AttributeCryptographicLength, 128),
		}},
	})
	if err != nil || derived.UniqueIdentifier == "" {
		t.Fatalf("DeriveKey = %+v, %v | 派生密钥 = %+v，%v", derived, err, derived, err)
	}

	target, err := client.Create(ctx, CreateRequest{ObjectType: ObjectTypeSymmetricKey, TemplateAttribute: symmetricTemplate()})
	if err != nil {
		t.Fatalf("Create wrap target: %v | 创建封装目标失败：%v", err, err)
	}
	if _, err := client.Activate(ctx, ActivateRequest{UniqueIdentifier: target.UniqueIdentifier}); err != nil {
		t.Fatalf("Activate wrap target: %v | 激活封装目标失败：%v", err, err)
	}
	wrapped, err := client.WrapKey(ctx, WrapKeyRequest{
		UniqueIdentifier: target.UniqueIdentifier,
		KeyWrappingSpecification: KeyWrappingSpecification{
			WrappingMethod:           WrappingMethodEncrypt,
			EncryptionKeyInformation: &EncryptionKeyInformation{UniqueIdentifier: created.UniqueIdentifier},
		},
	})
	if err != nil || wrapped.UniqueIdentifier == "" {
		t.Fatalf("WrapKey = %+v, %v | 封装 = %+v，%v", wrapped, err, wrapped, err)
	}
	unwrapped, err := client.UnwrapKey(ctx, UnwrapKeyRequest{
		Object: wrapped.Object,
		TemplateAttribute: TemplateAttribute{Attributes: AttributeList{
			NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmAES)),
			NewIntegerAttribute(AttributeCryptographicLength, 256),
		}},
	})
	if err != nil || unwrapped.UniqueIdentifier == "" {
		t.Fatalf("UnwrapKey = %+v, %v | 解封 = %+v，%v", unwrapped, err, unwrapped, err)
	}

	checked, err := client.Check(ctx, CheckRequest{UniqueIdentifier: created.UniqueIdentifier, CryptographicUsageMask: UsageMaskEncrypt})
	if err != nil || checked.UniqueIdentifier != created.UniqueIdentifier {
		t.Fatalf("Check = %+v, %v | 检查 = %+v，%v", checked, err, checked, err)
	}
	query, err := client.Query(ctx, QueryRequest{QueryFunctions: []QueryFunction{QueryFunctionOperations}})
	if err != nil || len(query.Operations) == 0 {
		t.Fatalf("Query = %+v, %v | 查询 = %+v，%v", query, err, query, err)
	}
	versions, err := client.DiscoverVersions(ctx, DiscoverVersionsRequest{ProtocolVersions: []ProtocolVersion{DefaultProtocolVersion}})
	if err != nil || len(versions.ProtocolVersions) == 0 {
		t.Fatalf("DiscoverVersions = %+v, %v | 发现版本 = %+v，%v", versions, err, versions, err)
	}

	revoked, err := client.Revoke(ctx, RevokeRequest{
		UniqueIdentifier: derived.UniqueIdentifier,
		Reason:           RevocationReason{Code: RevocationCessationOfOperation},
	})
	if err != nil || revoked.UniqueIdentifier != derived.UniqueIdentifier {
		t.Fatalf("Revoke = %+v, %v | 撤销 = %+v，%v", revoked, err, revoked, err)
	}
	destroyed, err := client.Destroy(ctx, DestroyRequest{UniqueIdentifier: derived.UniqueIdentifier})
	if err != nil || destroyed.UniqueIdentifier != derived.UniqueIdentifier {
		t.Fatalf("Destroy = %+v, %v | 销毁 = %+v，%v", destroyed, err, destroyed, err)
	}

	if _, err := client.Get(ctx, GetRequest{UniqueIdentifier: "missing"}); !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("Get missing error = %v | 获取缺失对象错误 = %v", err, err)
	}
	if _, err := client.Do(ctx); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Do without items error = %v | 空请求错误 = %v", err, err)
	}

	canceled, cancelRequest := context.WithCancel(ctx)
	cancelRequest()
	if _, err := client.Query(canceled, QueryRequest{QueryFunctions: []QueryFunction{QueryFunctionOperations}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Query error = %v | 已取消查询错误 = %v", err, err)
	}
}

// containsString reports whether values contains want. | containsString 报告 values 是否包含 want。
func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// TestClientConcurrentUse exercises serialized concurrent requests on one Client. |
// TestClientConcurrentUse 覆盖同一 Client 上的并发串行请求。
func TestClientConcurrentUse(t *testing.T) {
	_, address := startTestServer(t)
	client := dialTestClient(t, address)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	errsCh := make(chan error, 8)
	for index := 0; index < 8; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := client.Query(ctx, QueryRequest{QueryFunctions: []QueryFunction{QueryFunctionOperations}})
			errsCh <- err
		}()
	}
	wg.Wait()
	close(errsCh)
	for err := range errsCh {
		if err != nil {
			t.Fatalf("concurrent Query: %v | 并发查询失败：%v", err, err)
		}
	}
}
