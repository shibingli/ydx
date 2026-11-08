package kmip

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// exportObject exports one object and decodes the response. | exportObject 导出一个对象并解码响应。
func exportObject(t *testing.T, server *Server, request ExportRequest) ExportResponse {
	t.Helper()
	response, err := DecodeExportResponse(runOp(t, server, OpExport, request))
	if err != nil {
		t.Fatalf("DecodeExportResponse: %v", err)
	}
	return response
}

// TestServerExportSymmetricKey covers successful export, format conversion and raw material equality. |
// TestServerExportSymmetricKey 覆盖成功导出、格式转换与原始材料一致性。
func TestServerExportSymmetricKey(t *testing.T) {
	server := newTestServer(t)
	uid := createSymmetric(t, server)
	got := getObject(t, server, GetRequest{UniqueIdentifier: uid})
	kb, err := got.KeyBlock()
	if err != nil {
		t.Fatalf("Get KeyBlock: %v", err)
	}
	raw, err := kb.Value.Raw()
	if err != nil {
		t.Fatalf("Get raw material: %v", err)
	}

	exported := exportObject(t, server, ExportRequest{UniqueIdentifier: uid})
	if exported.ObjectType != ObjectTypeSymmetricKey || exported.UniqueIdentifier != uid {
		t.Fatalf("export metadata = %+v | 导出元数据 = %+v", exported, exported)
	}
	if exported.KeyFormatType != kb.Format {
		t.Fatalf("export format = %s, want %s | 导出格式 = %s，期望 %s", exported.KeyFormatType, kb.Format, exported.KeyFormatType, kb.Format)
	}
	if !bytes.Equal(exported.KeyMaterial, raw) {
		t.Fatalf("export material differs from Get material | 导出材料与 Get 材料不一致")
	}

	transparent := exportObject(t, server, ExportRequest{UniqueIdentifier: uid, KeyFormatType: KeyFormatTransparentSymmetricKey})
	if transparent.KeyFormatType != KeyFormatTransparentSymmetricKey {
		t.Fatalf("transparent format = %s | 透明格式 = %s", transparent.KeyFormatType, transparent.KeyFormatType)
	}
	item, err := Decode(transparent.KeyMaterial)
	if err != nil {
		t.Fatalf("transparent Key Material is not one TTLV item: %v | 透明 Key Material 不是单个 TTLV 项：%v", err, err)
	}
	key, err := DecodeTransparentSymmetricKey(item)
	if err != nil || !bytes.Equal(key.Key, raw) {
		t.Fatalf("transparent material = %x, %v | 透明材料 = %x，%v", key.Key, err, key.Key, err)
	}

	privateID, publicID := createKeyPair(t, server, AlgorithmRSA, 2048)
	public := exportObject(t, server, ExportRequest{UniqueIdentifier: publicID})
	if public.ObjectType != ObjectTypePublicKey || len(public.KeyMaterial) == 0 {
		t.Fatalf("public key export = %+v | 公钥导出 = %+v", public, public)
	}
	private := exportObject(t, server, ExportRequest{UniqueIdentifier: privateID})
	if private.ObjectType != ObjectTypePrivateKey || len(private.KeyMaterial) == 0 {
		t.Fatalf("private key export = %+v | 私钥导出 = %+v", private, private)
	}
}

// TestServerExportExtractionAndState covers non-extractable, missing, destroyed and empty identifiers. |
// TestServerExportExtractionAndState 覆盖不可导出、缺失、已销毁与空标识符。
func TestServerExportExtractionAndState(t *testing.T) {
	server := newTestServer(t)
	registered := runOp(t, server, OpRegister, RegisterRequest{
		ObjectType: ObjectTypeSymmetricKey,
		TemplateAttribute: TemplateAttribute{Attributes: AttributeList{
			NewBooleanAttribute(AttributeExtractable, false),
		}},
		Object: NewSymmetricKeyObject(rawKeyBlock(AlgorithmAES, testKeyMaterial())),
	})
	registeredResponse, err := DecodeRegisterResponse(registered)
	if err != nil {
		t.Fatalf("DecodeRegisterResponse: %v", err)
	}
	item := runOpItem(t, server, OpExport, ExportRequest{UniqueIdentifier: registeredResponse.UniqueIdentifier})
	if !errors.Is(item.Err(), ErrPermissionDenied) || item.ResultReason != ResultReasonNotExtractable {
		t.Fatalf("non-extractable export = %v, %s | 不可导出 Export = %v，%s", item.Err(), item.ResultReason, item.Err(), item.ResultReason)
	}

	if item := runOpItem(t, server, OpExport, ExportRequest{UniqueIdentifier: "missing"}); !errors.Is(item.Err(), ErrItemNotFound) {
		t.Fatalf("missing export error = %v | 缺失对象导出错误 = %v", item.Err(), item.Err())
	}
	empty := roundTrip(t, server, RequestMessage{
		Header: testHeader(),
		BatchItems: []RequestBatchItem{{
			Operation: OpExport,
			Payload:   payloadItem(TagRequestPayload),
		}},
	})
	if len(empty.BatchItems) != 1 || !errors.Is(empty.BatchItems[0].Err(), ErrMalformed) {
		t.Fatalf("empty identifier export = %+v | 空标识符导出 = %+v", empty.BatchItems, empty.BatchItems)
	}

	destroyed := createSymmetric(t, server)
	runOp(t, server, OpDestroy, DestroyRequest{UniqueIdentifier: destroyed})
	if item := runOpItem(t, server, OpExport, ExportRequest{UniqueIdentifier: destroyed}); !errors.Is(item.Err(), ErrIllegalOperation) {
		t.Fatalf("destroyed export error = %v | 已销毁对象导出错误 = %v", item.Err(), item.Err())
	}
}

// TestServerExportCertificateAndUnsupportedTypes covers certificate export and object types without material. |
// TestServerExportCertificateAndUnsupportedTypes 覆盖证书导出与没有材料的对象类型。
func TestServerExportCertificateAndUnsupportedTypes(t *testing.T) {
	server := newTestServer(t)
	value := []byte{0x30, 0x82, 0x01, 0x00, 0x01, 0x02, 0x03}
	certificate := runOp(t, server, OpRegister, RegisterRequest{
		ObjectType: ObjectTypeCertificate,
		Object:     NewCertificateObject(CertificateTypeX509, value),
	})
	certificateResponse, err := DecodeRegisterResponse(certificate)
	if err != nil {
		t.Fatalf("DecodeRegisterResponse certificate: %v", err)
	}
	exported := exportObject(t, server, ExportRequest{UniqueIdentifier: certificateResponse.UniqueIdentifier})
	if exported.ObjectType != ObjectTypeCertificate || exported.KeyFormatType != KeyFormatX509 ||
		!bytes.Equal(exported.KeyMaterial, value) {
		t.Fatalf("certificate export = %+v | 证书导出 = %+v", exported, exported)
	}
	if item := runOpItem(t, server, OpExport, ExportRequest{
		UniqueIdentifier: certificateResponse.UniqueIdentifier,
		KeyFormatType:    KeyFormatRaw,
	}); !errors.Is(item.Err(), ErrUnsupported) {
		t.Fatalf("certificate Raw export error = %v | 证书 Raw 导出错误 = %v", item.Err(), item.Err())
	}

	template := runOp(t, server, OpRegister, RegisterRequest{
		ObjectType: ObjectTypeTemplate,
		Object:     NewTemplateObject(AttributeList{NewTextAttribute(AttributeComment, "template")}),
	})
	templateResponse, err := DecodeRegisterResponse(template)
	if err != nil {
		t.Fatalf("DecodeRegisterResponse template: %v", err)
	}
	if item := runOpItem(t, server, OpExport, ExportRequest{UniqueIdentifier: templateResponse.UniqueIdentifier}); !errors.Is(item.Err(), ErrUnsupported) {
		t.Fatalf("template export error = %v | 模板导出错误 = %v", item.Err(), item.Err())
	}
	opaque := runOp(t, server, OpRegister, RegisterRequest{
		ObjectType: ObjectTypeOpaqueObject,
		Object:     NewOpaqueObject(7, []byte{4, 5}),
	})
	opaqueResponse, err := DecodeRegisterResponse(opaque)
	if err != nil {
		t.Fatalf("DecodeRegisterResponse opaque: %v", err)
	}
	if item := runOpItem(t, server, OpExport, ExportRequest{UniqueIdentifier: opaqueResponse.UniqueIdentifier}); !errors.Is(item.Err(), ErrUnsupported) {
		t.Fatalf("opaque export error = %v | 不透明对象导出错误 = %v", item.Err(), item.Err())
	}
}

// TestServerExportKMIP20Rejected verifies that Export is refused under KMIP 2.0 with ErrUnsupported. |
// TestServerExportKMIP20Rejected 校验 KMIP 2.0 下 Export 以 ErrUnsupported 拒绝。
func TestServerExportKMIP20Rejected(t *testing.T) {
	server := newTestServer(t)
	uid := createSymmetric(t, server)
	item := runPlainOpVersion(t, server, ProtocolVersion20, OpExport, ExportRequest{UniqueIdentifier: uid})
	if !errors.Is(item.Err(), ErrUnsupported) {
		t.Fatalf("2.0 Export error = %v, want ErrUnsupported | 2.0 Export 错误 = %v，期望 ErrUnsupported", item.Err(), item.Err())
	}
	if item.ResultReason != ResultReasonOperationNotSupported {
		t.Fatalf("2.0 Export reason = %s | 2.0 Export 原因 = %s", item.ResultReason, item.ResultReason)
	}
}

// TestServerExportAuthorizer verifies that an Authorizer can deny Export and sees its identifier. |
// TestServerExportAuthorizer 校验 Authorizer 可拒绝 Export 并看到其标识符。
func TestServerExportAuthorizer(t *testing.T) {
	var seen AuthorizationRequest
	server, err := NewServer(ServerConfig{
		AllowPlaintext: true,
		Store:          NewMemoryStore(),
		Authorizer: AuthorizerFunc(func(_ context.Context, request AuthorizationRequest) error {
			seen = request
			if request.Operation == OpExport {
				return ErrPermissionDenied
			}
			return nil
		}),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	uid := createSymmetric(t, server)
	item := runOpItem(t, server, OpExport, ExportRequest{UniqueIdentifier: uid})
	if !errors.Is(item.Err(), ErrPermissionDenied) {
		t.Fatalf("denied export = %v | 被拒绝的导出 = %v", item.Err(), item.Err())
	}
	if seen.Operation != OpExport || seen.UniqueIdentifier != uid {
		t.Fatalf("authorization metadata = %+v | 授权元数据 = %+v", seen, seen)
	}
}
