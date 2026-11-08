package kmip

import (
	"bytes"
	"errors"
	"testing"
)

// TestExportPayloadRoundTrip covers Export request and response encoding and decoding. |
// TestExportPayloadRoundTrip 覆盖 Export 请求与响应的编解码。
func TestExportPayloadRoundTrip(t *testing.T) {
	requestItem, err := (ExportRequest{UniqueIdentifier: "uid-export", KeyFormatType: KeyFormatPKCS8}).Item()
	if err != nil {
		t.Fatalf("ExportRequest.Item: %v", err)
	}
	request, err := DecodeExportRequest(requestItem)
	if err != nil || request.UniqueIdentifier != "uid-export" || request.KeyFormatType != KeyFormatPKCS8 {
		t.Fatalf("Export request = %+v, %v | Export 请求 = %+v，%v", request, err, request, err)
	}
	if _, err := (ExportRequest{}).Item(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty Export request err = %v | 空 Export 请求错误 = %v", err, err)
	}
	if _, err := DecodeExportRequest(NewTextString(TagUniqueIdentifier, "uid")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("non-structure Export request err = %v | 非结构 Export 请求错误 = %v", err, err)
	}
	if decoded, err := DecodeExportRequest(payloadItem(TagRequestPayload)); err != nil || decoded.UniqueIdentifier != "" {
		t.Fatalf("empty Export request decode = %+v, %v | 空 Export 请求解码 = %+v，%v", decoded, err, decoded, err)
	}

	material := []byte{1, 2, 3, 4}
	responseItem, err := (ExportResponse{
		ObjectType:         ObjectTypeSymmetricKey,
		UniqueIdentifier:   "uid-export",
		KeyFormatType:      KeyFormatRaw,
		KeyCompressionType: KeyCompressionECPublicKeyUncompressed,
		KeyMaterial:        material,
	}).Item()
	if err != nil {
		t.Fatalf("ExportResponse.Item: %v", err)
	}
	response, err := DecodeExportResponse(responseItem)
	if err != nil {
		t.Fatalf("DecodeExportResponse: %v", err)
	}
	if response.ObjectType != ObjectTypeSymmetricKey || response.UniqueIdentifier != "uid-export" ||
		response.KeyFormatType != KeyFormatRaw || response.KeyCompressionType != KeyCompressionECPublicKeyUncompressed ||
		!bytes.Equal(response.KeyMaterial, material) {
		t.Fatalf("Export response = %+v | Export 响应 = %+v", response, response)
	}
	for name, invalid := range map[string]ExportResponse{
		"missing object type": {UniqueIdentifier: "uid", KeyFormatType: KeyFormatRaw, KeyMaterial: material},
		"missing identifier":  {ObjectType: ObjectTypeSymmetricKey, KeyFormatType: KeyFormatRaw, KeyMaterial: material},
		"missing format":      {ObjectType: ObjectTypeSymmetricKey, UniqueIdentifier: "uid", KeyMaterial: material},
	} {
		if _, err := invalid.Item(); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("%s Item err = %v | %s Item 错误 = %v", name, err, name, err)
		}
	}

	if _, err := DecodeExportResponse(NewTextString(TagUniqueIdentifier, "uid")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("non-structure Export response err = %v | 非结构 Export 响应错误 = %v", err, err)
	}
	partial := func(children ...Item) Item { return payloadItem(TagResponsePayload, children...) }
	base := []Item{
		NewEnumeration(TagObjectType, uint32(ObjectTypeSymmetricKey)),
		NewTextString(TagUniqueIdentifier, "uid"),
		NewEnumeration(TagKeyFormatType, uint32(KeyFormatRaw)),
	}
	cases := map[string]Item{
		"missing material": partial(base...),
		"empty material":   partial(append(append([]Item(nil), base...), NewByteString(TagKeyMaterial, nil))...),
		"missing format":   partial(base[0], base[1], NewByteString(TagKeyMaterial, material)),
		"missing identifier": partial(base[0], NewEnumeration(TagKeyFormatType, uint32(KeyFormatRaw)),
			NewByteString(TagKeyMaterial, material)),
		"missing object type": partial(NewTextString(TagUniqueIdentifier, "uid"), base[2], NewByteString(TagKeyMaterial, material)),
	}
	for name, item := range cases {
		if _, err := DecodeExportResponse(item); !errors.Is(err, ErrMalformed) {
			t.Fatalf("%s decode err = %v | %s 解码错误 = %v", name, err, name, err)
		}
	}
}
