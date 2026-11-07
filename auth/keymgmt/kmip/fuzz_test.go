package kmip

import (
	"testing"
)

// fuzzTTLVSeeds returns canonical and malformed TTLV encodings. | fuzzTTLVSeeds 返回规范与畸形的 TTLV 编码。
func fuzzTTLVSeeds(t testing.TB) [][]byte {
	t.Helper()
	valid, err := Encode(NewStructure(TagRequestPayload,
		NewEnumeration(TagObjectType, uint32(ObjectTypeSymmetricKey)),
		NewTextString(TagUniqueIdentifier, "seed"),
	))
	if err != nil {
		t.Fatalf("Encode seed: %v", err)
	}
	truncated := valid[:len(valid)-3]
	badLength := append([]byte(nil), valid...)
	badLength[4], badLength[5], badLength[6], badLength[7] = 0xFF, 0xFF, 0xFF, 0xFF
	badPadding := append([]byte(nil), valid...)
	badPadding[len(badPadding)-1] = 0xFF
	return [][]byte{
		valid,
		truncated,
		badLength,
		badPadding,
		{0x42, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
		{},
		{0x42},
	}
}

// TestMalformedFramingRegression pins decoder behavior for malformed TTLV framing. |
// TestMalformedFramingRegression 固化解码器对畸形 TTLV 框架的行为。
func TestMalformedFramingRegression(t *testing.T) {
	valid, err := Encode(NewTextString(TagUniqueIdentifier, "abc"))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	for name, data := range map[string][]byte{
		"truncated header":  {0x42, 0x00, 0x00},
		"truncated value":   valid[:len(valid)-1],
		"oversized length":  {0x42, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 'a'},
		"bad padding":       append(append(append([]byte(nil), valid[:len(valid)-1]...), 0xFF), 0, 0),
		"negative framing":  {0x42, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF},
		"invalid type byte": {0x42, 0x00, 0x00, 0x7F, 0x00, 0x00, 0x00, 0x00},
	} {
		if _, err := Decode(data); err == nil {
			t.Fatalf("%s decoded without error | %s 解码未报错", name, name)
		}
	}
	if _, err := DecodeWithLimits(valid, Limits{MaxSize: 4}); err == nil {
		t.Fatal("oversized message decoded under MaxSize | 超出 MaxSize 的消息被解码")
	}
	if _, err := DecodeRequest(valid); err == nil {
		t.Fatal("non-message decoded as a request | 非消息被解码为请求")
	}
	if _, err := DecodeResponse(valid); err == nil {
		t.Fatal("non-message decoded as a response | 非消息被解码为响应")
	}
	nested := NewStructure(TagRequestPayload)
	for index := 0; index < 8; index++ {
		nested = NewStructure(TagRequestPayload, nested)
	}
	depthData, err := Encode(nested)
	if err != nil {
		t.Fatalf("EncodeWithLimits nested: %v", err)
	}
	if _, err := DecodeWithLimits(depthData, Limits{MaxDepth: 4}); err == nil {
		t.Fatal("over-depth structure decoded | 超深结构被解码")
	}
}

// FuzzDecodeRequest checks that request decoding never panics on arbitrary input. |
// FuzzDecodeRequest 检查请求解码在任意输入下永不 panic。
func FuzzDecodeRequest(f *testing.F) {
	request, err := EncodeRequest(RequestMessage{
		Header: testHeader(),
		BatchItems: []RequestBatchItem{{
			Operation: OpQuery,
			Payload:   mustItemFuzz(f, QueryRequest{QueryFunctions: []QueryFunction{QueryFunctionOperations}}),
		}},
	})
	if err != nil {
		f.Fatalf("EncodeRequest seed: %v", err)
	}
	for _, seed := range fuzzTTLVSeeds(f) {
		f.Add(seed)
	}
	f.Add(request)
	f.Add(append(append([]byte(nil), request...), 0x00))
	f.Fuzz(func(t *testing.T, data []byte) {
		message, err := DecodeRequestWithLimits(data, Limits{MaxSize: 1 << 16, MaxDepth: 32, MaxItems: 4096})
		if err != nil {
			return
		}
		if _, err := EncodeRequest(message); err != nil {
			t.Fatalf("re-encoding a decoded request failed: %v | 重新编码已解码请求失败：%v", err, err)
		}
	})
}

// mustItemFuzz encodes a payload or aborts fuzz setup. | mustItemFuzz 编码负载或终止模糊测试初始化。
func mustItemFuzz(f *testing.F, encoder payloadEncoder) Item {
	f.Helper()
	item, err := encoder.Item()
	if err != nil {
		f.Fatalf("encode payload: %v", err)
	}
	return item
}

// FuzzDecodeResponse checks that response decoding never panics on arbitrary input. |
// FuzzDecodeResponse 检查响应解码在任意输入下永不 panic。
func FuzzDecodeResponse(f *testing.F) {
	response, err := EncodeResponse(ResponseMessage{
		Header: ResponseHeader{ProtocolVersion: DefaultProtocolVersion},
		BatchItems: []ResponseBatchItem{{
			Operation:    OpQuery,
			ResultStatus: ResultStatusSuccess,
			Payload:      mustItemFuzz(f, QueryResponse{VendorIdentification: "ydx"}),
		}},
	})
	if err != nil {
		f.Fatalf("EncodeResponse seed: %v", err)
	}
	for _, seed := range fuzzTTLVSeeds(f) {
		f.Add(seed)
	}
	f.Add(response)
	f.Fuzz(func(t *testing.T, data []byte) {
		message, err := DecodeResponseWithLimits(data, Limits{MaxSize: 1 << 16, MaxDepth: 32, MaxItems: 4096})
		if err != nil {
			return
		}
		if _, err := EncodeResponse(message); err != nil {
			t.Fatalf("re-encoding a decoded response failed: %v | 重新编码已解码响应失败：%v", err, err)
		}
	})
}

// FuzzDecodeTTLV checks that generic TTLV decoding never panics on arbitrary input. |
// FuzzDecodeTTLV 检查通用 TTLV 解码在任意输入下永不 panic。
func FuzzDecodeTTLV(f *testing.F) {
	for _, seed := range fuzzTTLVSeeds(f) {
		f.Add(seed)
	}
	structure, err := Encode(NewStructure(TagKeyValue,
		NewByteString(TagKeyMaterial, []byte{1, 2, 3, 4}),
		NewInteger(TagCryptographicLength, 32),
	))
	if err != nil {
		f.Fatalf("Encode structure seed: %v", err)
	}
	f.Add(structure)
	f.Fuzz(func(t *testing.T, data []byte) {
		item, err := DecodeWithLimits(data, Limits{MaxSize: 1 << 16, MaxDepth: 32, MaxItems: 4096})
		if err != nil {
			return
		}
		if _, err := EncodeWithLimits(item, Limits{MaxSize: 1 << 16, MaxDepth: 32, MaxItems: 4096}); err != nil {
			t.Fatalf("re-encoding a decoded item failed: %v | 重新编码已解码项失败：%v", err, err)
		}
	})
}
