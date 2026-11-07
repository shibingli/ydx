package kmip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// buildTLTV assembles a TTLV item from raw parts for malformed-input tests. | buildTLTV 由原始部件组装 TTLV 项，用于畸形输入测试。
func buildTLTV(tag Tag, typ Type, value []byte) []byte {
	out := make([]byte, ttlvHeaderSize+(len(value)+7)/8*8)
	out[0] = byte(uint32(tag) >> 16)
	out[1] = byte(uint32(tag) >> 8)
	out[2] = byte(tag)
	out[3] = byte(typ)
	binary.BigEndian.PutUint32(out[4:8], uint32(len(value)))
	copy(out[8:], value)
	return out
}

func TestTTLVSpecVector(t *testing.T) {
	raw := []byte{
		0x42, 0x00, 0x69, 0x01, 0x00, 0x00, 0x00, 0x20,
		0x42, 0x00, 0x6A, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x42, 0x00, 0x6B, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
	}
	item, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if item.Tag != TagProtocolVersion || item.Type != TypeStructure || len(item.Children) != 2 {
		t.Fatalf("unexpected item: %+v", item)
	}
	major, err := item.Children[0].AsInteger()
	if err != nil || major != 1 {
		t.Fatalf("major = %d, %v", major, err)
	}
	minor, err := item.Children[1].AsInteger()
	if err != nil || minor != 4 {
		t.Fatalf("minor = %d, %v", minor, err)
	}
	encoded, err := Encode(item)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(encoded, raw) {
		t.Fatalf("re-encoding changed bytes:\n got %x\nwant %x", encoded, raw)
	}
}

func TestTTLVRoundTrip(t *testing.T) {
	when := time.Unix(1700000000, 123456000).UTC()
	bigValue, _ := new(big.Int).SetString("-123456789012345678901234567890", 10)
	item := NewStructure(TagRequestMessage,
		NewStructure(TagRequestHeader,
			NewInteger(TagProtocolVersionMajor, 1),
			NewInteger(TagBatchCount, 2),
			NewEnumeration(TagOperation, uint32(OpCreate)),
			NewBoolean(TagAsynchronousIndicator, true),
			NewTextString(TagNameValue, "clé-🔑"),
			NewByteString(TagKeyMaterial, []byte{0, 1, 2, 3, 4}),
			NewDateTime(TagTimeStamp, when),
			NewDateTimeExtended(TagLastChangeDate, when),
			NewInterval(TagLeaseTime, 90*time.Second),
			NewBigInteger(TagModulus, bigValue),
		),
	)
	encoded, err := Encode(item)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(encoded)%8 != 0 {
		t.Fatalf("encoded length %d is not a multiple of 8", len(encoded))
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	hdr := decoded.Children[0]
	if got, _ := hdr.Children[4].AsTextString(); got != "clé-🔑" {
		t.Fatalf("text = %q", got)
	}
	if got, _ := hdr.Children[3].AsBoolean(); !got {
		t.Fatalf("boolean = false")
	}
	if got, _ := hdr.Children[6].AsDateTime(); !got.Equal(when.Truncate(time.Second)) {
		t.Fatalf("date = %v", got)
	}
	if got, _ := hdr.Children[7].AsDateTimeExtended(); !got.Equal(when) {
		t.Fatalf("date-time-extended = %v", got)
	}
	if got, _ := hdr.Children[8].AsInterval(); got != 90*time.Second {
		t.Fatalf("interval = %v", got)
	}
	gotBig, err := hdr.Children[9].AsBigInteger()
	if err != nil || gotBig.Cmp(bigValue) != 0 {
		t.Fatalf("big = %v, %v", gotBig, err)
	}
	again, err := Encode(decoded)
	if err != nil {
		t.Fatalf("re-Encode: %v", err)
	}
	if !bytes.Equal(encoded, again) {
		t.Fatalf("round trip changed bytes")
	}
}

func TestTTLVUnknownTagPreserved(t *testing.T) {
	const vendorTag Tag = 0x54FFF1
	item := NewStructure(TagTemplate, NewTextString(vendorTag, "vendor"))
	encoded, err := Encode(item)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	child, ok := decoded.Child(vendorTag)
	if !ok {
		t.Fatalf("vendor tag lost")
	}
	if got, _ := child.AsTextString(); got != "vendor" {
		t.Fatalf("vendor value = %q", got)
	}
}

func TestTTLVZeroPaddingRejected(t *testing.T) {
	raw := buildTLTV(TagNameValue, TypeTextString, []byte("ab"))
	raw[len(raw)-1] = 0x7F
	if _, err := Decode(raw); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestTTLVMalformedInputs(t *testing.T) {
	cases := map[string][]byte{
		"empty":              {},
		"short header":       {0x42, 0x00},
		"zero tag":           buildTLTV(0, TypeInteger, make([]byte, 8)),
		"unknown type":       buildTLTV(TagBatchCount, Type(0x7F), []byte{0, 0, 0, 0}),
		"integer short":      buildTLTV(TagBatchCount, TypeInteger, []byte{0, 0, 0, 0}),
		"boolean bad":        buildTLTV(TagAsynchronousIndicator, TypeBoolean, []byte{0, 0, 0, 0, 0, 0, 0, 2}),
		"big integer length": buildTLTV(TagModulus, TypeBigInteger, []byte{0, 1, 2}),
		"structure length":   buildTLTV(TagRequestMessage, TypeStructure, make([]byte, 4)),
		"text invalid utf8":  buildTLTV(TagNameValue, TypeTextString, []byte{0xFF, 0xFE}),
		"truncated value":    buildTLTV(TagKeyMaterial, TypeByteString, []byte{1, 2, 3})[:12],
		"trailing":           append(buildTLTV(TagBatchCount, TypeInteger, make([]byte, 8)), 0x42),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(raw); err == nil {
				t.Fatalf("Decode accepted malformed input")
			}
		})
	}
}

func TestTTLVLimits(t *testing.T) {
	item := NewByteString(TagKeyMaterial, make([]byte, 64))
	encoded, err := Encode(item)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := DecodeWithLimits(encoded, Limits{MaxSize: 16, MaxDepth: 8, MaxItems: 8}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("size limit err = %v", err)
	}

	nested := NewStructure(TagRequestMessage, NewStructure(TagBatchItem, NewStructure(TagRequestPayload)))
	encoded, err = Encode(nested)
	if err != nil {
		t.Fatalf("Encode nested: %v", err)
	}
	if _, err := DecodeWithLimits(encoded, Limits{MaxSize: 1024, MaxDepth: 1, MaxItems: 128}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("depth limit err = %v", err)
	}
	if _, err := DecodeWithLimits(encoded, Limits{MaxSize: 1024, MaxDepth: 8, MaxItems: 2}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("item limit err = %v", err)
	}
}

func TestTTLVReaderWriter(t *testing.T) {
	item := NewStructure(TagResponseMessage, NewTextString(TagResultMessage, "ok"))
	var buf bytes.Buffer
	if err := WriteItem(&buf, item); err != nil {
		t.Fatalf("WriteItem: %v", err)
	}
	if buf.Len()%8 != 0 {
		t.Fatalf("wire length %d is not a multiple of 8", buf.Len())
	}
	got, err := ReadItem(&buf, DefaultLimits())
	if err != nil {
		t.Fatalf("ReadItem: %v", err)
	}
	if got.Tag != TagResponseMessage || len(got.Children) != 1 {
		t.Fatalf("unexpected item: %+v", got)
	}
	if _, err := ReadItem(&bytes.Buffer{}, DefaultLimits()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("empty read err = %v", err)
	}
}

func TestTTLVTypedAccessors(t *testing.T) {
	if _, err := NewTextString(TagNameValue, "x").AsInteger(); err == nil {
		t.Fatalf("text decoded as integer")
	}
	if _, err := (Item{Tag: TagNameValue, Type: TypeTextString, Value: []byte{0xFF}}).AsTextString(); err == nil {
		t.Fatalf("invalid UTF-8 accepted")
	}
	if s := UsageMaskEncrypt.String(); !strings.Contains(s, "Encrypt") {
		t.Fatalf("mask string = %q", s)
	}
	empty := NewBigInteger(TagModulus, nil)
	v, err := empty.AsBigInteger()
	if err != nil || v.Sign() != 0 {
		t.Fatalf("nil big integer = %v, %v", v, err)
	}
}
