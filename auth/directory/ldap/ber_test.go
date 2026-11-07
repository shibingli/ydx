package ldap

import (
	"bytes"
	"errors"
	"testing"
)

// TestBERPrimitiveEncoding verifies canonical primitive encodings. | TestBERPrimitiveEncoding
// 校验规范的原始值编码。
func TestBERPrimitiveEncoding(t *testing.T) {
	tests := []struct {
		name  string
		build func(*berEncoder)
		want  []byte
	}{
		{name: "boolean true", build: func(e *berEncoder) { e.boolean(true) }, want: []byte{0x01, 0x01, 0xff}},
		{name: "boolean false", build: func(e *berEncoder) { e.boolean(false) }, want: []byte{0x01, 0x01, 0x00}},
		{name: "integer zero", build: func(e *berEncoder) { e.integer(0) }, want: []byte{0x02, 0x01, 0x00}},
		{name: "integer 127", build: func(e *berEncoder) { e.integer(127) }, want: []byte{0x02, 0x01, 0x7f}},
		{name: "integer 128", build: func(e *berEncoder) { e.integer(128) }, want: []byte{0x02, 0x02, 0x00, 0x80}},
		{name: "integer -1", build: func(e *berEncoder) { e.integer(-1) }, want: []byte{0x02, 0x01, 0xff}},
		{name: "integer -129", build: func(e *berEncoder) { e.integer(-129) }, want: []byte{0x02, 0x02, 0xff, 0x7f}},
		{name: "enumerated", build: func(e *berEncoder) { e.enumerated(49) }, want: []byte{0x0a, 0x01, 0x31}},
		{name: "octet string", build: func(e *berEncoder) { e.octetString([]byte("abc")) }, want: []byte{0x04, 0x03, 'a', 'b', 'c'}},
		{name: "text empty", build: func(e *berEncoder) { e.text("") }, want: []byte{0x04, 0x00}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoder := newBEREncoder(8)
			test.build(encoder)
			if !bytes.Equal(encoder.bytes(), test.want) {
				t.Fatalf("encoded % x, want % x", encoder.bytes(), test.want)
			}
		})
	}
}

// TestBERLongLength verifies long-form lengths and nested frame compaction. |
// TestBERLongLength 校验长形式长度与嵌套帧压缩。
func TestBERLongLength(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, 300)
	encoder := newBEREncoder(64)
	encoder.open(berClassUniversal, berTagSequence)
	encoder.primitive(berClassUniversal, berTagOctetString, payload)
	encoder.close()
	encoded := encoder.bytes()
	if len(encoded) != 1+3+1+3+300 {
		t.Fatalf("encoded length %d", len(encoded))
	}
	reader := newBERReader(encoded)
	outer, err := reader.expectSequence()
	if err != nil {
		t.Fatalf("expect sequence: %v", err)
	}
	inner, err := reader.subReader(outer)
	if err != nil {
		t.Fatalf("sub reader: %v", err)
	}
	value, err := inner.readOctetString()
	if err != nil {
		t.Fatalf("read octet string: %v", err)
	}
	if !bytes.Equal(value, payload) {
		t.Fatalf("payload mismatch")
	}
	if err := reader.expectEnd(); err != nil {
		t.Fatalf("trailing: %v", err)
	}
}

// TestBERHighTagNumber verifies high-tag-number encoding and decoding. | TestBERHighTagNumber
// 校验高标签号编码与解码。
func TestBERHighTagNumber(t *testing.T) {
	encoded := appendBERTag(nil, berClassContext, true, 201)
	encoded = appendBERLength(encoded, 0)
	reader := newBERReader(encoded)
	tag, err := reader.peekTag()
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if tag.Class != berClassContext || !tag.Constructed || tag.Number != 201 {
		t.Fatalf("tag = %+v", tag)
	}
	element, err := reader.next()
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if len(element.Value) != 0 {
		t.Fatalf("value length %d", len(element.Value))
	}
}

// TestBERIntegerBoundaries verifies signed integer round trips. | TestBERIntegerBoundaries
// 校验有符号整数往返。
func TestBERIntegerBoundaries(t *testing.T) {
	values := []int64{0, 1, -1, 127, 128, -128, -129, 255, 256, 32767, 32768, -32768, -32769, 1<<31 - 1, 1 << 31, -(1 << 31), 1<<63 - 1, -(1 << 63)}
	for _, value := range values {
		encoder := newBEREncoder(16)
		encoder.integer(value)
		reader := newBERReader(encoder.bytes())
		decoded, err := reader.readInt(false)
		if err != nil {
			t.Fatalf("value %d: %v", value, err)
		}
		if decoded != value {
			t.Fatalf("value %d decoded as %d", value, decoded)
		}
		if err := reader.expectEnd(); err != nil {
			t.Fatalf("value %d trailing: %v", value, err)
		}
	}
}

// TestBERMalformed verifies malformed inputs return errors instead of panicking.
// | TestBERMalformed 校验畸形输入返回错误而不 panic。
func TestBERMalformed(t *testing.T) {
	tests := []struct {
		name  string
		data  []byte
		read  func(*berReader) error
		match error
	}{
		{name: "empty tag", data: nil, read: func(r *berReader) error { _, err := r.next(); return err }, match: ErrProtocolError},
		{name: "truncated length", data: []byte{0x04}, read: func(r *berReader) error { _, err := r.next(); return err }, match: ErrProtocolError},
		{name: "indefinite length", data: []byte{0x30, 0x80}, read: func(r *berReader) error { _, err := r.next(); return err }, match: ErrProtocolError},
		{name: "non-minimal long length", data: []byte{0x04, 0x81, 0x01, 0x00}, read: func(r *berReader) error { _, err := r.next(); return err }, match: ErrProtocolError},
		{name: "length exceeds data", data: []byte{0x04, 0x05, 'a'}, read: func(r *berReader) error { _, err := r.next(); return err }, match: ErrProtocolError},
		{name: "length octets too many", data: []byte{0x04, 0x89, 1, 2, 3, 4, 5, 6, 7, 8, 9}, read: func(r *berReader) error { _, err := r.next(); return err }, match: ErrProtocolError},
		{name: "non-minimal high tag", data: []byte{0xbf, 0x80, 0x01, 0x00}, read: func(r *berReader) error { _, err := r.next(); return err }, match: ErrProtocolError},
		{name: "high tag too short", data: []byte{0xbf, 0x01, 0x00}, read: func(r *berReader) error { _, err := r.next(); return err }, match: ErrProtocolError},
		{name: "empty integer", data: []byte{0x02, 0x00}, read: func(r *berReader) error { _, err := r.readInt(false); return err }, match: ErrProtocolError},
		{name: "integer nine bytes", data: []byte{0x02, 0x09, 1, 2, 3, 4, 5, 6, 7, 8, 9}, read: func(r *berReader) error { _, err := r.readInt(false); return err }, match: ErrProtocolError},
		{name: "boolean two bytes", data: []byte{0x01, 0x02, 0x00, 0x01}, read: func(r *berReader) error { _, err := r.readBoolean(); return err }, match: ErrProtocolError},
		{name: "wrong class", data: []byte{0x24, 0x00}, read: func(r *berReader) error { _, err := r.readOctetString(); return err }, match: ErrProtocolError},
		{name: "trailing bytes", data: []byte{0x04, 0x01, 'a', 0x00}, read: func(r *berReader) error {
			if _, err := r.readOctetString(); err != nil {
				return err
			}
			return r.expectEnd()
		}, match: ErrProtocolError},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.read(newBERReader(test.data))
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, test.match) {
				t.Fatalf("error %v does not match %v", err, test.match)
			}
		})
	}
}

// TestBERDepthLimit verifies constructed nesting is bounded. | TestBERDepthLimit
// 校验构造值嵌套深度受限。
func TestBERDepthLimit(t *testing.T) {
	if _, err := newBERSubReader(nil, maxBERDepth); err != nil {
		t.Fatalf("depth at limit: %v", err)
	}
	if _, err := newBERSubReader(nil, maxBERDepth+1); !errors.Is(err, ErrProtocolError) {
		t.Fatalf("depth above limit: %v", err)
	}
}

// TestBERAppendLength verifies minimal length helpers. | TestBERAppendLength 校验最小长度辅助函数。
func TestBERAppendLength(t *testing.T) {
	tests := []struct {
		length int
		want   []byte
	}{
		{length: 0, want: []byte{0x00}},
		{length: 127, want: []byte{0x7f}},
		{length: 128, want: []byte{0x81, 0x80}},
		{length: 255, want: []byte{0x81, 0xff}},
		{length: 256, want: []byte{0x82, 0x01, 0x00}},
		{length: 65535, want: []byte{0x82, 0xff, 0xff}},
		{length: 65536, want: []byte{0x83, 0x01, 0x00, 0x00}},
		{length: -1, want: nil},
	}
	for _, test := range tests {
		got := appendBERLength(nil, test.length)
		if !bytes.Equal(got, test.want) {
			t.Fatalf("length %d = % x, want % x", test.length, got, test.want)
		}
		// The encoder must append to an existing prefix and return the extended slice.
		// | 编码器必须在已有前缀后追加并返回扩展后的切片。
		prefixed := appendBERLength([]byte{0xAA}, test.length)
		if len(prefixed) != 1+len(test.want) || prefixed[0] != 0xAA || !bytes.Equal(prefixed[1:], test.want) {
			t.Fatalf("prefixed length %d = % x, want prefix 0xAA then % x", test.length, prefixed, test.want)
		}
	}
}

// FuzzBERReader checks that arbitrary BER input never panics. | FuzzBERReader
// 检查任意 BER 输入绝不 panic。
func FuzzBERReader(f *testing.F) {
	seeds := [][]byte{
		{},
		{0x30, 0x00},
		{0x30, 0x03, 0x02, 0x01, 0x01},
		{0x04, 0x81, 0x80, 'x'},
		{0xbf, 0x81, 0x00, 0x00},
		{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff},
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		reader := newBERReader(data)
		for reader.remaining() > 0 {
			element, err := reader.next()
			if err != nil {
				break
			}
			if element.Tag.Constructed {
				_, _ = newBERSubReader(element.Value, 1)
			}
			_, _ = decodeBERInt(element.Value)
		}
		_, _ = decodeLDAPMessage(data)
	})
}
