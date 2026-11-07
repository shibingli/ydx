package webauthn

import (
	"bytes"
	"errors"
	"math"
	"testing"
)

func TestCBORCanonicalMapRoundTrip(t *testing.T) {
	value := NewMap(
		Pair{Key: NewText("b"), Value: NewUint(2)},
		Pair{Key: NewText("a"), Value: NewArray(NewBool(true), NewNull(), NewFloat(1.5), NewInt(-5))},
	)
	encoded, err := Encode(value)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Canonical order sorts "a" before "b". | 规范顺序把 "a" 排在 "b" 之前。
	wantPrefix := []byte{0xa2, 0x61, 'a'}
	if !bytes.HasPrefix(encoded, wantPrefix) {
		t.Fatalf("encoded map is not sorted: %x", encoded)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if decoded.Kind != KindMap || len(decoded.Pairs) != 2 {
		t.Fatalf("decoded map = %#v", decoded)
	}
	a, ok := decoded.MapGetText("a")
	if !ok || a.Kind != KindArray || len(a.Array) != 4 {
		t.Fatalf("decoded a = %#v", a)
	}
	if b, ok := decoded.MapGetText("b"); !ok {
		t.Fatal("decoded map lacks b")
	} else if n, ok := b.AsUint64(); !ok || n != 2 {
		t.Fatalf("b = %#v", b)
	}
	reencoded, err := Encode(decoded)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if !bytes.Equal(encoded, reencoded) {
		t.Fatalf("round trip differs:\n%x\n%x", encoded, reencoded)
	}
}

func TestCBORIntegerAccessors(t *testing.T) {
	if got, ok := NewInt(-7).AsInt64(); !ok || got != -7 {
		t.Fatalf("NewInt(-7) = %d, %v", got, ok)
	}
	if _, ok := NewInt(-7).AsUint64(); ok {
		t.Fatal("negative integer reported as unsigned")
	}
	if got, ok := NewUint(math.MaxUint64).AsUint64(); !ok || got != math.MaxUint64 {
		t.Fatalf("MaxUint64 = %d, %v", got, ok)
	}
	if _, ok := NewUint(math.MaxUint64).AsInt64(); ok {
		t.Fatal("MaxUint64 reported as int64")
	}
}

func TestCBORIndefiniteLengths(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
		check func(t *testing.T, v *Value)
	}{
		{
			name:  "bytes",
			input: []byte{0x5f, 0x41, 0x01, 0x41, 0x02, 0xff},
			check: func(t *testing.T, v *Value) {
				b, ok := v.AsBytes()
				if !ok || !bytes.Equal(b, []byte{1, 2}) {
					t.Fatalf("bytes = %x, %v", b, ok)
				}
			},
		},
		{
			name:  "text",
			input: []byte{0x7f, 0x61, 'a', 0x61, 'b', 0xff},
			check: func(t *testing.T, v *Value) {
				if s, ok := v.AsText(); !ok || s != "ab" {
					t.Fatalf("text = %q, %v", s, ok)
				}
			},
		},
		{
			name:  "array",
			input: []byte{0x9f, 0x01, 0x02, 0xff},
			check: func(t *testing.T, v *Value) {
				if v.Kind != KindArray || len(v.Array) != 2 {
					t.Fatalf("array = %#v", v)
				}
			},
		},
		{
			name:  "map",
			input: []byte{0xbf, 0x61, 'a', 0x01, 0xff},
			check: func(t *testing.T, v *Value) {
				if v.Kind != KindMap || len(v.Pairs) != 1 {
					t.Fatalf("map = %#v", v)
				}
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			value, err := Decode(test.input)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			test.check(t, value)
		})
	}
}

func TestCBORFloats(t *testing.T) {
	for _, want := range []float64{0, 1.5, -2.25, 65504, 1e300} {
		value := NewFloat(want)
		encoded, err := Encode(value)
		if err != nil {
			t.Fatalf("Encode(%v): %v", want, err)
		}
		decoded, err := Decode(encoded)
		if err != nil {
			t.Fatalf("Decode(%v): %v", want, err)
		}
		if decoded.Float != want {
			t.Fatalf("float round trip = %v, want %v", decoded.Float, want)
		}
	}
	encoded, err := Encode(NewFloat(math.NaN()))
	if err != nil {
		t.Fatalf("encode NaN: %v", err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode NaN: %v", err)
	}
	if !math.IsNaN(decoded.Float) {
		t.Fatalf("NaN round trip = %v", decoded.Float)
	}
}

func TestCBORMalformedInputNeverPanics(t *testing.T) {
	inputs := [][]byte{
		nil,
		{},
		{0x1b},
		{0x5a, 0x00, 0x00, 0x00, 0x01},
		{0x82, 0x01},
		{0xa1, 0x61, 'a'},
		{0xa1, 0x61, 'a', 0x01, 0x61, 'a', 0x02},
		{0x9f, 0x01},
		{0x7f, 0x41, 0xff, 0xff},
		{0x1c},
		{0xff},
		{0xf8, 0x01},
		{0x81, 0x18},
		{0xbf, 0x61, 'a', 0xff},
		{0x61, 0xff},
		{0x5f, 0x61, 'a', 0xff},
	}
	for i, input := range inputs {
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("input %d panicked: %v", i, recovered)
				}
			}()
			if _, err := Decode(input); err == nil {
				t.Fatalf("input %d decoded without an error", i)
			}
		}()
	}
}

func TestCBORLimits(t *testing.T) {
	nested := []byte{0x81, 0x81, 0x81, 0x01}
	if _, err := Decode(nested, DecodeOptions{MaxDepth: 2}); !errors.Is(err, ErrCBORLimit) {
		t.Fatalf("depth limit error = %v, want ErrCBORLimit", err)
	}
	if _, err := Decode(nested, DecodeOptions{MaxBytes: 2}); !errors.Is(err, ErrCBORLimit) {
		t.Fatalf("size limit error = %v, want ErrCBORLimit", err)
	}
}

func TestCBORTrailingBytes(t *testing.T) {
	if _, err := Decode([]byte{0x01, 0x02}); !errors.Is(err, ErrInvalidCBOR) {
		t.Fatalf("trailing bytes error = %v, want ErrInvalidCBOR", err)
	}
}

func TestCBOREncodeRejectsInvalidValues(t *testing.T) {
	if _, err := Encode(nil); !errors.Is(err, ErrInvalidCBOR) {
		t.Fatalf("nil value error = %v", err)
	}
	if _, err := Encode(NewText("\xff")); !errors.Is(err, ErrInvalidCBOR) {
		t.Fatalf("invalid UTF-8 error = %v", err)
	}
	duplicate := NewMap(
		Pair{Key: NewText("a"), Value: NewUint(1)},
		Pair{Key: NewText("a"), Value: NewUint(2)},
	)
	if _, err := Encode(duplicate); !errors.Is(err, ErrInvalidCBOR) {
		t.Fatalf("duplicate key error = %v", err)
	}
	if _, err := Encode(&Value{Kind: Kind(200)}); !errors.Is(err, ErrInvalidCBOR) {
		t.Fatalf("unknown kind error = %v", err)
	}
	deep := NewArray()
	current := deep
	for i := 0; i < maxCBOREncodeDepth+1; i++ {
		next := NewArray()
		current.Array = []*Value{next}
		current = next
	}
	if _, err := Encode(deep); !errors.Is(err, ErrCBORLimit) {
		t.Fatalf("encode depth error = %v, want ErrCBORLimit", err)
	}
}

func TestCBORTags(t *testing.T) {
	encoded, err := Encode(NewTag(24, NewBytes([]byte{1, 2, 3})))
	if err != nil {
		t.Fatalf("Encode tag: %v", err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode tag: %v", err)
	}
	if decoded.Kind != KindTag || decoded.Tag != 24 || decoded.Inner == nil {
		t.Fatalf("tag = %#v", decoded)
	}
}
