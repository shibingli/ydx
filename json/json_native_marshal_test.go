//go:build !jsonx_std

package json

import (
	stdjson "encoding/json"
	"math"
	"reflect"
	"testing"
	"time"
)

// marshalFastFixture covers every field kind the pointer-based fast encoder writes inline. |
// marshalFastFixture 覆盖基于指针的快速编码器内联写入的每种字段类型。
type marshalFastFixture struct {
	Name   string    `json:"name"`
	Note   string    `json:"note"`
	OK     bool      `json:"ok"`
	I      int       `json:"i"`
	I8     int8      `json:"i8"`
	I16    int16     `json:"i16"`
	I32    int32     `json:"i32"`
	I64    int64     `json:"i64"`
	U      uint      `json:"u"`
	U8     uint8     `json:"u8"`
	U16    uint16    `json:"u16"`
	U32    uint32    `json:"u32"`
	U64    uint64    `json:"u64"`
	UP     uintptr   `json:"up"`
	F32    float32   `json:"f32"`
	F64    float64   `json:"f64"`
	Tags   []string  `json:"tags"`
	When   time.Time `json:"when"`
	Hidden string    `json:"-"`
}

// marshalPtrReceiver implements Marshaler only through a pointer receiver, so a non-addressable
// value must fall back to normal struct encoding. | marshalPtrReceiver 仅在指针接收者上实现
// Marshaler，因此不可寻址的值必须回退到普通结构体编码。
type marshalPtrReceiver struct {
	Value string `json:"value"`
}

func (m *marshalPtrReceiver) MarshalJSON() ([]byte, error) {
	return []byte(`"pointer-marshaler"`), nil
}

// marshalValueReceiver implements Marshaler on the value receiver. | marshalValueReceiver 在值接收者上
// 实现 Marshaler。
type marshalValueReceiver struct {
	Value string `json:"value"`
}

func (m marshalValueReceiver) MarshalJSON() ([]byte, error) {
	return []byte(`"value-marshaler"`), nil
}

// TestMarshalNonAddressableStructFastPath verifies that top-level struct values, which the
// pointer-based fast encoder can read directly from the interface data word, keep byte-for-byte
// compatibility with the reflective encoder and encoding/json. |
// TestMarshalNonAddressableStructFastPath 验证顶层结构体值（基于指针的快速编码器可直接从接口数据字
// 读取）与反射编码器及 encoding/json 逐字节一致。
func TestMarshalNonAddressableStructFastPath(t *testing.T) {
	when := time.Date(2026, 10, 22, 8, 9, 10, 123456789, time.UTC)
	value := marshalFastFixture{
		Name: "alpha",
		Note: `<tag> & "quoted" \ tail`,
		OK:   true,
		I:    -12345,
		I8:   -8,
		I16:  -1600,
		I32:  -320000,
		I64:  -6400000000,
		U:    12345,
		U8:   8,
		U16:  1600,
		U32:  320000,
		U64:  6400000000,
		UP:   42,
		F32:  1.5,
		F64:  -2.25,
		Tags: []string{"one", "two", "three"},
		When: when,
	}
	info := fastStructFor(reflect.TypeOf(value))
	if info == nil {
		t.Fatal("fast struct encoder is unavailable for the fixture | 测试载荷没有可用的快速结构体编码器")
	}
	if info.encBuf == nil {
		t.Fatal("fast struct buffer encoder is unavailable for the fixture | 测试载荷没有可用的快速结构体缓冲编码器")
	}

	got, err := Marshal(value)
	if err != nil {
		t.Fatalf("Marshal failed | Marshal 失败: %v", err)
	}
	want, err := stdjson.Marshal(value)
	if err != nil {
		t.Fatalf("encoding/json Marshal failed | encoding/json Marshal 失败: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("non-addressable output mismatch\n got: %s\nwant: %s", got, want)
	}

	// The reflective encoder over the same non-addressable value is the behavior the fast path
	// replaced; both must stay identical. | 反射编码器处理同一个不可寻址值的行为就是快速路径所替代的
	// 行为，两者必须保持一致。
	e := getEncoder(true)
	if err := encoderFor(reflect.TypeOf(value))(e, reflect.ValueOf(value)); err != nil {
		t.Fatalf("reflective encoder failed | 反射编码器失败: %v", err)
	}
	reflective := string(e.buf)
	putEncoder(e)
	if string(got) != reflective {
		t.Fatalf("fast path differs from reflective encoder\n fast: %s\n  ref: %s", got, reflective)
	}

	// A pointer to the same value is addressable and must produce identical bytes. | 同一值的指针可寻址，
	// 必须产生相同字节。
	fromPtr, err := Marshal(&value)
	if err != nil {
		t.Fatalf("Marshal pointer failed | Marshal 指针失败: %v", err)
	}
	if string(fromPtr) != string(got) {
		t.Fatalf("pointer output mismatch\n ptr: %s\n got: %s", fromPtr, got)
	}
}

// TestMarshalFloatFastPaths compares the short-float shortcuts, including negative one-decimal
// values, against encoding/json. | TestMarshalFloatFastPaths 将短浮点快速路径（含负的一位小数）与
// encoding/json 对比。
func TestMarshalFloatFastPaths(t *testing.T) {
	float64s := []float64{
		0, math.Copysign(0, -1), 1.5, -1.5, 0.5, -0.5, 2.5, -2.5, 0.1, -0.1,
		1.25, -1.25, 2.25, -2.25, 1e-7, -1e-7, 1e15, -1e15, 1e20,
		123456789.5, -123456789.5, math.MaxFloat64, math.SmallestNonzeroFloat64,
	}
	for _, f := range float64s {
		got, err := Marshal(f)
		if err != nil {
			t.Fatalf("Marshal(%v) failed | Marshal(%v) 失败: %v", f, f, err)
		}
		want, err := stdjson.Marshal(f)
		if err != nil {
			t.Fatalf("encoding/json Marshal(%v) failed | encoding/json Marshal(%v) 失败: %v", f, f, err)
		}
		if string(got) != string(want) {
			t.Fatalf("float64 %v mismatch: got %s, want %s", f, got, want)
		}
	}
	float32s := []float32{0, float32(math.Copysign(0, -1)), 1.5, -1.5, 0.1, -0.1, 3.4e38, 1e-7}
	for _, f := range float32s {
		got, err := Marshal(f)
		if err != nil {
			t.Fatalf("Marshal(%v) failed | Marshal(%v) 失败: %v", f, f, err)
		}
		want, err := stdjson.Marshal(f)
		if err != nil {
			t.Fatalf("encoding/json Marshal(%v) failed | encoding/json Marshal(%v) 失败: %v", f, f, err)
		}
		if string(got) != string(want) {
			t.Fatalf("float32 %v mismatch: got %s, want %s", f, got, want)
		}
	}
}

// TestMarshalNonAddressableMarshalerSemantics pins encoding/json's addressability rule for custom
// marshalers: a value receiver always runs, a pointer receiver only runs for addressable values. |
// TestMarshalNonAddressableMarshalerSemantics 固定 encoding/json 对自定义编码器的可寻址性规则：值接收者
// 总是执行，指针接收者仅对可寻址值执行。
func TestMarshalNonAddressableMarshalerSemantics(t *testing.T) {
	cases := []struct {
		name string
		v    any
		ptr  any
	}{
		{name: "value-receiver", v: marshalValueReceiver{Value: "x"}, ptr: &marshalValueReceiver{Value: "x"}},
		{name: "pointer-receiver", v: marshalPtrReceiver{Value: "x"}, ptr: &marshalPtrReceiver{Value: "x"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, v := range []any{c.v, c.ptr} {
				got, err := Marshal(v)
				if err != nil {
					t.Fatalf("Marshal failed | Marshal 失败: %v", err)
				}
				want, err := stdjson.Marshal(v)
				if err != nil {
					t.Fatalf("encoding/json Marshal failed | encoding/json Marshal 失败: %v", err)
				}
				if string(got) != string(want) {
					t.Fatalf("output mismatch for %T\n got: %s\nwant: %s", v, got, want)
				}
			}
		})
	}
}

// TestMarshalNonAddressableEmptyAndOmitEmpty covers zero structs and structs whose fields force
// the reflective fallback. | TestMarshalNonAddressableEmptyAndOmitEmpty 覆盖零值结构体与因字段而回退
// 反射路径的结构体。
func TestMarshalNonAddressableEmptyAndOmitEmpty(t *testing.T) {
	type omit struct {
		Name string   `json:"name"`
		Tags []string `json:"tags,omitempty"`
		Any  any      `json:"any,omitempty"`
	}
	values := []any{
		marshalFastFixture{},
		omit{},
		omit{Name: "n", Tags: []string{"a"}, Any: map[string]int{"k": 1}},
	}
	for _, v := range values {
		got, err := Marshal(v)
		if err != nil {
			t.Fatalf("Marshal(%T) failed | Marshal(%T) 失败: %v", v, v, err)
		}
		want, err := stdjson.Marshal(v)
		if err != nil {
			t.Fatalf("encoding/json Marshal(%T) failed | encoding/json Marshal(%T) 失败: %v", v, v, err)
		}
		if string(got) != string(want) {
			t.Fatalf("output mismatch for %T\n got: %s\nwant: %s", v, got, want)
		}
	}
}
