package kmip

import (
	"bytes"
	"strings"
	"testing"
	"time"

	kmipcore "github.com/shibingli/ydx/auth/keymgmt/kmip"
)

// TestEncodeDecodeRoundTrip verifies that every field and nested attribute tree survives a storage
// round trip. | TestEncodeDecodeRoundTrip 验证每个字段与嵌套属性树都能在存储往返后保留。
func TestEncodeDecodeRoundTrip(t *testing.T) {
	want := testRecord("round-trip")
	data, err := encodeRecord(want)
	if err != nil {
		t.Fatalf("encodeRecord: %v", err)
	}
	got, err := decodeRecord(data)
	if err != nil {
		t.Fatalf("decodeRecord: %v", err)
	}
	requireRecordEqual(t, want, got)
	if got.Object == nil || got.Object.SymmetricKey == nil {
		t.Fatalf("decoded record lost its object: %#v", got.Object)
	}
	material := got.Object.SymmetricKey.KeyBlock.Value.Material.Value
	if !bytes.Equal(material, []byte("0123456789abcdef")) {
		t.Fatalf("decoded key material = %q", material)
	}
}

// TestEncodeDoesNotMutateCaller verifies that encoding normalizes only its own copy.
// | TestEncodeDoesNotMutateCaller 验证编码只规范化自己的副本。
func TestEncodeDoesNotMutateCaller(t *testing.T) {
	record := testRecord("caller-owned")
	originalTime := record.InitialDate
	originalMaterial := append([]byte(nil), record.Object.SymmetricKey.KeyBlock.Value.Material.Value...)
	if _, err := encodeRecord(record); err != nil {
		t.Fatalf("encodeRecord: %v", err)
	}
	if record.InitialDate != originalTime {
		t.Fatalf("encodeRecord changed the caller's time from %v to %v", originalTime, record.InitialDate)
	}
	if !bytes.Equal(record.Object.SymmetricKey.KeyBlock.Value.Material.Value, originalMaterial) {
		t.Fatal("encodeRecord changed the caller's key material")
	}
}

// TestEncodeDecodeNilAndEmptyCollections verifies that nil and empty collections keep their
// distinct JSON representations. | TestEncodeDecodeNilAndEmptyCollections 验证 nil 与空集合保持各自
// 不同的 JSON 表示。
func TestEncodeDecodeNilAndEmptyCollections(t *testing.T) {
	record := testRecord("collections")
	record.Names = nil
	record.Attributes = nil
	record.ObjectGroups = []string{}
	data, err := encodeRecord(record)
	if err != nil {
		t.Fatalf("encodeRecord: %v", err)
	}
	got, err := decodeRecord(data)
	if err != nil {
		t.Fatalf("decodeRecord: %v", err)
	}
	if got.Names != nil {
		t.Fatalf("nil Names decoded as %#v", got.Names)
	}
	if got.Attributes != nil {
		t.Fatalf("nil Attributes decoded as %#v", got.Attributes)
	}
	if got.ObjectGroups == nil || len(got.ObjectGroups) != 0 {
		t.Fatalf("empty ObjectGroups decoded as %#v", got.ObjectGroups)
	}
}

// TestDecodeRejectsCorruptRecords verifies that empty, malformed, and identifier-less values map to
// ErrStoreUnavailable without echoing the stored payload. | TestDecodeRejectsCorruptRecords 验证空值、
// 畸形值与无标识符的值映射为 ErrStoreUnavailable，且不回显已存内容。
func TestDecodeRejectsCorruptRecords(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"empty", ""},
		{"malformed", `{"UniqueIdentifier":"leaky-secret",`},
		{"null", "null"},
		{"empty object", "{}"},
		{"wrong type", "[1,2,3]"},
	}
	for _, tc := range cases {
		_, err := decodeRecord([]byte(tc.data))
		requireErrorIs(t, err, ErrStoreUnavailable, tc.name)
		if strings.Contains(err.Error(), "leaky-secret") {
			t.Fatalf("%s leaked stored data in %q", tc.name, err.Error())
		}
	}
}

// TestDecodeReturnsIndependentValues verifies that two decodes never share slices or trees.
// | TestDecodeReturnsIndependentValues 验证两次解码从不共享切片或树。
func TestDecodeReturnsIndependentValues(t *testing.T) {
	data, err := encodeRecord(testRecord("independent"))
	if err != nil {
		t.Fatalf("encodeRecord: %v", err)
	}
	first, err := decodeRecord(data)
	if err != nil {
		t.Fatalf("decodeRecord first: %v", err)
	}
	second, err := decodeRecord(data)
	if err != nil {
		t.Fatalf("decodeRecord second: %v", err)
	}
	want := testRecord("independent")
	requireRecordEqual(t, want, second)
	first.Names[0].Value = "mutated"
	first.ObjectGroups[0] = "mutated"
	first.Attributes[0].Value.Value[0] ^= 0xff
	first.Object.SymmetricKey.KeyBlock.Value.Material.Value[0] ^= 0xff
	requireRecordEqual(t, want, second)
	third, err := decodeRecord(data)
	if err != nil {
		t.Fatalf("decodeRecord third: %v", err)
	}
	requireRecordEqual(t, want, third)
}

// TestNormalizeRecordTimes verifies UTC normalization, zero preservation, instant preservation and
// nanosecond preservation for every date field. | TestNormalizeRecordTimes 验证每个日期字段的 UTC
// 规范化、零值保留、时刻保留与纳秒保留。
func TestNormalizeRecordTimes(t *testing.T) {
	zone := time.FixedZone("CST", 8*60*60)
	base := time.Date(2026, time.November, 8, 10, 30, 45, 123456789, zone)
	record := kmipcore.ObjectRecord{
		InitialDate:              base,
		OriginalCreationDate:     base.Add(time.Minute),
		ActivationDate:           base.Add(2 * time.Minute),
		DeactivationDate:         time.Time{},
		CompromiseDate:           base.Add(3 * time.Minute),
		CompromiseOccurrenceDate: base.Add(4 * time.Minute),
		DestroyDate:              base.Add(5 * time.Minute),
		ArchiveDate:              base.Add(6 * time.Minute),
		LastChangeDate:           base.Add(7 * time.Minute),
	}
	normalizeRecordTimes(&record)
	times := []time.Time{
		record.InitialDate,
		record.OriginalCreationDate,
		record.ActivationDate,
		record.CompromiseDate,
		record.CompromiseOccurrenceDate,
		record.DestroyDate,
		record.ArchiveDate,
		record.LastChangeDate,
	}
	for i, value := range times {
		if value.Location() != time.UTC {
			t.Fatalf("time %d location = %v, want UTC", i, value.Location())
		}
	}
	if !record.InitialDate.Equal(base) {
		t.Fatalf("InitialDate instant changed: got %v want %v", record.InitialDate, base)
	}
	if record.InitialDate.Nanosecond() != base.Nanosecond() {
		t.Fatalf("InitialDate nanoseconds changed: got %d want %d", record.InitialDate.Nanosecond(), base.Nanosecond())
	}
	if record.DeactivationDate != (time.Time{}) {
		t.Fatalf("zero DeactivationDate changed to %v", record.DeactivationDate)
	}
}

// TestNormalizeRecordTimesNil verifies that a nil receiver is ignored. | TestNormalizeRecordTimesNil
// 验证 nil 接收者被忽略。
func TestNormalizeRecordTimesNil(t *testing.T) {
	normalizeRecordTimes(nil)
}

// TestDecodeTimesAreUTC verifies that stored JSON always decodes to UTC times and zero dates.
// | TestDecodeTimesAreUTC 验证已存 JSON 总是解码为 UTC 时间与零日期。
func TestDecodeTimesAreUTC(t *testing.T) {
	record := testRecord("utc-json")
	record.DeactivationDate = time.Time{}
	data, err := encodeRecord(record)
	if err != nil {
		t.Fatalf("encodeRecord: %v", err)
	}
	if bytes.Contains(data, []byte("+08:00")) {
		t.Fatalf("encoded record kept an offset time zone: %s", data)
	}
	got, err := decodeRecord(data)
	if err != nil {
		t.Fatalf("decodeRecord: %v", err)
	}
	if got.InitialDate.Location() != time.UTC {
		t.Fatalf("InitialDate location = %v, want UTC", got.InitialDate.Location())
	}
	if !got.InitialDate.Equal(record.InitialDate) {
		t.Fatalf("InitialDate instant changed: got %v want %v", got.InitialDate, record.InitialDate)
	}
	if !got.DeactivationDate.IsZero() {
		t.Fatalf("zero DeactivationDate decoded as %v", got.DeactivationDate)
	}
}
