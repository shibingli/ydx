package ldap

import (
	"bytes"
	"testing"
)

// TestSortControlReversePrimitive verifies the RFC 2891 reverseOrder field is
// encoded as the implicit primitive [1] BOOLEAN. | TestSortControlReversePrimitive
// 校验 RFC 2891 reverseOrder 字段编码为隐式原始 [1] BOOLEAN。
func TestSortControlReversePrimitive(t *testing.T) {
	control := SortControl(
		SortKey{Attribute: "cn"},
		SortKey{Attribute: "uid", OrderingRule: "1.2.3", Reverse: true},
	)
	if control.Type != OIDSortRequest {
		t.Fatalf("control type = %q", control.Type)
	}
	outer := newBERReader(control.Value)
	sequence, err := outer.expectSequence()
	if err != nil {
		t.Fatalf("sort key list: %v", err)
	}
	keys, err := outer.subReader(sequence)
	if err != nil {
		t.Fatalf("sort key reader: %v", err)
	}
	if err := outer.expectEnd(); err != nil {
		t.Fatalf("control trailing: %v", err)
	}
	first, err := keys.expectSequence()
	if err != nil {
		t.Fatalf("first sort key: %v", err)
	}
	firstKey, err := keys.subReader(first)
	if err != nil {
		t.Fatalf("first sort key reader: %v", err)
	}
	if attribute, err := firstKey.readString(); err != nil || attribute != "cn" {
		t.Fatalf("first attribute = %q, %v", attribute, err)
	}
	if err := firstKey.expectEnd(); err != nil {
		t.Fatalf("first sort key trailing: %v", err)
	}
	second, err := keys.expectSequence()
	if err != nil {
		t.Fatalf("second sort key: %v", err)
	}
	secondKey, err := keys.subReader(second)
	if err != nil {
		t.Fatalf("second sort key reader: %v", err)
	}
	if attribute, err := secondKey.readString(); err != nil || attribute != "uid" {
		t.Fatalf("second attribute = %q, %v", attribute, err)
	}
	rule, err := secondKey.expect(berClassContext, false, 0)
	if err != nil {
		t.Fatalf("ordering rule component: %v", err)
	}
	if string(rule.Value) != "1.2.3" {
		t.Fatalf("ordering rule = %q", rule.Value)
	}
	reverse, err := secondKey.expect(berClassContext, false, 1)
	if err != nil {
		t.Fatalf("reverseOrder component: %v", err)
	}
	if !bytes.Equal(reverse.Value, []byte{0xff}) {
		t.Fatalf("reverseOrder value = %x, want ff", reverse.Value)
	}
	if err := secondKey.expectEnd(); err != nil {
		t.Fatalf("second sort key trailing: %v", err)
	}
	if err := keys.expectEnd(); err != nil {
		t.Fatalf("sort key list trailing: %v", err)
	}
}

// TestSortControlAscendingOmitsReverse verifies ascending keys omit the
// reverseOrder field. | TestSortControlAscendingOmitsReverse 校验升序键省略
// reverseOrder 字段。
func TestSortControlAscendingOmitsReverse(t *testing.T) {
	control := SortControl(SortKey{Attribute: "cn"})
	outer := newBERReader(control.Value)
	sequence, err := outer.expectSequence()
	if err != nil {
		t.Fatalf("sort key list: %v", err)
	}
	keys, err := outer.subReader(sequence)
	if err != nil {
		t.Fatalf("sort key reader: %v", err)
	}
	key, err := keys.expectSequence()
	if err != nil {
		t.Fatalf("sort key: %v", err)
	}
	keyReader, err := keys.subReader(key)
	if err != nil {
		t.Fatalf("sort key reader: %v", err)
	}
	if attribute, err := keyReader.readString(); err != nil || attribute != "cn" {
		t.Fatalf("attribute = %q, %v", attribute, err)
	}
	if keyReader.remaining() != 0 {
		t.Fatalf("ascending key has %d extra bytes", keyReader.remaining())
	}
}
