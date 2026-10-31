package waf

import "testing"

// TestTXHashCollision verifies that distinct keys sharing a hash retain separate values. |
// TestTXHashCollision 验证共享同一哈希的不同键保持独立取值。
func TestTXHashCollision(t *testing.T) {
	tx := &transaction{}
	const hash = uint64(42)
	tx.txStore(hash, "alpha", txValue{first: "a", single: true})
	tx.txStore(hash, "beta", txValue{first: "b", single: true})
	if value, ok := tx.txLookup(hash, "alpha"); !ok || value.first != "a" {
		t.Fatalf("alpha = %q, %v", value.first, ok)
	}
	if value, ok := tx.txLookup(hash, "beta"); !ok || value.first != "b" {
		t.Fatalf("beta = %q, %v", value.first, ok)
	}
	if entries := tx.txEntries(); len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	tx.txDelete(hash, "alpha")
	if _, ok := tx.txLookup(hash, "alpha"); ok {
		t.Fatal("alpha survived deletion")
	}
	if value, ok := tx.txLookup(hash, "beta"); !ok || value.first != "b" {
		t.Fatalf("beta after delete = %q, %v", value.first, ok)
	}
	tx.txStore(hash, "alpha", txValue{first: "a2", single: true})
	if entries := tx.txEntries(); len(entries) != 2 {
		t.Fatalf("entries after reinsert = %d, want 2", len(entries))
	}
}

// TestTXCollectionSorted verifies TX collection iteration remains name-sorted. |
// TestTXCollectionSorted 验证 TX 集合遍历仍按名称排序。
func TestTXCollectionSorted(t *testing.T) {
	tx := &transaction{}
	tx.setTXValue("z", "1", 0)
	tx.setTXValue("a", "2", 0)
	values := tx.txCollection()
	if len(values) != 2 || values[0].Key != "a" || values[1].Key != "z" {
		t.Fatalf("values = %+v", values)
	}
}
