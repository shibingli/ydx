package kms

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func testKey(id, alias string) *Key {
	return &Key{
		ID:         id,
		Alias:      alias,
		Type:       KeyTypeAES,
		Algorithm:  "AES-256-GCM",
		Bits:       256,
		Version:    1,
		State:      StateActive,
		UsageMask:  MaskEncrypt | MaskDecrypt,
		CreatedAt:  time.Unix(1700000000, 0).UTC(),
		Material:   []byte{1, 2, 3, 4},
		Exportable: true,
	}
}

func TestMemoryStoreCreateGetClone(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	key := testKey("k1", "alias-1")
	if err := store.CreateKey(ctx, key); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	got, err := store.GetKey(ctx, "k1")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if got.Revision != 1 {
		t.Fatalf("revision = %d, want 1", got.Revision)
	}
	got.Material[0] = 9
	again, err := store.GetKey(ctx, "k1")
	if err != nil {
		t.Fatalf("GetKey again: %v", err)
	}
	if again.Material[0] != 1 {
		t.Fatal("store returned shared material")
	}
	if err := store.CreateKey(ctx, testKey("k1", "other")); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("duplicate CreateKey err = %v, want ErrKeyExists", err)
	}
	if err := store.CreateKey(ctx, testKey("k2", "alias-1")); !errors.Is(err, ErrAliasExists) {
		t.Fatalf("duplicate alias err = %v, want ErrAliasExists", err)
	}
}

func TestMemoryStoreAliasLifecycle(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	if err := store.CreateKey(ctx, testKey("k1", "old")); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateKey(ctx, testKey("k2", "")); err != nil {
		t.Fatal(err)
	}
	id, err := store.ResolveAlias(ctx, "old")
	if err != nil || id != "k1" {
		t.Fatalf("ResolveAlias = %q, %v", id, err)
	}
	if err := store.SetAlias(ctx, "new", "k1"); err != nil {
		t.Fatalf("SetAlias: %v", err)
	}
	if err := store.SetAlias(ctx, "old", "k2"); !errors.Is(err, ErrAliasExists) {
		t.Fatalf("conflicting SetAlias err = %v", err)
	}
	if err := store.DeleteAlias(ctx, "missing"); !errors.Is(err, ErrAliasNotFound) {
		t.Fatalf("DeleteAlias err = %v", err)
	}
	if err := store.DeleteKey(ctx, "k1"); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
	if _, err := store.ResolveAlias(ctx, "new"); !errors.Is(err, ErrAliasNotFound) {
		t.Fatalf("alias survived deletion: %v", err)
	}
}

func TestMemoryStoreOptimisticConcurrency(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	if err := store.CreateKey(ctx, testKey("k1", "")); err != nil {
		t.Fatal(err)
	}
	first, _ := store.GetKey(ctx, "k1")
	second, _ := store.GetKey(ctx, "k1")
	first.Metadata = map[string]string{"owner": "first"}
	if err := store.UpdateKey(ctx, first); err != nil {
		t.Fatalf("first UpdateKey: %v", err)
	}
	stored, _ := store.GetKey(ctx, "k1")
	if stored.Revision != 2 {
		t.Fatalf("revision = %d, want 2", stored.Revision)
	}
	second.Metadata = map[string]string{"owner": "second"}
	if err := store.UpdateKey(ctx, second); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale UpdateKey err = %v, want ErrConflict", err)
	}
	if err := store.UpdateKey(ctx, testKey("missing", "")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing UpdateKey err = %v", err)
	}
}

func TestMemoryStoreVersionsAndAudit(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	if err := store.CreateKey(ctx, testKey("k1", "")); err != nil {
		t.Fatal(err)
	}
	version := &KeyVersion{Version: 2, State: StateActive, Material: []byte{5}, CreatedAt: time.Now().UTC()}
	if err := store.SaveVersion(ctx, "k1", version); err != nil {
		t.Fatalf("SaveVersion: %v", err)
	}
	if err := store.SaveVersion(ctx, "k1", version); !errors.Is(err, ErrVersionExists) {
		t.Fatalf("duplicate SaveVersion err = %v, want ErrVersionExists", err)
	}
	versions, err := store.ListVersions(ctx, "k1")
	if err != nil || len(versions) != 1 {
		t.Fatalf("ListVersions = %d, %v", len(versions), err)
	}
	if _, err := store.GetVersion(ctx, "k1", 9); !errors.Is(err, ErrVersionNotFound) {
		t.Fatalf("GetVersion err = %v, want ErrVersionNotFound", err)
	}
	if err := store.AppendAudit(ctx, &AuditEvent{Operation: OperationKeyCreate, KeyID: "k1", Outcome: OutcomeSuccess}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	if err := store.AppendAudit(ctx, &AuditEvent{Operation: OperationEncrypt, KeyID: "k1", Outcome: OutcomeSuccess}); err != nil {
		t.Fatal(err)
	}
	events, err := store.ListAudit(ctx, AuditFilter{Operation: OperationEncrypt})
	if err != nil || len(events) != 1 || events[0].ID == "" || events[0].At.IsZero() {
		t.Fatalf("ListAudit = %+v, %v", events, err)
	}
	if err := store.AppendAudit(ctx, nil); err == nil {
		t.Fatal("AppendAudit(nil) succeeded")
	}
}

func TestKeyStoreMaterialSafety(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	private, public, _, _, err := generateMaterial(KeyTypeECDSA, 256)
	if err != nil {
		t.Fatalf("generateMaterial: %v", err)
	}
	key := &Key{
		ID:             "ks-key",
		Alias:          "ks-alias",
		Type:           KeyTypeECDSA,
		Version:        1,
		State:          StateActive,
		UsageMask:      MaskSign | MaskVerify,
		CreatedAt:      time.Unix(1700000000, 0).UTC(),
		Material:       private,
		PublicMaterial: public,
		Exportable:     true,
		Versions: []*KeyVersion{{
			Version:        1,
			State:          StateActive,
			Material:       private,
			PublicMaterial: public,
			CreatedAt:      time.Unix(1700000000, 0).UTC(),
		}},
	}
	if err := store.CreateKey(ctx, key); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	keys := NewKeyStore(store, ExportPolicy{})
	view, err := keys.Get(ctx, "ks-key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if view.Material != nil || len(view.Versions) != 1 || view.Versions[0].Material != nil {
		t.Fatal("KeyStore.Get returned private material")
	}
	if len(view.PublicMaterial) == 0 || len(view.Versions[0].PublicMaterial) == 0 {
		t.Fatal("KeyStore.Get dropped public material")
	}
	resolved, err := keys.Resolve(ctx, "ks-alias")
	if err != nil || resolved.ID != key.ID || resolved.Material != nil {
		t.Fatalf("Resolve = %+v, %v", resolved, err)
	}
	listed, err := keys.List(ctx, KeyFilter{})
	if err != nil || len(listed) != 1 || listed[0].Material != nil || len(listed[0].PublicMaterial) != 0 {
		t.Fatalf("List = %+v, %v", listed, err)
	}
	if _, err := keys.Export(ctx, key.ID, ExportRequest{Format: ExportFormatRaw, Private: true}); !errors.Is(err, ErrExportDenied) {
		t.Fatalf("private Export err = %v, want ErrExportDenied", err)
	}
	publicExport, err := keys.Export(ctx, key.ID, ExportRequest{Format: ExportFormatRaw})
	if err != nil || !bytes.Equal(publicExport.PublicMaterial, public) {
		t.Fatalf("public Export = %+v, %v", publicExport, err)
	}
	open := NewKeyStore(store, ExportPolicy{AllowPrivate: true})
	privateExport, err := open.Export(ctx, key.ID, ExportRequest{Format: ExportFormatRaw, Private: true})
	if err != nil || !bytes.Equal(privateExport.Material, private) {
		t.Fatalf("private Export = %+v, %v", privateExport, err)
	}
	if _, err := NewKeyStore(nil, ExportPolicy{}).Get(ctx, key.ID); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("nil KeyStore err = %v, want ErrStoreUnavailable", err)
	}
}

func TestNonceCache(t *testing.T) {
	cache := newNonceCache(2)
	first := [gcmNonceSize]byte{1}
	second := [gcmNonceSize]byte{2}
	third := [gcmNonceSize]byte{3}
	if !cache.add(first) || !cache.add(second) {
		t.Fatal("fresh nonces were rejected")
	}
	if cache.add(first) {
		t.Fatal("duplicate nonce was accepted")
	}
	if !cache.add(third) {
		t.Fatal("third nonce was rejected")
	}
	if !cache.add(first) {
		t.Fatal("evicted nonce was not reusable")
	}
	service := &Service{}
	nonce := make([]byte, gcmNonceSize)
	for i := range nonce {
		nonce[i] = 0x5a
	}
	if !service.rememberNonce("key", 1, nonce) {
		t.Fatal("first rememberNonce was rejected")
	}
	if service.rememberNonce("key", 1, nonce) {
		t.Fatal("duplicate rememberNonce was accepted")
	}
	if !service.rememberNonce("key", 2, nonce) {
		t.Fatal("same nonce for another version was rejected")
	}
	seen := make(map[string]bool)
	for i := 0; i < 64; i++ {
		generated, err := service.newNonce("key", 1)
		if err != nil {
			t.Fatalf("newNonce: %v", err)
		}
		if seen[string(generated)] {
			t.Fatal("newNonce repeated a nonce")
		}
		seen[string(generated)] = true
	}
}

func TestMemoryStoreListFilters(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	one := testKey("a1", "alpha")
	one.Tags = []string{"prod"}
	one.Metadata = map[string]string{"team": "crypto"}
	two := testKey("b2", "beta")
	two.State = StateDeactivated
	two.Type = KeyTypeSM4
	two.CreatedAt = one.CreatedAt.Add(time.Second)
	if err := store.CreateKey(ctx, one); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateKey(ctx, two); err != nil {
		t.Fatal(err)
	}
	matching, err := store.ListKeys(ctx, KeyFilter{Tag: "prod", Query: "ALPHA"})
	if err != nil || len(matching) != 1 || matching[0].ID != "a1" {
		t.Fatalf("filtered ListKeys = %+v, %v", matching, err)
	}
	limited, err := store.ListKeys(ctx, KeyFilter{Limit: 1})
	if err != nil || len(limited) != 1 || limited[0].ID != "a1" {
		t.Fatalf("limited ListKeys = %+v, %v", limited, err)
	}
	byState, err := store.ListKeys(ctx, KeyFilter{State: StateDeactivated, Type: KeyTypeSM4})
	if err != nil || len(byState) != 1 || byState[0].ID != "b2" {
		t.Fatalf("state ListKeys = %+v, %v", byState, err)
	}
}
