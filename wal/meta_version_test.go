package wal

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestMetaV1UpgradesToV2 verifies that a v1 META slot is accepted, rewritten
// as v2 on the next persist, and keeps the records readable. | 验证 v1 META 槽
// 被接受、在下一次持久化时写成 v2，且记录仍可读。
func TestMetaV1UpgradesToV2(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(context.Background(), Record{Data: []byte("v1-meta")}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"META", "META.mirror"} {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		// Rewrite every valid slot as version 1 and refresh its CRC. |
		// 把每个有效槽改回版本 1 并刷新 CRC。
		for off := 0; off+metaSlotSize <= len(data); off += metaSlotSize {
			slot := data[off : off+metaSlotSize]
			if slot[0] == 0 {
				continue
			}
			binary.LittleEndian.PutUint16(slot[metaOffVersion:], metaVersionV1)
			binary.LittleEndian.PutUint32(slot[metaCRCOffset:], checksum(slot[:metaCRCOffset]))
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	w2, err := Open(dir)
	if err != nil {
		t.Fatalf("open v1 META: %v", err)
	}
	rec, err := w2.Read(1)
	if err != nil || !bytes.Equal(rec.Data, []byte("v1-meta")) {
		t.Fatalf("read v1 META record: %q, %v", rec.Data, err)
	}
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "META"))
	if err != nil {
		t.Fatal(err)
	}
	upgraded := false
	for off := 0; off+metaSlotSize <= len(data); off += metaSlotSize {
		slot := data[off : off+metaSlotSize]
		if slot[0] == 0 {
			continue
		}
		if binary.LittleEndian.Uint16(slot[metaOffVersion:]) == metaVersion {
			upgraded = true
		}
	}
	if !upgraded {
		t.Fatal("META was not upgraded to v2")
	}
}

// TestSerializableSM3AdoptedFromMeta verifies that the persisted write-key
// hash algorithm is adopted when the caller did not set one, and that an
// explicit conflicting choice is rejected. | 验证调用方未显式选择时采用 META
// 持久化的写键哈希算法，显式冲突则拒绝。
func TestSerializableSM3AdoptedFromMeta(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir, WithHashAlgorithm(HashSM3), WithSerializableDurability(true))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := w.Begin(ctx, WithTxnIsolation(IsolationSerializable))
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Append(ctx, Record{Key: []byte("k"), Data: []byte("v")}); err != nil {
		t.Fatal(err)
	}
	if err := tx.WriteKey([]byte("k")); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w2, err := Open(dir)
	if err != nil {
		t.Fatalf("open without WithHashAlgorithm: %v", err)
	}
	if _, err := w2.Read(1); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, WithHashAlgorithm(HashSHA256)); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("explicit SHA256 err = %v, want ErrInvalidOptions", err)
	}
}

// TestMetaVersionRejectsUnknown verifies that a future META version is not
// silently parsed as v1/v2. | 验证未来 META 版本不会被静默当作 v1/v2 解析。
func TestMetaVersionRejectsUnknown(t *testing.T) {
	var slot [metaSlotSize]byte
	encodeMetaSlot(slot[:], metaState{
		generation: 1, nextSeq: 1, nextLSN: 1, createdNano: 1, firstLSN: 1,
		walID: [16]byte{1},
	})
	binary.LittleEndian.PutUint16(slot[metaOffVersion:], metaVersion+1)
	binary.LittleEndian.PutUint32(slot[metaCRCOffset:], checksum(slot[:metaCRCOffset]))
	if _, _, err := decodeMetaSlot(slot[:]); err == nil {
		t.Fatal("unknown META version was accepted")
	}
}
