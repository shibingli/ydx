package wal

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testAESKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestKeyRotationAndReopen(t *testing.T) {
	dir := t.TempDir()
	ring, err := NewKeyRing(1,
		Key{ID: 1, Suite: SuiteAESGCM, Bytes: testAESKey(0x11)},
		Key{ID: 2, Suite: SuiteAESGCM, Bytes: testAESKey(0x22)})
	if err != nil {
		t.Fatalf("ring: %v", err)
	}
	w, err := Open(dir, WithEncryption(ring))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()
	lsn1, err := w.Append(ctx, Record{Key: []byte("k1"), Data: []byte("before")})
	if err != nil {
		t.Fatalf("append before: %v", err)
	}
	if err := w.SetActiveKey(2); err != nil {
		t.Fatalf("set active key: %v", err)
	}
	lsn2, err := w.Append(ctx, Record{Key: []byte("k2"), Data: []byte("after")})
	if err != nil {
		t.Fatalf("append after: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	w2, err := Open(dir, WithEncryption(ring))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer w2.Close()
	for _, lsn := range []uint64{lsn1, lsn2} {
		if _, err := w2.Read(lsn); err != nil {
			t.Fatalf("read %d: %v", lsn, err)
		}
	}
}

func TestEnableEncryptionOnEmptyWAL(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatalf("open plaintext: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close plaintext: %v", err)
	}
	ring, _ := NewKeyRing(1, Key{ID: 1, Suite: SuiteAESGCM, Bytes: testAESKey(0x44)})
	w2, err := Open(dir, WithEncryption(ring))
	if err != nil {
		t.Fatalf("enable encryption: %v", err)
	}
	if _, err := w2.Append(context.Background(), Record{Data: []byte("encrypted")}); err != nil {
		t.Fatalf("append encrypted: %v", err)
	}
	if err := w2.Close(); err != nil {
		t.Fatalf("close encrypted: %v", err)
	}
	w3, err := Open(dir, WithEncryption(ring))
	if err != nil {
		t.Fatalf("reopen encrypted: %v", err)
	}
	defer w3.Close()
	if rec, err := w3.Read(1); err != nil || string(rec.Data) != "encrypted" {
		t.Fatalf("read encrypted rec=%v err=%v", rec, err)
	}
}

func TestKCVRejectsReplacedKey(t *testing.T) {
	dir := t.TempDir()
	ring1, _ := NewKeyRing(1, Key{ID: 1, Suite: SuiteAESGCM, Bytes: testAESKey(0x11)})
	w, err := Open(dir, WithEncryption(ring1))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := w.Append(context.Background(), Record{Data: []byte("secret")}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	ring2, _ := NewKeyRing(1, Key{ID: 1, Suite: SuiteAESGCM, Bytes: testAESKey(0x33)})
	if _, err := Open(dir, WithEncryption(ring2)); !errors.Is(err, ErrAuth) {
		t.Fatalf("open with replaced key err=%v, want ErrAuth", err)
	}
	w2, err := Open(dir, WithEncryption(ring2), WithSkipKeyCheck(true))
	if err != nil {
		t.Fatalf("skip key check open: %v", err)
	}
	defer w2.Close()
	if _, err := w2.Read(1); err == nil {
		t.Fatal("expected authentication failure on read")
	}
}

func TestReadOnlyDoesNotMutate(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := w.Append(context.Background(), Record{Data: []byte("x")}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	metaPath := filepath.Join(dir, "META")
	before, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("read meta: %v", err)
	}
	rw, err := Open(dir, WithReadOnly(true))
	if err != nil {
		t.Fatalf("read-only open: %v", err)
	}
	if _, err := rw.Append(context.Background(), Record{Data: []byte("y")}); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("append err=%v, want ErrReadOnly", err)
	}
	if _, err := rw.Read(1); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := rw.Close(); err != nil {
		t.Fatalf("read-only close: %v", err)
	}
	after, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("read meta after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("read-only Close mutated META")
	}
}

func TestCheckpointSidecar(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, WithCheckpointBytes(128))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer w.Close()
	ctx := context.Background()
	payload := bytes.Repeat([]byte("c"), 100)
	for i := 0; i < 12; i++ {
		if _, err := w.Append(ctx, Record{Data: payload}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		sc, err := loadSidecar(sidecarPath(dir, 1))
		if err == nil && sc.checkpoint {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("checkpoint sidecar not written: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	for i := uint64(1); i <= 12; i++ {
		if _, err := w.Read(i); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
	}
}

func TestManifestDisabled(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, WithManifest(false))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := w.Append(ctx, Record{Data: []byte{byte(i)}}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	w2, err := Open(dir, WithManifest(false))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer w2.Close()
	for i := uint64(1); i <= 3; i++ {
		if _, err := w2.Read(i); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
	}
}
