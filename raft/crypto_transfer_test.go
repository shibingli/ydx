package raft

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// TestEncryptedChunkedSnapshotTransfer verifies an encrypted file-backed leader
// image is decrypted for each transport chunk, reassembled by a learner and
// persisted encrypted there. | TestEncryptedChunkedSnapshotTransfer 验证加密的
// 文件镜像按传输分块逐一解密、由学习者重组并在学习者端加密持久化。
func TestEncryptedChunkedSnapshotTransfer(t *testing.T) {
	leaderStore, err := NewFileStorage(testStorageOptions(t.TempDir(), EncryptionAES256GCM, EncryptAll))
	if err != nil {
		t.Fatal(err)
	}
	learnerStore, err := NewFileStorage(testStorageOptions(t.TempDir(), EncryptionAES256GCM, EncryptAll))
	if err != nil {
		t.Fatal(err)
	}
	net := NewMemNetwork()
	t.Cleanup(net.Close)
	tr1, err := net.NewTransport(1)
	if err != nil {
		t.Fatal(err)
	}
	tr2, err := net.NewTransport(2)
	if err != nil {
		t.Fatal(err)
	}
	leaderFSM := newStreamingKVFSM()
	leader, err := New(Config{
		ID: 1, Peers: []Peer{{ID: 1}}, Storage: leaderStore, FSM: leaderFSM, Transport: tr1,
		TickInterval: 5 * time.Millisecond, HeartbeatTicks: 1, ElectionTicks: 8,
		SnapshotEntries: 5, SnapshotCatchUpEntries: 1, SnapshotChunkBytes: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = leader.Close() })
	learnerFSM := newKVFSM()
	learner, err := New(Config{
		ID: 2, Join: true, Storage: learnerStore, FSM: learnerFSM, Transport: tr2,
		TickInterval: 5 * time.Millisecond, HeartbeatTicks: 1, ElectionTicks: 8,
		SnapshotChunkBytes: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = learner.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := leader.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 180)
	for i := range payload {
		payload[i] = byte('a' + i%26)
	}
	var last Result
	for i := 0; i < 20; i++ {
		res, err := leader.Propose(ctx, append([]byte(fmt.Sprintf("e%d=", i)), payload...))
		if err != nil {
			t.Fatalf("propose %d: %v", i, err)
		}
		last = res
	}
	waitSnapshot(t, leader, 10*time.Second)
	if err := leader.AddLearner(ctx, 2, ""); err != nil {
		t.Fatalf("add learner: %v", err)
	}
	if err := learner.WaitApplied(ctx, last.Index); err != nil {
		t.Fatalf("learner apply: %v", err)
	}
	if got := learnerFSM.value("e19"); string(got) != string(payload) {
		t.Fatalf("learner value length = %d, want %d", len(got), len(payload))
	}
	if got := leader.metrics.snapshotChunksOut.Load(); got == 0 {
		t.Fatal("leader sent no encrypted snapshot chunks")
	}
	if got := learner.metrics.snapshotChunksIn.Load(); got == 0 {
		t.Fatal("learner received no encrypted snapshot chunks")
	}
	learnerSnap := learner.latestSnapshot
	if learnerSnap == nil || learnerSnap.crypto == nil || learnerSnap.file == "" {
		t.Fatalf("learner snapshot = %+v", learnerSnap)
	}
	learnerRaw, err := os.ReadFile(learnerSnap.file)
	if err != nil {
		t.Fatal(err)
	}
	if learnerRaw[8] != snapshotVersionEncrypted {
		t.Fatalf("learner snapshot version = %d, want %d", learnerRaw[8], snapshotVersionEncrypted)
	}
	snap := leader.latestSnapshot
	if snap == nil || snap.crypto == nil || snap.file == "" {
		t.Fatalf("latest snapshot = %+v", snap)
	}
	raw, err := os.ReadFile(snap.file)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, payload[:32]) {
		t.Fatal("leader snapshot file contains plaintext payload")
	}
}

// TestStreamingSnapshotEncryption verifies the StreamingFSM path writes an
// encrypted version 3 image and restores it after a restart. |
// TestStreamingSnapshotEncryption 验证 StreamingFSM 路径写入加密的版本 3 镜像，并在
// 重启后恢复。
func TestStreamingSnapshotEncryption(t *testing.T) {
	dir := t.TempDir()
	opts := testStorageOptions(dir, EncryptionAES256GCM, EncryptAll)
	store, err := NewFileStorage(opts)
	if err != nil {
		t.Fatal(err)
	}
	fsm := newStreamingKVFSM()
	node, err := New(Config{
		ID: 1, Peers: []Peer{{ID: 1}}, Storage: store, FSM: fsm,
		TickInterval: time.Millisecond, HeartbeatTicks: 1, ElectionTicks: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := node.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := node.Propose(ctx, []byte("secret=1")); err != nil {
		t.Fatal(err)
	}
	if err := node.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	snap := node.latestSnapshot
	if snap == nil || snap.file == "" || snap.crypto == nil {
		t.Fatalf("latest snapshot = %+v", snap)
	}
	raw, err := os.ReadFile(snap.file)
	if err != nil {
		t.Fatal(err)
	}
	if raw[8] != snapshotVersionEncrypted {
		t.Fatalf("snapshot version = %d, want %d", raw[8], snapshotVersionEncrypted)
	}
	if bytes.Contains(raw, []byte("secret=1")) {
		t.Fatal("streaming snapshot contains plaintext")
	}
	loaded, err := readSnapshotFileWith(snap.file, store.cipher)
	if err != nil {
		t.Fatal(err)
	}
	if string(loaded.Data) != "secret=1\n" {
		t.Fatalf("snapshot payload = %q", loaded.Data)
	}
	if err := node.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStorage(opts)
	if err != nil {
		t.Fatal(err)
	}
	restored := newStreamingKVFSM()
	node2, err := New(Config{
		ID: 1, Peers: []Peer{{ID: 1}}, Storage: reopened, FSM: restored,
		TickInterval: time.Millisecond, HeartbeatTicks: 1, ElectionTicks: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer node2.Close()
	if got := restored.value("secret"); got != "1" {
		t.Fatalf("restored secret = %q, want 1", got)
	}
}
