package raft

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// streamingKVFSM writes its snapshot directly to the provided writer and makes
// the in-memory Snapshot method fail so tests can prove the streaming path is
// the one in use. | streamingKVFSM 将快照直接写入给定 writer，并让内存 Snapshot
// 方法失败，使测试能够证明实际走的是流式路径。
type streamingKVFSM struct {
	*kvFSM
	mu          sync.Mutex
	streamCalls int
	streamErr   error
}

func newStreamingKVFSM() *streamingKVFSM {
	return &streamingKVFSM{kvFSM: newKVFSM()}
}

func (f *streamingKVFSM) Snapshot() ([]byte, error) {
	return nil, errors.New("streaming FSM must not materialize Snapshot")
}

func (f *streamingKVFSM) SnapshotTo(w io.Writer) error {
	f.mu.Lock()
	f.streamCalls++
	err := f.streamErr
	f.mu.Unlock()
	if err != nil {
		return err
	}
	data, snapErr := f.kvFSM.Snapshot()
	if snapErr != nil {
		return snapErr
	}
	_, err = w.Write(data)
	return err
}

func (f *streamingKVFSM) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.streamCalls
}

// TestStreamingFSMSnapshotSkipsMemoryImage verifies a StreamingFSM writes the
// image directly to storage, the live snapshot keeps only a file reference, and
// recovery restores the same state. | TestStreamingFSMSnapshotSkipsMemoryImage
// 验证 StreamingFSM 将镜像直接写入存储、活动快照只保留文件引用，且恢复得到相同状态。
func TestStreamingFSMSnapshotSkipsMemoryImage(t *testing.T) {
	dir := t.TempDir()
	fs, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	fsm := newStreamingKVFSM()
	node, err := New(Config{
		ID: 1, Peers: []Peer{{ID: 1}}, Storage: fs, FSM: fsm,
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
	if _, err := node.Propose(ctx, []byte("a=1")); err != nil {
		t.Fatal(err)
	}
	if _, err := node.Propose(ctx, []byte("b=2")); err != nil {
		t.Fatal(err)
	}
	if err := node.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	snap := node.latestSnapshot
	if snap == nil || snap.file == "" {
		t.Fatalf("latest snapshot = %+v, want file-backed image", snap)
	}
	if snap.Data != nil {
		t.Fatalf("streaming snapshot kept %d in-memory bytes", len(snap.Data))
	}
	if got := fsm.calls(); got != 1 {
		t.Fatalf("SnapshotTo calls = %d, want 1", got)
	}
	loaded, err := readSnapshotFile(snap.file)
	if err != nil {
		t.Fatal(err)
	}
	if string(loaded.Data) != "a=1\nb=2\n" {
		t.Fatalf("snapshot image = %q", loaded.Data)
	}
	// The marker must make the file trusted after a restart. | 重启后标记必须让
	// 文件被恢复流程信任。
	if err := node.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
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
	if got := restored.value("a"); got != "1" {
		t.Fatalf("restored a = %q, want 1", got)
	}
	if got := restored.value("b"); got != "2" {
		t.Fatalf("restored b = %q, want 2", got)
	}
}

// TestFileBackedSnapshotLoadsPayloadForSend verifies a streaming snapshot can
// be sent later without retaining its payload in memory. | TestFileBackedSnapshotLoadsPayloadForSend
// 验证流式快照之后发送时可以从文件加载负载，而无需在内存中长期保留。
func TestFileBackedSnapshotLoadsPayloadForSend(t *testing.T) {
	dir := t.TempDir()
	fs, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	snap := &Snapshot{Index: 3, Term: 1, ConfState: ConfState{Voters: []NodeID{1}},
		Data: []byte("payload")}
	if err := fs.WriteSnapshotFile(snap); err != nil {
		t.Fatal(err)
	}
	snap.Data = nil
	node := &Node{storage: fs}
	data, err := node.snapshotData(snap)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "payload" {
		t.Fatalf("loaded payload = %q", data)
	}
}

// TestStreamingSnapshotFailureRemovesTemporaryFile verifies a failed
// SnapshotTo call leaves no partial image behind. | TestStreamingSnapshotFailureRemovesTemporaryFile
// 验证 SnapshotTo 失败后不留下部分镜像文件。
func TestStreamingSnapshotFailureRemovesTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	fs, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	fsm := newStreamingKVFSM()
	fsm.streamErr = errors.New("snapshot capture failed")
	node, err := New(Config{
		ID: 1, Peers: []Peer{{ID: 1}}, Storage: fs, FSM: fsm,
		TickInterval: time.Millisecond, HeartbeatTicks: 1, ElectionTicks: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := node.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := node.Propose(ctx, []byte("a=1")); err != nil {
		t.Fatal(err)
	}
	if err := node.Snapshot(ctx); err == nil {
		t.Fatal("Snapshot succeeded with a failing StreamingFSM")
	}
	entries, err := os.ReadDir(filepath.Join(dir, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".snap-") {
			t.Fatalf("partial snapshot temp file left behind: %s", entry.Name())
		}
	}
}
