package raft

import (
	"errors"
	"testing"
)

// TestLogAppendTruncateCompact covers the log window invariants. | TestLogAppendTruncateCompact
// 覆盖日志窗口不变量。
func TestLogAppendTruncateCompact(t *testing.T) {
	l, err := newLog(nil, entriesRange(1, 5, 1))
	if err != nil {
		t.Fatal(err)
	}
	if l.lastIndex != 5 || l.lastTerm() != 1 {
		t.Fatalf("last = %d/%d", l.lastIndex, l.lastTerm())
	}
	if err := l.append(entriesRange(6, 8, 2)); err != nil {
		t.Fatal(err)
	}
	if l.lastIndex != 8 || l.lastTerm() != 2 {
		t.Fatalf("last after append = %d/%d", l.lastIndex, l.lastTerm())
	}
	if err := l.truncateFrom(6); err != nil {
		t.Fatal(err)
	}
	if l.lastIndex != 5 {
		t.Fatalf("last after truncate = %d", l.lastIndex)
	}
	if err := l.compact(3); err != nil {
		t.Fatal(err)
	}
	if l.firstIndex != 4 || l.snapshotIndex != 3 || l.mustTerm(3) != 1 {
		t.Fatalf("compacted log = %+v", l)
	}
	if _, err := l.term(2); !errors.Is(err, ErrCompacted) {
		t.Fatalf("term(2) error = %v", err)
	}
	if got, err := l.slice(4, 6, 0); err != nil || len(got) != 2 || got[0].Index != 4 {
		t.Fatalf("slice = %+v %v", got, err)
	}
}

// TestLogMaybeAppendConflict checks fast backtracking hints. | TestLogMaybeAppendConflict
// 检查快速回退提示。
func TestLogMaybeAppendConflict(t *testing.T) {
	l, err := newLog(nil, entriesRange(1, 5, 1))
	if err != nil {
		t.Fatal(err)
	}
	last, commit, trunc, conflict := l.maybeAppend(4, 1, 5, entriesRange(5, 6, 1))
	if conflict != nil || last != 6 || commit != 5 || trunc != 0 {
		t.Fatalf("append duplicate: last=%d commit=%d trunc=%d conflict=%+v", last, commit, trunc, conflict)
	}
	conflictEntries := []Entry{{Index: 5, Term: 2}, {Index: 6, Term: 2}}
	last, commit, trunc, conflict = l.maybeAppend(4, 1, 6, conflictEntries)
	if conflict != nil || last != 6 || commit != 6 || trunc != 5 {
		t.Fatalf("conflict append: last=%d commit=%d trunc=%d conflict=%+v", last, commit, trunc, conflict)
	}
	_, _, _, conflict = l.maybeAppend(2, 9, 0, nil)
	if conflict == nil || conflict.index != 2 || conflict.term != 1 {
		t.Fatalf("term conflict = %+v", conflict)
	}
	_, _, _, conflict = l.maybeAppend(99, 9, 0, nil)
	if conflict == nil || !conflict.tooFar || conflict.index != 7 {
		t.Fatalf("short log conflict = %+v", conflict)
	}
}

// TestLogSnapshotBoundary checks prevIndex at the snapshot base. | TestLogSnapshotBoundary
// 检查快照基点处的 prevIndex。
func TestLogSnapshotBoundary(t *testing.T) {
	snap := &Snapshot{Index: 5, Term: 3, Data: []byte("s")}
	l, err := newLog(snap, entriesRange(6, 8, 4))
	if err != nil {
		t.Fatal(err)
	}
	last, _, _, conflict := l.maybeAppend(5, 3, 8, entriesRange(6, 8, 4))
	if conflict != nil || last != 8 {
		t.Fatalf("snapshot boundary: last=%d conflict=%+v", last, conflict)
	}
	_, _, _, conflict = l.maybeAppend(4, 2, 8, nil)
	if conflict == nil || conflict.index != 6 {
		t.Fatalf("compacted predecessor = %+v", conflict)
	}
	if !l.upToDate(9, 4) || l.upToDate(5, 3) || l.upToDate(8, 3) {
		t.Fatalf("upToDate is wrong")
	}
}

// TestConfChangeCodec covers membership command round trips. | TestConfChangeCodec
// 覆盖成员命令往返。
func TestConfChangeCodec(t *testing.T) {
	cases := []ConfChange{
		{Type: ConfChangeAddNode, NodeID: 4, Addr: "host:1"},
		{Type: ConfChangeRemoveNode, NodeID: 2},
		{Type: ConfChangeAddLearner, NodeID: 5, Addr: "host:2"},
		{Type: ConfChangePromote, NodeID: 5},
		{Type: ConfChangeLeaveJoint},
	}
	for _, want := range cases {
		data, err := encodeConfChange(want)
		if err != nil {
			t.Fatal(err)
		}
		got, err := decodeConfChange(data)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("got %+v want %+v", got, want)
		}
	}
}
