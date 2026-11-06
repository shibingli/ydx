package raft

import (
	"github.com/shibingli/ydx/errs"
)

// raftLog is the in-memory log window. Entries after the snapshot base are
// authoritative; compact may retain a bounded prefix at or below snapshotIndex
// so slightly lagging followers can catch up without a snapshot transfer. That
// prefix is memory-only and is not recovered after a restart. | raftLog 是内存
// 日志窗口。快照基点之后的日志项是权威数据；compact 可保留 snapshotIndex 及之前
// 有界的前缀，使略微落后的跟随者无需快照传输即可追上。该前缀仅存在于内存，重启后
// 不会恢复。
type raftLog struct {
	entries       []Entry
	firstIndex    uint64
	lastIndex     uint64
	snapshotIndex uint64
	snapshotTerm  uint64
}

// newLog builds a log from a snapshot and the contiguous entries after it.
// | newLog 用快照及其后的连续日志项构建日志。
func newLog(snapshot *Snapshot, entries []Entry) (*raftLog, error) {
	l := &raftLog{firstIndex: 1}
	if snapshot != nil {
		l.snapshotIndex = snapshot.Index
		l.snapshotTerm = snapshot.Term
		l.firstIndex = snapshot.Index + 1
		l.lastIndex = snapshot.Index
	}
	if len(entries) > 0 {
		want := l.firstIndex
		for i := range entries {
			if entries[i].Index != want {
				return nil, errs.Detail(ErrCorrupt, "log gap at index %d, want %d", entries[i].Index, want)
			}
			if entries[i].Term == 0 {
				return nil, errs.Detail(ErrCorrupt, "zero term at index %d", entries[i].Index)
			}
			want++
		}
		l.entries = entries
		l.lastIndex = entries[len(entries)-1].Index
	}
	return l, nil
}

// term returns the term at index. Index 0 is term 0 by definition. | term 返回
// 指定索引的任期。按定义，索引 0 的任期为 0。
func (l *raftLog) term(index uint64) (uint64, error) {
	if index == 0 {
		return 0, nil
	}
	if index == l.snapshotIndex {
		return l.snapshotTerm, nil
	}
	if index < l.firstIndex {
		return 0, errs.Detail(ErrCompacted, "index %d first %d", index, l.firstIndex)
	}
	if index > l.lastIndex {
		return 0, errs.Detail(ErrUnavailable, "index %d last %d", index, l.lastIndex)
	}
	return l.entries[index-l.firstIndex].Term, nil
}

// mustTerm is term for indices the caller already validated. | mustTerm 用于调用方
// 已校验的索引。
func (l *raftLog) mustTerm(index uint64) uint64 {
	t, err := l.term(index)
	if err != nil {
		return 0
	}
	return t
}

// lastTerm returns the term of the last entry. | lastTerm 返回最后一条日志项的任期。
func (l *raftLog) lastTerm() uint64 {
	if l.lastIndex == 0 {
		return 0
	}
	return l.mustTerm(l.lastIndex)
}

// entry returns the entry at index. | entry 返回指定索引的日志项。
func (l *raftLog) entry(index uint64) (Entry, bool) {
	if index < l.firstIndex || index > l.lastIndex {
		return Entry{}, false
	}
	return l.entries[index-l.firstIndex], true
}

// slice returns entries in [lo, hi), stopping before maxBytes when set. At least
// one entry is returned when the range is non-empty and lo is available. | slice
// 返回 [lo, hi) 内的日志项；maxBytes 非零时在超限前停止。区间非空且 lo 可用时至少
// 返回一条。
func (l *raftLog) slice(lo, hi uint64, maxBytes int) ([]Entry, error) {
	if lo < l.firstIndex {
		return nil, errs.Detail(ErrCompacted, "lo %d first %d", lo, l.firstIndex)
	}
	if hi > l.lastIndex+1 {
		hi = l.lastIndex + 1
	}
	if lo >= hi {
		return nil, nil
	}
	start := lo - l.firstIndex
	end := hi - l.firstIndex
	if maxBytes <= 0 {
		return l.entries[start:end], nil
	}
	bytes := 0
	for i := start; i < end; i++ {
		sz := l.entries[i].size()
		if i > start && bytes+sz > maxBytes {
			end = i
			break
		}
		bytes += sz
	}
	return l.entries[start:end], nil
}

// append adds contiguous entries. | append 追加连续日志项。
func (l *raftLog) append(entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}
	if entries[0].Index != l.lastIndex+1 {
		return errs.Detail(ErrUnavailable, "append at %d after %d", entries[0].Index, l.lastIndex)
	}
	l.entries = append(l.entries, entries...)
	l.lastIndex = entries[len(entries)-1].Index
	return nil
}

// truncateFrom removes entries with index >= index. | truncateFrom 删除索引不小于 index
// 的日志项。
func (l *raftLog) truncateFrom(index uint64) error {
	if index > l.lastIndex {
		return nil
	}
	if index <= l.snapshotIndex {
		return errs.Detail(ErrCompacted, "truncate at %d snapshot %d", index, l.snapshotIndex)
	}
	cut := index - l.firstIndex
	// Copy the surviving prefix so in-flight messages and persistence batches
	// that reference the old backing array are never overwritten by later
	// appends. | 复制幸存前缀，确保仍引用旧底层数组的在途消息与持久化批次不会被后续
	// 追加覆盖。
	keep := append([]Entry(nil), l.entries[:cut]...)
	l.entries = keep
	if len(l.entries) == 0 {
		l.lastIndex = l.snapshotIndex
	} else {
		l.lastIndex = l.entries[len(l.entries)-1].Index
	}
	return nil
}

// conflict is returned when an AppendEntries consistency check fails. | conflict
// 在 AppendEntries 一致性检查失败时返回。
type conflict struct {
	index uint64
	term  uint64
	// tooFar means the follower's log is shorter than prevIndex. | tooFar 表示
	// 跟随者日志比 prevIndex 短。
	tooFar bool
}

// maybeAppend performs Raft's consistency check and appends entries. It returns
// the last new index, the commit index the follower may adopt, and the index at
// which a conflicting suffix was truncated (zero when nothing was removed).
// | maybeAppend 执行 Raft 一致性检查并追加日志，返回最后的新索引、跟随者可采用的
// 提交索引，以及冲突后缀被截断的位置（未删除时为零）。
func (l *raftLog) maybeAppend(prevIndex, prevTerm, leaderCommit uint64, entries []Entry) (lastNew, commit, truncatedAt uint64, c *conflict) {
	// prevIndex == snapshotIndex is checkable from the snapshot term, and index
	// 0 is the valid empty-log predecessor. Only a position strictly before the
	// snapshot base must be rejected. | prevIndex 等于快照索引时可用快照任期校验，
	// 索引 0 是空日志的合法前驱；只有严格早于快照基点的位置才必须拒绝。
	if prevIndex < l.snapshotIndex {
		// Point the leader at the first position checkable from the snapshot
		// term, not at a retained catch-up entry that this log still refuses to
		// match below the snapshot base. | 让领导者从可用快照任期校验的第一个
		// 位置重试，而不是指向本日志在快照基点之下仍拒绝匹配的追赶日志项。
		return 0, 0, 0, &conflict{index: l.snapshotIndex + 1, term: l.snapshotTerm}
	}
	if prevIndex > l.lastIndex {
		return 0, 0, 0, &conflict{index: l.lastIndex + 1, term: 0, tooFar: true}
	}
	if t := l.mustTerm(prevIndex); t != prevTerm {
		return 0, 0, 0, &conflict{index: prevIndex, term: t}
	}
	lastNew = prevIndex
	for i := range entries {
		e := entries[i]
		if e.Index <= l.lastIndex {
			if l.mustTerm(e.Index) == e.Term {
				lastNew = e.Index
				continue
			}
			if err := l.truncateFrom(e.Index); err != nil {
				return 0, 0, 0, &conflict{index: l.firstIndex, term: l.mustTerm(l.firstIndex)}
			}
			truncatedAt = e.Index
		}
		if err := l.append(entries[i:]); err != nil {
			return 0, 0, 0, &conflict{index: e.Index, term: e.Term}
		}
		lastNew = entries[len(entries)-1].Index
		break
	}
	if leaderCommit < lastNew {
		commit = leaderCommit
	} else {
		commit = lastNew
	}
	return lastNew, commit, truncatedAt, nil
}

// lastIndexInTerm returns the last log index carrying term, or false when the
// term is absent. | lastIndexInTerm 返回带有 term 的最后日志索引；不存在时返回 false。
func (l *raftLog) lastIndexInTerm(term uint64) (uint64, bool) {
	for i := len(l.entries) - 1; i >= 0; i-- {
		if l.entries[i].Term == term {
			return l.entries[i].Index, true
		}
		if l.entries[i].Term < term {
			break
		}
	}
	if l.snapshotIndex > 0 && l.snapshotTerm == term {
		return l.snapshotIndex, true
	}
	return 0, false
}

// restore replaces the log with a snapshot. | restore 用快照替换日志。
func (l *raftLog) restore(s *Snapshot) {
	l.entries = nil
	l.snapshotIndex = s.Index
	l.snapshotTerm = s.Term
	l.firstIndex = s.Index + 1
	l.lastIndex = s.Index
}

// compact folds entries through index into the snapshot base. catchUp retains
// up to that many older entries in memory for follower catch-up; with zero the
// window starts strictly after the snapshot. | compact 将 index 及之前的日志项
// 折叠进快照基点。catchUp 会在内存中保留最多该数量的更旧日志项供跟随者追赶；
// 为零时窗口严格位于快照之后。
func (l *raftLog) compact(index, catchUp uint64) error {
	if index <= l.snapshotIndex {
		return nil
	}
	if index > l.lastIndex {
		return errs.Detail(ErrUnavailable, "compact %d past last %d", index, l.lastIndex)
	}
	term := l.mustTerm(index)
	keepFrom := index + 1
	if catchUp > 0 {
		if index > catchUp && index-catchUp > l.firstIndex {
			keepFrom = index - catchUp
		} else {
			keepFrom = l.firstIndex
		}
	}
	if keepFrom < l.firstIndex {
		keepFrom = l.firstIndex
	}
	cut := int(keepFrom - l.firstIndex)
	keep := append([]Entry(nil), l.entries[cut:]...)
	l.entries = keep
	l.snapshotIndex = index
	l.snapshotTerm = term
	l.firstIndex = keepFrom
	if len(keep) == 0 {
		l.lastIndex = index
	} else {
		l.lastIndex = keep[len(keep)-1].Index
	}
	return nil
}

// upToDate reports whether a candidate with the given last log position can win
// a vote against the local log. | upToDate 报告具有给定最后日志位置的候选者能否在
// 本地日志上赢得选票。
func (l *raftLog) upToDate(lastIndex, lastTerm uint64) bool {
	if lastTerm != l.lastTerm() {
		return lastTerm > l.lastTerm()
	}
	return lastIndex >= l.lastIndex
}
