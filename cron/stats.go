package cron

import (
	"sync"
	"sync/atomic"
)

// errorBox makes the last error readable without a mutex; it is allocated only
// on a failed run, so the success path stays allocation-free. |
// errorBox 让最后错误无需互斥锁即可读取；它只在失败运行时分配，成功路径保持零分配。
type errorBox struct {
	text string
}

// jobStats accumulates one job's counters. The atomics keep the run path lock
// free; only the bounded history needs the mutex. |
// jobStats 累积单个任务的计数器。原子量让运行路径无锁；只有有界历史需要互斥锁。
type jobStats struct {
	lastErr      atomic.Pointer[errorBox]
	history      []RunRecord
	runs         atomic.Uint64
	failures     atomic.Uint64
	skipped      atomic.Uint64
	dropped      atomic.Uint64
	lastRun      atomic.Int64
	lastDuration atomic.Int64
	mu           sync.Mutex
	running      atomic.Int32
}

// addRecord stores the last error and appends to the history ring. A negative
// limit disables history while still recording the last error. |
// addRecord 保存最后错误并追加到历史环；负上限关闭历史但仍记录最后错误。
func (st *jobStats) addRecord(record RunRecord, limit int) {
	if record.Err == "" {
		st.lastErr.Store(nil)
	} else {
		st.lastErr.Store(&errorBox{text: record.Err})
	}
	if limit <= 0 {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.history) == limit {
		copy(st.history, st.history[1:])
		st.history[len(st.history)-1] = RunRecord{}
		st.history = st.history[:limit-1]
	}
	st.history = append(st.history, record)
}

// lastError returns the most recent run error. | lastError 返回最近一次运行错误。
func (st *jobStats) lastError() string {
	if box := st.lastErr.Load(); box != nil {
		return box.text
	}
	return ""
}

// historyNewestFirst copies the history with the newest record first. |
// historyNewestFirst 复制历史并按最新在前返回。
func (st *jobStats) historyNewestFirst() []RunRecord {
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.history) == 0 {
		return nil
	}
	out := make([]RunRecord, len(st.history))
	for index, record := range st.history {
		out[len(st.history)-1-index] = record
	}
	return out
}
