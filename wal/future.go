package wal

import (
	"context"
	"sync"
)

// appendResult is the completion of one writer request. | appendResult 是单个写入请求的完成结果。
type appendResult struct {
	err        error
	backupSet  *BackupSet
	timestamps []int64
	txnInfo    TxnInfo
	lsn        uint64
	firstLSN   uint64
	lastLSN    uint64
	segments   int
	duplicate  bool
}

// AppendFuture is the handle returned by AppendAsync. The record's Key/Data
// must stay unchanged until Done closes. | AppendFuture 是 AppendAsync 返回的
// 句柄；Done 关闭前不得修改记录的 Key/Data。
type AppendFuture struct {
	done   chan struct{}
	result appendResult
	once   sync.Once
	mu     sync.Mutex
}

// newAppendFuture builds a pending future. | newAppendFuture 构建待完成的 future。
func newAppendFuture() *AppendFuture {
	return &AppendFuture{done: make(chan struct{})}
}

// complete records the result exactly once and wakes waiters. | complete 只记录一次结果并唤醒等待者。
func (f *AppendFuture) complete(res appendResult) {
	f.once.Do(func() {
		f.mu.Lock()
		f.result = res
		f.mu.Unlock()
		close(f.done)
	})
}

// Done returns a channel closed when the request reaches a terminal state. | Done
// 返回请求进入终态时关闭的通道。
func (f *AppendFuture) Done() <-chan struct{} { return f.done }

// Result blocks until completion and may be called repeatedly. | Result 阻塞到完成，可重复调用。
func (f *AppendFuture) Result() (uint64, error) {
	<-f.done
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.result.lsn, f.result.err
}

// Wait blocks until completion or ctx cancellation. A canceled Wait does not
// imply the record was not committed. | Wait 阻塞到完成或 ctx 取消；Wait 被取消
// 不代表记录未提交。
func (f *AppendFuture) Wait(ctx context.Context) (uint64, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-f.done:
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.result.lsn, f.result.err
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}
