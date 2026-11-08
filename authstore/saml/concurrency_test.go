package saml_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	samlapi "github.com/shibingli/ydx/auth/protocol/saml"
	authsaml "github.com/shibingli/ydx/authstore/saml"
)

// concurrentResult carries one operation outcome from a worker goroutine.
// | concurrentResult 携带工作协程的单次操作结果。
type concurrentResult struct {
	seen bool
	err  error
}

// runConcurrently runs workers operations across two stores and returns every outcome.
// | runConcurrently 在两个存储上运行 workers 次操作并返回全部结果。
func runConcurrently(t *testing.T, workers int, operation func(stores *authsaml.Stores, worker int) (bool, error)) []concurrentResult {
	t.Helper()
	first, second := newPair(t)
	start := make(chan struct{})
	results := make(chan concurrentResult, workers)
	for worker := 0; worker < workers; worker++ {
		stores := first
		if worker%2 == 1 {
			stores = second
		}
		go func(stores *authsaml.Stores, worker int) {
			<-start
			seen, err := operation(stores, worker)
			results <- concurrentResult{seen: seen, err: err}
		}(stores, worker)
	}
	close(start)
	collected := make([]concurrentResult, 0, workers)
	for len(collected) < workers {
		collected = append(collected, <-results)
	}
	return collected
}

// TestConcurrentSeenAndStoreExactlyOnce verifies that exactly one concurrent assertion record is
// fresh across two instances. | TestConcurrentSeenAndStoreExactlyOnce 验证跨两个实例的并发断言记录
// 恰好一个为新鲜。
func TestConcurrentSeenAndStoreExactlyOnce(t *testing.T) {
	base := testTime(2026, time.June, 15, 0, 0, 0)
	expires := base.Add(time.Hour)
	const workers = 32
	results := runConcurrently(t, workers, func(stores *authsaml.Stores, _ int) (bool, error) {
		return stores.SeenAndStore(testContext, "assertion-concurrent", expires, base)
	})
	fresh, seen := 0, 0
	for _, result := range results {
		if result.err != nil {
			t.Fatalf("SeenAndStore error: %v | 并发 SeenAndStore 失败", result.err)
		}
		if result.seen {
			seen++
		} else {
			fresh++
		}
	}
	if fresh != 1 || seen != workers-1 {
		t.Fatalf("fresh=%d seen=%d, want 1/%d | 并发 SeenAndStore 恰好一次语义不符", fresh, seen, workers-1)
	}
}

// TestConcurrentTakeArtifactExactlyOnce verifies that exactly one concurrent artifact take wins.
// | TestConcurrentTakeArtifactExactlyOnce 验证并发工件消费恰好一个成功。
func TestConcurrentTakeArtifactExactlyOnce(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.July, 15, 0, 0, 0)
	expires := base.Add(time.Hour)
	artifact := sampleArtifact(1, 0)
	if err := first.SaveArtifact(testContext, sampleRecord(artifact, "payload", base, expires), base); err != nil {
		t.Fatalf("save artifact: %v | 保存工件失败", err)
	}
	const workers = 32
	start := make(chan struct{})
	results := make(chan concurrentResult, workers)
	for worker := 0; worker < workers; worker++ {
		stores := first
		if worker%2 == 1 {
			stores = second
		}
		go func(stores *authsaml.Stores) {
			<-start
			record, err := stores.TakeArtifact(testContext, artifact, base)
			if err == nil && !record.Used {
				err = errors.New("taken artifact is not marked used | 已消费工件未标记已用")
			}
			results <- concurrentResult{err: err}
		}(stores)
	}
	close(start)
	success, replay := 0, 0
	for received := 0; received < workers; received++ {
		result := <-results
		switch {
		case result.err == nil:
			success++
		case errors.Is(result.err, samlapi.ErrReplay):
			replay++
		default:
			t.Fatalf("take artifact error: %v | 并发消费工件失败", result.err)
		}
	}
	if success != 1 || replay != workers-1 {
		t.Fatalf("success=%d replay=%d, want 1/%d | 并发消费工件语义不符", success, replay, workers-1)
	}
}

// TestConcurrentSaveRequestDuplicate verifies that a shared request ID accepts only one writer.
// | TestConcurrentSaveRequestDuplicate 验证共享请求标识只接受一个写入者。
func TestConcurrentSaveRequestDuplicate(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.September, 15, 0, 0, 0)
	expires := base.Add(time.Hour)
	const workers = 24
	start := make(chan struct{})
	results := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		stores := first
		if worker%2 == 1 {
			stores = second
		}
		go func(stores *authsaml.Stores) {
			<-start
			results <- stores.SaveRequest(testContext, sampleRequest("request-concurrent", base, expires))
		}(stores)
	}
	close(start)
	success, replay := 0, 0
	for received := 0; received < workers; received++ {
		err := <-results
		switch {
		case err == nil:
			success++
		case errors.Is(err, samlapi.ErrReplay):
			replay++
		default:
			t.Fatalf("save request error: %v | 并发保存请求失败", err)
		}
	}
	if success != 1 || replay != workers-1 {
		t.Fatalf("success=%d replay=%d | 并发保存请求语义不符", success, replay)
	}
}

// TestConcurrentSaveArtifactDuplicate verifies that one artifact key accepts only one writer.
// | TestConcurrentSaveArtifactDuplicate 验证单个工件键只接受一个写入者。
func TestConcurrentSaveArtifactDuplicate(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.October, 15, 0, 0, 0)
	expires := base.Add(time.Hour)
	artifact := sampleArtifact(1, 0)
	const workers = 24
	start := make(chan struct{})
	results := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		stores := first
		if worker%2 == 1 {
			stores = second
		}
		go func(stores *authsaml.Stores) {
			<-start
			results <- stores.SaveArtifact(testContext, sampleRecord(artifact, "payload", base, expires), base)
		}(stores)
	}
	close(start)
	success, replay := 0, 0
	for received := 0; received < workers; received++ {
		err := <-results
		switch {
		case err == nil:
			success++
		case errors.Is(err, samlapi.ErrReplay):
			replay++
		default:
			t.Fatalf("save artifact error: %v | 并发保存工件失败", err)
		}
	}
	if success != 1 || replay != workers-1 {
		t.Fatalf("success=%d replay=%d | 并发保存工件语义不符", success, replay)
	}
}

// TestConcurrentSessionWrites verifies that concurrent session writes all appear in one subject
// list. | TestConcurrentSessionWrites 验证并发会话写入全部出现在同一主体列表中。
func TestConcurrentSessionWrites(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.November, 15, 0, 0, 0)
	expires := base.Add(time.Hour)
	const workers = 40
	start := make(chan struct{})
	results := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		stores := first
		if worker%2 == 1 {
			stores = second
		}
		go func(stores *authsaml.Stores, worker int) {
			<-start
			id := fmt.Sprintf("sess-concurrent-%02d", worker)
			results <- stores.SaveSession(testContext, sampleSession(id, "alice", base, expires))
		}(stores, worker)
	}
	close(start)
	for received := 0; received < workers; received++ {
		if err := <-results; err != nil {
			t.Fatalf("save session error: %v | 并发保存会话失败", err)
		}
	}
	sessions, err := first.ListSessions(testContext, "alice")
	if err != nil {
		t.Fatalf("list sessions: %v | 列出会话失败", err)
	}
	if len(sessions) != workers {
		t.Fatalf("sessions = %d, want %d | 并发会话数量不符", len(sessions), workers)
	}
	unique := make(map[string]struct{}, workers)
	for _, session := range sessions {
		unique[session.ID] = struct{}{}
	}
	if len(unique) != workers {
		t.Fatalf("unique sessions = %d, want %d | 并发会话存在重复", len(unique), workers)
	}
}

// TestConcurrentCleanupAndWrites verifies that cleanup runs concurrently without losing live
// records. | TestConcurrentCleanupAndWrites 验证清理并发运行时不丢失有效记录。
func TestConcurrentCleanupAndWrites(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.December, 15, 0, 0, 0)
	expires := base.Add(24 * time.Hour)
	const workers = 24
	start := make(chan struct{})
	results := make(chan error, workers+1)
	for worker := 0; worker < workers; worker++ {
		stores := first
		if worker%2 == 1 {
			stores = second
		}
		go func(stores *authsaml.Stores, worker int) {
			<-start
			id := fmt.Sprintf("sess-mixed-%02d", worker)
			if err := stores.SaveSession(testContext, sampleSession(id, "alice", base, expires)); err != nil {
				results <- err
				return
			}
			if err := stores.SaveArtifact(testContext, sampleRecord(sampleArtifact(byte(worker), 0), id, base, expires), base); err != nil {
				results <- err
				return
			}
			results <- nil
		}(stores, worker)
	}
	go func(stores *authsaml.Stores) {
		<-start
		results <- stores.Cleanup(testContext, base)
	}(second)
	close(start)
	for received := 0; received < workers+1; received++ {
		if err := <-results; err != nil {
			t.Fatalf("concurrent operation error: %v | 并发操作失败", err)
		}
	}
	sessions, err := second.ListSessions(testContext, "alice")
	if err != nil {
		t.Fatalf("list sessions: %v | 列出会话失败", err)
	}
	if len(sessions) != workers {
		t.Fatalf("sessions after cleanup = %d, want %d | 清理误删有效会话", len(sessions), workers)
	}
	for worker := 0; worker < workers; worker++ {
		artifact := sampleArtifact(byte(worker), 0)
		if _, err := first.TakeArtifact(testContext, artifact, base); err != nil {
			t.Fatalf("take artifact %d: %v | 清理误删有效工件 %d", worker, err, worker)
		}
	}
}
