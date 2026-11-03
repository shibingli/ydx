package pool

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestCompletionWait verifies that wait observes the value written by finish.
// | TestCompletionWait 验证 wait 能观察到 finish 写入的值。
func TestCompletionWait(t *testing.T) {
	c := newCompletion[int]()
	go func() {
		c.finish(42, nil)
	}()
	got, err := c.wait(context.Background())
	if err != nil {
		t.Fatalf("wait error = %v | wait 错误", err)
	}
	if got != 42 {
		t.Fatalf("wait value = %d, want 42 | wait 结果不符", got)
	}
}

// TestCompletionError verifies that wait returns the stored error. | TestCompletionError
// 验证 wait 返回存储的错误。
func TestCompletionError(t *testing.T) {
	c := newCompletion[int]()
	c.finish(0, ErrPoolClosed)
	_, err := c.wait(context.Background())
	if !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("wait error = %v, want ErrPoolClosed | wait 错误不符", err)
	}
}

// TestCompletionContext verifies that an unfinished completion honors context expiry.
// | TestCompletionContext 验证未完成的 completion 遵守 context 到期。
func TestCompletionContext(t *testing.T) {
	c := newCompletion[int]()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := c.wait(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait error = %v, want DeadlineExceeded | wait 错误不符", err)
	}
}

// TestCompletionDone verifies that Done is closed by finish. | TestCompletionDone 验证
// finish 会关闭 Done 返回的 channel。
func TestCompletionDone(t *testing.T) {
	c := newCompletion[int]()
	done := c.doneCh()
	select {
	case <-done:
		t.Fatal("Done closed before finish | finish 之前 Done 已关闭")
	default:
	}
	c.finish(7, nil)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Done not closed after finish | finish 之后 Done 未关闭")
	}
	if got, err := c.wait(context.Background()); err != nil || got != 7 {
		t.Fatalf("wait = (%d, %v), want (7, nil) | wait 结果不符", got, err)
	}
}

// TestCompletionFinishOnce verifies that a second finish is ignored. | TestCompletionFinishOnce
// 验证第二次 finish 被忽略。
func TestCompletionFinishOnce(t *testing.T) {
	c := newCompletion[int]()
	c.finish(1, nil)
	c.finish(2, ErrQueueFull)
	if got, err := c.wait(context.Background()); err != nil || got != 1 {
		t.Fatalf("wait = (%d, %v), want (1, nil) | wait 结果不符", got, err)
	}
}

// TestCompletionConcurrentWait verifies that multiple waiters all observe completion.
// | TestCompletionConcurrentWait 验证多个等待者都能观察到完成。
func TestCompletionConcurrentWait(t *testing.T) {
	c := newCompletion[int]()
	const waiters = 8
	errsCh := make(chan error, waiters)
	for i := 0; i < waiters; i++ {
		go func() {
			got, err := c.wait(context.Background())
			if err == nil && got != 99 {
				err = errors.New("unexpected value | 结果不符")
			}
			errsCh <- err
		}()
	}
	c.finish(99, nil)
	for i := 0; i < waiters; i++ {
		if err := <-errsCh; err != nil {
			t.Fatalf("waiter error = %v | 等待者错误", err)
		}
	}
}
