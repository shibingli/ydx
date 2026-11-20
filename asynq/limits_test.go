package asynq_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	asynqio "github.com/hibiken/asynq"

	asynq "github.com/shibingli/ydx/asynq"
)

// TestQueueWeightLimitsRejected asserts programmatic queue weights are bounded
// as well, not only the parsed config string. | TestQueueWeightLimitsRejected
// 断言不仅解析配置串，程序化设置的队列权重同样受限。
func TestQueueWeightLimitsRejected(t *testing.T) {
	if asynq.MaxQueueWeight <= 0 || asynq.MaxTotalQueueWeight < asynq.MaxQueueWeight {
		t.Fatalf("权重上限常量非法: single=%d total=%d", asynq.MaxQueueWeight, asynq.MaxTotalQueueWeight)
	}
	single := asynq.Options{Queues: map[string]int{"critical": asynq.MaxQueueWeight + 1}}
	if err := single.Err(); !errors.Is(err, asynq.ErrQueueWeightTooLarge) {
		t.Fatalf("单队列超限 Err = %v, 期望 ErrQueueWeightTooLarge", err)
	}
	total := asynq.Options{Queues: map[string]int{"a": 600, "b": 401}}
	if err := total.Err(); !errors.Is(err, asynq.ErrQueueWeightTooLarge) {
		t.Fatalf("总权重超限 Err = %v, 期望 ErrQueueWeightTooLarge", err)
	}
}

// TestEnqueueRejectsOversizedPayload asserts the client applies MaxPayloadBytes
// before touching the broker. | TestEnqueueRejectsOversizedPayload 断言客户端在访问
// 中间件之前应用 MaxPayloadBytes。
func TestEnqueueRejectsOversizedPayload(t *testing.T) {
	mr := miniredis.RunT(t)
	o := testOptions()
	o.MaxPayloadBytes = 64
	cli := newTestClient(t, mr, o)

	if _, err := cli.Enqueue(context.Background(), "big:run", strings.Repeat("x", 256)); !errors.Is(err, asynq.ErrPayloadTooLarge) {
		t.Fatalf("超大载荷错误 = %v, 期望 ErrPayloadTooLarge", err)
	}
}

// TestProcessTaskRejectsOversizedPayload asserts the consumer applies the same
// bound before decoding a task body. | TestProcessTaskRejectsOversizedPayload
// 断言消费侧在解码任务载荷之前应用同样的上限。
func TestProcessTaskRejectsOversizedPayload(t *testing.T) {
	log, _ := newTestLogger()
	called := false
	reg := asynq.NewRegistry()
	reg.Register("big:run", func(context.Context, asynq.Payload) error {
		called = true
		return nil
	})
	srv := asynq.NewServer(reg, asynqio.RedisClientOpt{Addr: "127.0.0.1:1"}, asynq.Options{MaxPayloadBytes: 64}, log)
	task := asynqio.NewTask("big:run", []byte(strings.Repeat("x", 256)))
	err := srv.ProcessTask(context.Background(), task)
	if !errors.Is(err, asynq.ErrPayloadTooLarge) {
		t.Fatalf("消费超大载荷错误 = %v, 期望 ErrPayloadTooLarge", err)
	}
	if called {
		t.Fatal("超大载荷仍被交给处理器")
	}
}

// TestDefaultMaxPayloadBytes pins the documented default. | TestDefaultMaxPayloadBytes 固化文档化的默认值。
func TestDefaultMaxPayloadBytes(t *testing.T) {
	if asynq.DefaultMaxPayloadBytes != 1<<20 {
		t.Fatalf("DefaultMaxPayloadBytes = %d, 期望 1 MiB", asynq.DefaultMaxPayloadBytes)
	}
}
