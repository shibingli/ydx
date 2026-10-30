package cron

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	gocron "github.com/go-co-op/gocron/v2"
	robfig "github.com/robfig/cron/v3"

	yd "github.com/shibingli/ydx/cron"
)

// benchJobs is the population used by list/get/stat benchmarks. |
// benchJobs 是列表/读取/统计基准使用的任务数量。
const benchJobs = 1000

// benchSinkAny keeps interface results observable. | benchSinkAny 让接口结果保持可观测。
var benchSinkAny any

// noopHandler is the ydx benchmark handler. | noopHandler 是 ydx 基准处理器。
func noopHandler(context.Context, *yd.Job) error { return nil }

// BenchmarkAddRemove measures one add plus one remove using a pre-parsed
// schedule and a preconstructed handler/definition, in both idle and running
// modes. | BenchmarkAddRemove 用已解析调度与预构造处理器/定义测量一次新增加一次删除，
// 分别覆盖未启动与运行中两种模式。
func BenchmarkAddRemove(b *testing.B) {
	ctx := context.Background()
	b.Run("ydx/idle", func(b *testing.B) {
		scheduler := yd.New(yd.Options{Concurrency: 1, HistoryLimit: -1})
		schedule := yd.MustParseIn("0 0 12 * * *", time.UTC)
		job := &yd.Job{ID: "bench", Schedule: schedule, Handler: noopHandler}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := scheduler.Add(ctx, job); err != nil {
				b.Fatal(err)
			}
			if err := scheduler.Remove(ctx, job.ID); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("robfig/idle", func(b *testing.B) {
		clock := robfig.New()
		schedule, err := robfig.ParseStandard("0 12 * * *")
		if err != nil {
			b.Fatal(err)
		}
		job := robfig.FuncJob(func() {})
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			clock.Remove(clock.Schedule(schedule, job))
		}
	})
	b.Run("gocron/idle", func(b *testing.B) {
		scheduler, err := gocron.NewScheduler()
		if err != nil {
			b.Fatal(err)
		}
		defer func() { _ = scheduler.Shutdown() }()
		definition := gocron.CronJob("0 0 12 * * *", true)
		task := gocron.NewTask(func() {})
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			job, err := scheduler.NewJob(definition, task)
			if err != nil {
				b.Fatal(err)
			}
			if err := scheduler.RemoveJob(job.ID()); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ydx/running", func(b *testing.B) {
		scheduler := yd.New(yd.Options{Concurrency: 1, HistoryLimit: -1})
		schedule := yd.MustParseIn("0 0 12 * * *", time.UTC)
		job := &yd.Job{ID: "bench", Schedule: schedule, Handler: noopHandler}
		if err := scheduler.Start(ctx); err != nil {
			b.Fatal(err)
		}
		defer func() {
			stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = scheduler.Stop(stop)
		}()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := scheduler.Add(ctx, job); err != nil {
				b.Fatal(err)
			}
			if err := scheduler.Remove(ctx, job.ID); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("robfig/running", func(b *testing.B) {
		clock := robfig.New()
		schedule, err := robfig.ParseStandard("0 12 * * *")
		if err != nil {
			b.Fatal(err)
		}
		job := robfig.FuncJob(func() {})
		clock.Start()
		defer clock.Stop()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			clock.Remove(clock.Schedule(schedule, job))
		}
	})
	b.Run("gocron/running", func(b *testing.B) {
		scheduler, err := gocron.NewScheduler()
		if err != nil {
			b.Fatal(err)
		}
		scheduler.Start()
		defer func() { _ = scheduler.Shutdown() }()
		definition := gocron.CronJob("0 0 12 * * *", true)
		task := gocron.NewTask(func() {})
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			job, err := scheduler.NewJob(definition, task)
			if err != nil {
				b.Fatal(err)
			}
			if err := scheduler.RemoveJob(job.ID()); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkAddRemoveWithParse includes expression parsing, matching each
// library's natural add API. | BenchmarkAddRemoveWithParse 包含表达式解析，
// 对应各库自然的新增 API。
func BenchmarkAddRemoveWithParse(b *testing.B) {
	ctx := context.Background()
	b.Run("ydx", func(b *testing.B) {
		scheduler := yd.New(yd.Options{Concurrency: 1, HistoryLimit: -1})
		job := &yd.Job{ID: "bench", Handler: noopHandler}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			schedule, err := yd.ParseIn("0 0 12 * * *", time.UTC)
			if err != nil {
				b.Fatal(err)
			}
			job.Schedule = schedule
			if err := scheduler.Add(ctx, job); err != nil {
				b.Fatal(err)
			}
			if err := scheduler.Remove(ctx, job.ID); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("robfig", func(b *testing.B) {
		clock := robfig.New()
		job := robfig.FuncJob(func() {})
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			schedule, err := robfigSecondsParser.Parse("0 0 12 * * *")
			if err != nil {
				b.Fatal(err)
			}
			clock.Remove(clock.Schedule(schedule, job))
		}
	})
	b.Run("gocron", func(b *testing.B) {
		scheduler, err := gocron.NewScheduler()
		if err != nil {
			b.Fatal(err)
		}
		defer func() { _ = scheduler.Shutdown() }()
		task := gocron.NewTask(func() {})
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			job, err := scheduler.NewJob(gocron.CronJob("0 0 12 * * *", true), task)
			if err != nil {
				b.Fatal(err)
			}
			if err := scheduler.RemoveJob(job.ID()); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// populateYDX adds benchJobs jobs to a ydx scheduler and returns their ids. |
// populateYDX 向 ydx 调度器加入 benchJobs 个任务并返回其 ID。
func populateYDX(b *testing.B) (*yd.Scheduler, []string) {
	b.Helper()
	scheduler := yd.New(yd.Options{Concurrency: 1, HistoryLimit: -1})
	schedule := yd.MustParseIn("0 0 12 * * *", time.UTC)
	ctx := context.Background()
	ids := make([]string, benchJobs)
	for i := 0; i < benchJobs; i++ {
		ids[i] = "job-" + strconv.Itoa(i)
		job := &yd.Job{ID: ids[i], Schedule: schedule, Handler: noopHandler}
		if err := scheduler.Add(ctx, job); err != nil {
			b.Fatal(err)
		}
	}
	return scheduler, ids
}

// populateRobfig adds benchJobs jobs to a robfig cron and returns their ids. |
// populateRobfig 向 robfig cron 加入 benchJobs 个任务并返回其 ID。
func populateRobfig(b *testing.B) (*robfig.Cron, []robfig.EntryID) {
	b.Helper()
	clock := robfig.New()
	schedule, err := robfig.ParseStandard("0 12 * * *")
	if err != nil {
		b.Fatal(err)
	}
	job := robfig.FuncJob(func() {})
	ids := make([]robfig.EntryID, benchJobs)
	for i := 0; i < benchJobs; i++ {
		ids[i] = clock.Schedule(schedule, job)
	}
	return clock, ids
}

// populateGocron adds benchJobs jobs to a gocron scheduler and returns it. |
// populateGocron 向 gocron 调度器加入 benchJobs 个任务并返回它。
func populateGocron(b *testing.B) gocron.Scheduler {
	b.Helper()
	scheduler, err := gocron.NewScheduler()
	if err != nil {
		b.Fatal(err)
	}
	definition := gocron.CronJob("0 0 12 * * *", true)
	task := gocron.NewTask(func() {})
	for i := 0; i < benchJobs; i++ {
		if _, err := scheduler.NewJob(definition, task); err != nil {
			b.Fatal(err)
		}
	}
	return scheduler
}

// BenchmarkList measures one full snapshot of benchJobs jobs. |
// BenchmarkList 测量对 benchJobs 个任务做一次完整快照。
func BenchmarkList(b *testing.B) {
	b.Run("ydx", func(b *testing.B) {
		scheduler, _ := populateYDX(b)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchSinkAny = scheduler.List()
		}
	})
	b.Run("robfig", func(b *testing.B) {
		clock, _ := populateRobfig(b)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchSinkAny = clock.Entries()
		}
	})
	b.Run("gocron", func(b *testing.B) {
		scheduler := populateGocron(b)
		defer func() { _ = scheduler.Shutdown() }()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchSinkAny = scheduler.Jobs()
		}
	})
}

// BenchmarkGet measures one point lookup with benchJobs jobs present. |
// BenchmarkGet 测量存在 benchJobs 个任务时的单点读取。
func BenchmarkGet(b *testing.B) {
	b.Run("ydx", func(b *testing.B) {
		scheduler, ids := populateYDX(b)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			snapshot, ok := scheduler.Get(ids[i%len(ids)])
			if !ok {
				b.Fatal("missing")
			}
			benchSinkAny = snapshot
		}
	})
	b.Run("robfig", func(b *testing.B) {
		clock, ids := populateRobfig(b)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchSinkAny = clock.Entry(ids[i%len(ids)])
		}
	})
}

// BenchmarkGetParallel measures concurrent point lookups. |
// BenchmarkGetParallel 测量并发单点读取。
func BenchmarkGetParallel(b *testing.B) {
	b.Run("ydx", func(b *testing.B) {
		scheduler, ids := populateYDX(b)
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			index := 0
			for pb.Next() {
				snapshot, ok := scheduler.Get(ids[index%len(ids)])
				if !ok {
					b.Error("missing")
				}
				benchSinkAny = snapshot
				index++
			}
		})
	})
	b.Run("robfig", func(b *testing.B) {
		clock, ids := populateRobfig(b)
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			index := 0
			for pb.Next() {
				benchSinkAny = clock.Entry(ids[index%len(ids)])
				index++
			}
		})
	})
}

// BenchmarkStats measures aggregating counters over benchJobs jobs. |
// BenchmarkStats 测量对 benchJobs 个任务汇总计数器。
func BenchmarkStats(b *testing.B) {
	scheduler, _ := populateYDX(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSinkAny = scheduler.Stats()
	}
}

// BenchmarkTrigger measures one manual trigger through to handler completion. |
// BenchmarkTrigger 测量一次手动触发到处理器完成的端到端成本。
func BenchmarkTrigger(b *testing.B) {
	b.Run("ydx", func(b *testing.B) {
		done := make(chan struct{}, 1)
		scheduler := yd.New(yd.Options{Concurrency: 1, HistoryLimit: -1})
		job := &yd.Job{
			ID:       "bench",
			Schedule: yd.Interval(time.Hour),
			Overlap:  yd.AllowOverlap,
			Handler: func(context.Context, *yd.Job) error {
				done <- struct{}{}
				return nil
			},
		}
		ctx := context.Background()
		if err := scheduler.Add(ctx, job); err != nil {
			b.Fatal(err)
		}
		if err := scheduler.Start(ctx); err != nil {
			b.Fatal(err)
		}
		defer func() {
			stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = scheduler.Stop(stop)
		}()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := scheduler.Trigger(job.ID); err != nil {
				b.Fatal(err)
			}
			<-done
		}
	})
	b.Run("gocron", func(b *testing.B) {
		done := make(chan struct{}, 1)
		scheduler, err := gocron.NewScheduler()
		if err != nil {
			b.Fatal(err)
		}
		job, err := scheduler.NewJob(
			gocron.CronJob("0 0 0 1 1 *", true),
			gocron.NewTask(func() { done <- struct{}{} }),
		)
		if err != nil {
			b.Fatal(err)
		}
		scheduler.Start()
		defer func() { _ = scheduler.Shutdown() }()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := job.RunNow(); err != nil {
				b.Fatal(err)
			}
			<-done
		}
	})
}

// BenchmarkTriggerParallel measures concurrent trigger throughput through a
// shared completion channel. | BenchmarkTriggerParallel 测量经共享完成通道的并发触发吞吐。
func BenchmarkTriggerParallel(b *testing.B) {
	done := make(chan struct{}, 64)
	scheduler := yd.New(yd.Options{
		Concurrency:  runtime.GOMAXPROCS(0),
		QueueSize:    1 << 20,
		HistoryLimit: -1,
	})
	job := &yd.Job{
		ID:       "bench",
		Schedule: yd.Interval(time.Hour),
		Overlap:  yd.AllowOverlap,
		Handler: func(context.Context, *yd.Job) error {
			done <- struct{}{}
			return nil
		},
	}
	ctx := context.Background()
	if err := scheduler.Add(ctx, job); err != nil {
		b.Fatal(err)
	}
	if err := scheduler.Start(ctx); err != nil {
		b.Fatal(err)
	}
	defer func() {
		stop, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = scheduler.Stop(stop)
	}()

	var wait sync.WaitGroup
	wait.Add(b.N)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := scheduler.Trigger(job.ID); err != nil {
				b.Error(err)
				wait.Done()
				continue
			}
			<-done
			wait.Done()
		}
	})
	wait.Wait()
}

// BenchmarkHTTPAdmin measures the administrative list, get and stats routes. |
// BenchmarkHTTPAdmin 测量管理 API 的列表、单任务与统计路由。
func BenchmarkHTTPAdmin(b *testing.B) {
	scheduler, ids := populateYDX(b)
	handler := scheduler.HTTPHandler("/cron")
	cases := []struct {
		name string
		path string
	}{
		{name: "list", path: "/cron/jobs"},
		{name: "get", path: "/cron/jobs/" + ids[0]},
		{name: "stats", path: "/cron/stats"},
	}
	for _, tc := range cases {
		tc := tc
		b.Run(tc.name, func(b *testing.B) {
			request := newBenchRequest(tc.path)
			recorder := newBenchRecorder()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				resetBenchRecorder(recorder)
				handler.ServeHTTP(recorder, request)
			}
			benchSinkAny = recorder.Body.Bytes()
		})
	}
}

// newBenchRequest builds one request outside the timed loop. |
// newBenchRequest 在计时区外构建一次请求。
func newBenchRequest(path string) *http.Request {
	return httptest.NewRequest(http.MethodGet, path, nil)
}

// newBenchRecorder builds one reusable recorder. | newBenchRecorder 构建可复用的记录器。
func newBenchRecorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }

// resetBenchRecorder clears the body, status and headers between requests. |
// resetBenchRecorder 在请求之间清空正文、状态码与头。
func resetBenchRecorder(recorder *httptest.ResponseRecorder) {
	recorder.Body.Reset()
	recorder.Code = 0
	header := recorder.Header()
	for key := range header {
		header.Del(key)
	}
}
