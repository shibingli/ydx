package cron

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// TestMemoryStore covers copy semantics, replacement and deletion. |
// TestMemoryStore 覆盖复制语义、替换与删除。
func TestMemoryStore(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	definition := Definition{
		ID:         "alpha",
		Name:       "alpha",
		Task:       "tick",
		Expression: "0 0 * * *",
		Metadata:   map[string]string{"key": "value"},
	}
	if err := store.Save(ctx, definition); err != nil {
		t.Fatalf("Save: %v | 保存失败", err)
	}
	definition.Metadata["key"] = "mutated"
	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v | 列举失败", err)
	}
	if len(list) != 1 || list[0].Metadata["key"] != "value" {
		t.Fatalf("stored definition was aliased: %+v | 存储内容被别名修改", list)
	}
	list[0].Metadata["key"] = "mutated"
	again, _ := store.List(ctx)
	if again[0].Metadata["key"] != "value" {
		t.Fatalf("returned definition was aliased | 返回内容被别名修改")
	}

	replacement := definition
	replacement.Name = "renamed"
	replacement.Metadata = nil
	if err := store.Save(ctx, replacement); err != nil {
		t.Fatalf("Save replacement: %v | 替换失败", err)
	}
	list, _ = store.List(ctx)
	if len(list) != 1 || list[0].Name != "renamed" {
		t.Fatalf("replacement not applied: %+v | 替换未生效", list)
	}

	if err := store.Delete(ctx, "alpha"); err != nil {
		t.Fatalf("Delete: %v | 删除失败", err)
	}
	if err := store.Delete(ctx, "missing"); err != nil {
		t.Fatalf("Delete(missing) = %v, want nil | 删除不存在项应无错误", err)
	}
	list, _ = store.List(ctx)
	if len(list) != 0 {
		t.Fatalf("List after Delete = %+v | 删除后仍存在", list)
	}

	if err := store.Save(ctx, Definition{Expression: "0 0 * * *"}); !errors.Is(err, ErrInvalidDefinition) {
		t.Fatalf("Save(empty id) = %v, want ErrInvalidDefinition | 空 ID 错误不符", err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := store.Save(cancelled, definition); err == nil {
		t.Fatal("Save with cancelled context returned nil | 取消上下文未报错")
	}
}

// TestSchedulerStorePersistence verifies definitions survive a restart and
// lifecycle changes write through the store. | TestSchedulerStorePersistence 验证定义跨重启
// 保留，且生命周期变更写穿存储。
func TestSchedulerStorePersistence(t *testing.T) {
	store := NewMemoryStore()
	var calls atomic.Int32
	handler := func(context.Context, *Job) error {
		calls.Add(1)
		return nil
	}

	first := New(Options{Store: store, Concurrency: 1, HistoryLimit: -1})
	if err := first.Register("tick", handler); err != nil {
		t.Fatalf("Register: %v | 注册失败", err)
	}
	job := &Job{Task: "tick", Name: "persisted", Schedule: Interval(10 * time.Millisecond)}
	if err := first.Add(context.Background(), job); err != nil {
		t.Fatalf("Add: %v | 新增失败", err)
	}
	definitions, _ := store.List(context.Background())
	if len(definitions) != 1 || definitions[0].Expression == "" {
		t.Fatalf("stored definitions = %+v | 存储定义不符", definitions)
	}
	if err := first.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v | 启动失败", err)
	}
	waitFor(t, 2*time.Second, func() bool { return calls.Load() >= 1 }, "first scheduler did not run | 首个调度器未运行")
	stopScheduler(t, first)

	second := New(Options{Store: store, Concurrency: 1, HistoryLimit: -1})
	if err := second.Register("tick", handler); err != nil {
		t.Fatalf("Register: %v | 注册失败", err)
	}
	if err := second.Start(context.Background()); err != nil {
		t.Fatalf("restore Start: %v | 恢复启动失败", err)
	}
	if _, ok := second.Get(job.ID); !ok {
		t.Fatalf("job %q was not restored | 任务未恢复", job.ID)
	}
	waitFor(t, 2*time.Second, func() bool { return calls.Load() >= 2 }, "restored job did not run | 恢复的任务未运行")

	if err := second.Pause(context.Background(), job.ID); err != nil {
		t.Fatalf("Pause: %v | 暂停失败", err)
	}
	definitions, _ = store.List(context.Background())
	if len(definitions) != 1 || !definitions[0].Disabled {
		t.Fatalf("pause was not persisted: %+v | 暂停状态未持久化", definitions)
	}

	job.Name = "renamed"
	if err := second.Update(context.Background(), job); err != nil {
		t.Fatalf("Update: %v | 更新失败", err)
	}
	definitions, _ = store.List(context.Background())
	if definitions[0].Name != "renamed" {
		t.Fatalf("update was not persisted: %+v | 更新未持久化", definitions)
	}

	if err := second.Remove(context.Background(), job.ID); err != nil {
		t.Fatalf("Remove: %v | 删除失败", err)
	}
	definitions, _ = store.List(context.Background())
	if len(definitions) != 0 {
		t.Fatalf("remove was not persisted: %+v | 删除未持久化", definitions)
	}
	stopScheduler(t, second)
}

// failingStore reports errors for every operation. | failingStore 对每个操作返回错误。
type failingStore struct{ listErr error }

func (f failingStore) Save(context.Context, Definition) error { return errors.New("save failed") }
func (f failingStore) Delete(context.Context, string) error   { return errors.New("delete failed") }
func (f failingStore) List(context.Context) ([]Definition, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return nil, errors.New("list failed")
}

// TestStoreFailures verifies store errors are declared and mutations do not
// pretend to succeed. | TestStoreFailures 验证存储错误被声明，且变更不会假装成功。
func TestStoreFailures(t *testing.T) {
	sch := New(Options{Store: failingStore{}})
	if err := sch.Register("tick", func(context.Context, *Job) error { return nil }); err != nil {
		t.Fatalf("Register: %v | 注册失败", err)
	}
	job := &Job{Task: "tick", Schedule: Interval(time.Hour)}
	if err := sch.Add(context.Background(), job); !errors.Is(err, ErrStoreFailed) {
		t.Fatalf("Add = %v, want ErrStoreFailed | 存储失败错误不符", err)
	}
	if _, ok := sch.Get(job.ID); ok {
		t.Fatal("job exists after failed store write | 存储失败后任务仍存在")
	}

	listErr := errors.New("database down")
	sch = New(Options{Store: failingStore{listErr: listErr}})
	if err := sch.Start(context.Background()); !errors.Is(err, ErrStoreFailed) {
		t.Fatalf("Start = %v, want ErrStoreFailed | 启动时存储错误不符", err)
	}
}

// TestRestoreRequiresHandler verifies a missing registration fails startup. |
// TestRestoreRequiresHandler 验证缺少注册处理器时启动失败。
func TestRestoreRequiresHandler(t *testing.T) {
	store := NewMemoryStore()
	if err := store.Save(context.Background(), Definition{
		ID:         "good",
		Task:       "tick",
		Expression: "0 0 * * *",
	}); err != nil {
		t.Fatalf("Save: %v | 保存失败", err)
	}
	if err := store.Save(context.Background(), Definition{
		ID:         "orphan",
		Task:       "missing",
		Expression: "0 0 * * *",
	}); err != nil {
		t.Fatalf("Save: %v | 保存失败", err)
	}
	sch := New(Options{Store: store})
	if err := sch.Register("tick", func(context.Context, *Job) error { return nil }); err != nil {
		t.Fatalf("Register: %v | 注册失败", err)
	}
	err := sch.Start(context.Background())
	if !errors.Is(err, ErrHandlerNotFound) {
		t.Fatalf("Start = %v, want ErrHandlerNotFound | 缺少处理器错误不符", err)
	}
	if _, ok := sch.Get("good"); ok {
		t.Fatal("a valid definition was applied before validation finished | 校验完成前应用了有效定义")
	}
	if err := sch.Stop(context.Background()); err != nil {
		t.Fatalf("Stop after failed Start = %v | 启动失败后停止出错", err)
	}
}

// TestDefinitionRoundTrip keeps time zone and schedule semantics across
// serialization. | TestDefinitionRoundTrip 保证序列化前后时区与调度语义一致。
func TestDefinitionRoundTrip(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatalf("LoadLocation: %v | 加载时区失败", err)
	}
	schedule, err := ParseIn("30 8 * * *", loc)
	if err != nil {
		t.Fatalf("ParseIn: %v | 解析失败", err)
	}
	job := &Job{
		ID:       "tz",
		Name:     "timezone",
		Task:     "tick",
		Schedule: schedule,
		Metadata: map[string]string{"env": "test"},
		Timeout:  time.Minute,
		Retries:  2,
		Overlap:  AllowOverlap,
	}
	definition := job.Definition()
	if definition.Timezone != loc.String() {
		t.Fatalf("Timezone = %q, want %q | 时区字段不符", definition.Timezone, loc.String())
	}
	restored, err := definition.Schedule()
	if err != nil {
		t.Fatalf("Schedule: %v | 重建调度失败", err)
	}
	after := utc(2026, time.January, 1, 0, 0, 0)
	if a, b := schedule.Next(after), restored.Next(after); !a.Equal(b) {
		t.Fatalf("round trip: %s != %s | 序列化前后结果不符", a, b)
	}

	if _, err := (Definition{Expression: "not a schedule"}).Schedule(); !errors.Is(err, ErrInvalidDefinition) {
		t.Fatalf("invalid expression error = %v, want ErrInvalidDefinition | 非法表达式错误不符", err)
	}
	if _, err := (Definition{Expression: "0 0 * * *", Timezone: "Nope/Zone"}).Schedule(); !errors.Is(err, ErrInvalidDefinition) {
		t.Fatalf("invalid time zone error = %v, want ErrInvalidDefinition | 非法时区错误不符", err)
	}
}

// TestReload synchronizes a running scheduler with definitions written by
// another node. | TestReload 验证运行中的调度器同步其它节点写入的定义。
func TestReload(t *testing.T) {
	store := NewMemoryStore()
	var runs atomic.Int32
	sch := New(Options{Store: store, Concurrency: 1, HistoryLimit: -1})
	if err := sch.Register("tick", func(context.Context, *Job) error {
		runs.Add(1)
		return nil
	}); err != nil {
		t.Fatalf("Register: %v | 注册失败", err)
	}
	if err := sch.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v | 启动失败", err)
	}

	definition := Definition{ID: "remote", Task: "tick", Expression: "@every 10ms"}
	if err := store.Save(context.Background(), definition); err != nil {
		t.Fatalf("remote Save: %v | 远端保存失败", err)
	}
	if err := sch.Reload(context.Background()); err != nil {
		t.Fatalf("Reload add: %v | 同步新增失败", err)
	}
	if _, ok := sch.Get("remote"); !ok {
		t.Fatal("added definition was not applied | 新增定义未生效")
	}
	waitFor(t, 2*time.Second, func() bool { return runs.Load() >= 1 }, "reloaded job did not run | 同步的任务未运行")

	definition.Disabled = true
	if err := store.Save(context.Background(), definition); err != nil {
		t.Fatalf("remote Save: %v | 远端保存失败", err)
	}
	if err := sch.Reload(context.Background()); err != nil {
		t.Fatalf("Reload pause: %v | 同步暂停失败", err)
	}
	snapshot, _ := sch.Get("remote")
	if !snapshot.Disabled {
		t.Fatal("remote pause was not applied | 远端暂停未生效")
	}

	if err := store.Delete(context.Background(), "remote"); err != nil {
		t.Fatalf("remote Delete: %v | 远端删除失败", err)
	}
	if err := sch.Reload(context.Background()); err != nil {
		t.Fatalf("Reload remove: %v | 同步删除失败", err)
	}
	if _, ok := sch.Get("remote"); ok {
		t.Fatal("removed definition still exists | 删除的定义仍存在")
	}
	stopScheduler(t, sch)
}

// TestReloadValidation verifies a bad definition aborts the whole reload. |
// TestReloadValidation 验证一条非法定义会中止整次同步。
func TestReloadValidation(t *testing.T) {
	store := NewMemoryStore()
	sch := New(Options{Store: store})
	if err := store.Save(context.Background(), Definition{
		ID:         "orphan",
		Task:       "missing",
		Expression: "0 0 * * *",
	}); err != nil {
		t.Fatalf("Save: %v | 保存失败", err)
	}
	if err := sch.Reload(context.Background()); !errors.Is(err, ErrHandlerNotFound) {
		t.Fatalf("Reload = %v, want ErrHandlerNotFound | 非法定义错误不符", err)
	}
	if _, ok := sch.Get("orphan"); ok {
		t.Fatal("invalid definition was partially applied | 非法定义被部分应用")
	}

	withoutStore := New(Options{})
	if err := withoutStore.Reload(context.Background()); !errors.Is(err, ErrNoStore) {
		t.Fatalf("Reload without Store = %v, want ErrNoStore | 缺少 Store 错误不符", err)
	}
}

// TestStoreRequiresTask verifies persisted jobs must name a task. |
// TestStoreRequiresTask 验证持久化任务必须提供任务名。
func TestStoreRequiresTask(t *testing.T) {
	sch := New(Options{Store: NewMemoryStore()})
	job := &Job{Schedule: Interval(time.Hour), Handler: func(context.Context, *Job) error { return nil }}
	if err := sch.Add(context.Background(), job); !errors.Is(err, ErrEmptyTask) {
		t.Fatalf("Add = %v, want ErrEmptyTask | 缺少任务名错误不符", err)
	}
}
