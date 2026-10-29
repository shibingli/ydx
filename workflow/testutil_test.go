package workflow_test

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/shibingli/ydx/workflow"
	"github.com/shibingli/ydx/workflow/gormstore"
	gormlib "gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// testClock is a controllable UTC clock. | testClock 是可控制的 UTC 时钟。
type testClock struct {
	// mu guards now. | mu 保护 now。
	mu sync.Mutex
	// now is the current instant. | now 是当前时刻。
	now time.Time
}

// Now returns the current instant. | Now 返回当前时刻。
func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward. | Advance 向前推进时钟。
func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fakeDirectory resolves users and roles from an in-memory table. | fakeDirectory 从内存表解析用户与角色。
type fakeDirectory struct {
	// users maps id and username onto the same assignee. | users 把 ID 与用户名映射到同一个审批人。
	users map[string]workflow.Assignee
}

// User returns one assignee by id or username. | User 按 ID 或用户名返回审批人。
func (d *fakeDirectory) User(_ context.Context, _ string, userID string) (workflow.Assignee, error) {
	if user, ok := d.users[userID]; ok {
		return user, nil
	}
	return workflow.Assignee{}, workflow.ErrNotFound
}

// Users resolves a batch. | Users 批量解析。
func (d *fakeDirectory) Users(_ context.Context, _ string, userIDs []string) ([]workflow.Assignee, error) {
	out := make([]workflow.Assignee, 0, len(userIDs))
	for _, id := range userIDs {
		if user, ok := d.users[id]; ok {
			out = append(out, user)
		}
	}
	return out, nil
}

// UsersByRole returns every user holding role. | UsersByRole 返回持有角色的全部用户。
func (d *fakeDirectory) UsersByRole(_ context.Context, _ string, role string) ([]workflow.Assignee, error) {
	out := make([]workflow.Assignee, 0, 4)
	for _, user := range d.users {
		for _, held := range user.Roles {
			if held == role {
				out = append(out, user)
				break
			}
		}
	}
	return out, nil
}

// recordingChannel keeps every delivered notification. | recordingChannel 保存全部已投递通知。
type recordingChannel struct {
	// mu guards notes. | mu 保护 notes。
	mu sync.Mutex
	// notes are the delivered notifications. | notes 是已投递通知。
	notes []workflow.Notification
	// failures makes the next calls fail. | failures 让接下来的调用失败。
	failures int
}

// Name returns the channel name. | Name 返回渠道名。
func (c *recordingChannel) Name() string { return "memory" }

// Send records one notification. | Send 记录一条通知。
func (c *recordingChannel) Send(_ context.Context, note workflow.Notification) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failures > 0 {
		c.failures--
		return workflow.ErrNotificationFailed
	}
	c.notes = append(c.notes, note)
	return nil
}

// count returns the number of delivered notifications. | count 返回已投递通知数量。
func (c *recordingChannel) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.notes)
}

// txProbeStore records whether a transaction callback is currently running and counts transactions. |
// txProbeStore 记录事务回调是否正在执行，并统计事务次数。
type txProbeStore struct {
	workflow.Store
	// mu guards depth and transactions. | mu 保护 depth 与 transactions。
	mu sync.Mutex
	// depth is the number of active WithTx callbacks. | depth 是活动 WithTx 回调数量。
	depth int
	// transactions counts completed and active WithTx calls. | transactions 统计已完成与活动中的 WithTx 调用。
	transactions int
}

// WithTx marks the callback scope and delegates. | WithTx 标记回调作用域后委派执行。
func (s *txProbeStore) WithTx(ctx context.Context, fn func(workflow.Store) error) error {
	s.mu.Lock()
	s.depth++
	s.transactions++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.depth--
		s.mu.Unlock()
	}()
	return s.Store.WithTx(ctx, fn)
}

// inTx reports whether a transaction callback is active. | inTx 报告是否有事务回调正在执行。
func (s *txProbeStore) inTx() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.depth > 0
}

// count returns the number of WithTx calls seen. | count 返回已观察到的 WithTx 调用次数。
func (s *txProbeStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transactions
}

// fixture is one isolated service backed by SQLite. | fixture 是一个由 SQLite 支撑的隔离服务。
type fixture struct {
	// svc is the workflow service. | svc 是流程服务。
	svc *workflow.Service
	// store is the persistence layer. | store 是持久化层。
	store workflow.Store
	// db is the raw database. | db 是原始数据库。
	db *gormlib.DB
	// dir resolves users. | dir 解析用户。
	dir *fakeDirectory
	// clock controls time. | clock 控制时间。
	clock *testClock
	// channel records notifications. | channel 记录通知。
	channel *recordingChannel
	// tenant is the test tenant. | tenant 是测试租户。
	tenant string
}

// newFixture builds one isolated service. | newFixture 构建一个隔离服务。
func newFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixtureWithStore(t, nil)
}

// newFixtureWithStore builds a fixture and lets the caller decorate the store. |
// newFixtureWithStore 构建 fixture，并允许调用方装饰存储。
func newFixtureWithStore(t *testing.T, wrap func(workflow.Store) workflow.Store) *fixture {
	t.Helper()
	name := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	dsn := fmt.Sprintf("file:%s?_txlock=immediate&_pragma=busy_timeout(5000)", filepath.Join(t.TempDir(), name+".db"))
	db, err := gormlib.Open(sqlite.Open(dsn), &gormlib.Config{
		Logger:         logger.Discard,
		TranslateError: true,
	})
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	if err := gormstore.Migrate(context.Background(), db); err != nil {
		t.Fatalf("迁移测试数据库失败: %v", err)
	}
	base, err := gormstore.New(db)
	if err != nil {
		t.Fatalf("构建流程存储失败: %v", err)
	}
	var store workflow.Store = base
	if wrap != nil {
		store = wrap(store)
	}
	clock := &testClock{now: time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)}
	dir := &fakeDirectory{users: map[string]workflow.Assignee{
		"u1":   {ID: "u1", Name: "User One", Email: "u1@example.com", Roles: []string{"staff"}},
		"u2":   {ID: "u2", Name: "User Two", Email: "u2@example.com", Roles: []string{"staff"}},
		"u3":   {ID: "u3", Name: "User Three", Email: "u3@example.com", Roles: []string{"manager"}},
		"boss": {ID: "boss", Name: "Boss", Email: "boss@example.com", Roles: []string{"admin"}},
	}}
	channel := &recordingChannel{}
	svc, err := workflow.New(store, workflow.Deps{
		Directory:  dir,
		Dispatcher: workflow.NewDispatcher(time.Second, channel),
		Options: workflow.Options{
			Now: clock.Now,
		},
		Notify: workflow.NotificationOptions{Lang: "en"},
	})
	if err != nil {
		t.Fatalf("构建流程服务失败: %v", err)
	}
	return &fixture{svc: svc, store: store, db: db, dir: dir, clock: clock, channel: channel, tenant: "tn_test"}
}

// close closes the database. | close 关闭数据库。
func (f *fixture) close() {
	if sqlDB, err := f.db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}

// actor returns the standard test actor. | actor 返回标准测试操作人。
func actor(id string) workflow.Actor {
	return workflow.Actor{ID: id, Name: id}
}

// adminActor returns an administrative test actor. | adminActor 返回管理员测试操作人。
func adminActor() workflow.Actor {
	return workflow.Actor{ID: "boss", Name: "Boss", Admin: true}
}

// startNode builds the single start event. | startNode 构建唯一起始事件。
func startNode() workflow.Node {
	return workflow.Node{ID: "start", Type: workflow.NodeStart, Name: "开始 | Start", Position: workflow.Position{X: 60, Y: 200}}
}

// endNode builds one end event. | endNode 构建一个结束事件。
func endNode(id string) workflow.Node {
	return workflow.Node{ID: id, Type: workflow.NodeEnd, Name: "结束 | End", Position: workflow.Position{X: 700, Y: 200}}
}

// userNode builds one user task. | userNode 构建一个用户任务。
func userNode(id, name string, assignee workflow.Assignment, completion workflow.Completion) workflow.Node {
	if assignee.Claim == "" {
		assignee.Claim = workflow.ClaimAssigned
	}
	if completion.Mode == "" {
		completion.Mode = workflow.CompletionAny
	}
	return workflow.Node{
		ID: id, Type: workflow.NodeUserTask, Name: name,
		Assignee: assignee, Completion: completion, OnReject: workflow.OnRejectTerminate,
		Position: workflow.Position{X: 240, Y: 200}, AllowAuto: true,
	}
}

// edge builds one sequence flow. | edge 构建一条顺序流。
func edge(id, source, target, condition string) workflow.Edge {
	return workflow.Edge{ID: id, Source: source, Target: target, Condition: condition}
}

// linearDesign builds start → one user task → end. | linearDesign 构建开始 → 一个用户任务 → 结束。
func linearDesign(assignee workflow.Assignment, completion workflow.Completion) workflow.Design {
	design := workflow.DefaultDesign()
	design.Nodes = []workflow.Node{
		startNode(),
		userNode("approve", "审批 | Approve", assignee, completion),
		endNode("end"),
	}
	design.Edges = []workflow.Edge{
		edge("e1", "start", "approve", ""),
		edge("e2", "approve", "end", ""),
	}
	return design
}

// publishDefinition creates, versions and publishes one definition. | publishDefinition 创建、建版本并发布一个定义。
func (f *fixture) publishDefinition(t *testing.T, key string, design workflow.Design) (workflow.Definition, workflow.Version) {
	t.Helper()
	ctx := context.Background()
	def, err := f.svc.CreateDefinition(ctx, f.tenant, "boss", workflow.DefinitionInput{
		Key: key, Name: key + " 流程", Category: "leave",
	})
	if err != nil {
		t.Fatalf("创建定义失败: %v", err)
	}
	version, err := f.svc.CreateVersion(ctx, f.tenant, def.ID, "boss", workflow.VersionInput{Design: design})
	if err != nil {
		t.Fatalf("创建版本失败: %v", err)
	}
	published, err := f.svc.PublishVersion(ctx, f.tenant, version.ID, "boss", "首次发布")
	if err != nil {
		t.Fatalf("发布版本失败: %v", err)
	}
	return def, published
}

// start starts one instance of a published definition. | start 发起一个已发布定义的实例。
func (f *fixture) start(t *testing.T, key string, variables map[string]any) workflow.Instance {
	t.Helper()
	inst, err := f.svc.Start(context.Background(), f.tenant, actor("u1"), workflow.StartInput{
		DefinitionKey: key, Title: "测试实例", Variables: variables,
	})
	if err != nil {
		t.Fatalf("发起流程失败: %v", err)
	}
	return inst
}

// listTasks returns every task of one instance. | listTasks 返回实例的全部任务。
func (f *fixture) listTasks(t *testing.T, instanceID string) []workflow.Task {
	t.Helper()
	page, err := f.svc.ListTasks(context.Background(), f.tenant, workflow.TaskFilter{InstanceID: instanceID, Page: 1, PageSize: 100})
	if err != nil {
		t.Fatalf("列出任务失败: %v", err)
	}
	return page.Items
}

// openTasks returns the pending and claimed tasks of one instance. | openTasks 返回实例的待处理与已签收任务。
func (f *fixture) openTasks(t *testing.T, instanceID string) []workflow.Task {
	t.Helper()
	out := make([]workflow.Task, 0, 4)
	for _, task := range f.listTasks(t, instanceID) {
		if task.Status == workflow.TaskPending || task.Status == workflow.TaskClaimed {
			out = append(out, task)
		}
	}
	return out
}

// taskFor returns the open task assigned to user. | taskFor 返回指派给用户的未结束任务。
func (f *fixture) taskFor(t *testing.T, instanceID, userID string) workflow.Task {
	t.Helper()
	for _, task := range f.openTasks(t, instanceID) {
		if task.AssigneeID == userID {
			return task
		}
	}
	t.Fatalf("实例 %s 没有指派给 %s 的未结束任务: %+v", instanceID, userID, f.listTasks(t, instanceID))
	return workflow.Task{}
}

// approve approves or rejects one task. | approve 通过或驳回一条任务。
func (f *fixture) approve(t *testing.T, userID, taskID, decision string) workflow.Task {
	t.Helper()
	task, err := f.svc.Approve(context.Background(), f.tenant, actor(userID), taskID, workflow.ActionInput{
		Decision: decision, Comment: "测试意见 | test comment",
	})
	if err != nil {
		t.Fatalf("处理任务失败: %v", err)
	}
	return task
}

// instance reloads one instance. | instance 重新读取一个实例。
func (f *fixture) instance(t *testing.T, id string) workflow.Instance {
	t.Helper()
	inst, err := f.svc.GetInstance(context.Background(), f.tenant, id)
	if err != nil {
		t.Fatalf("读取实例失败: %v", err)
	}
	return inst
}
