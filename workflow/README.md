# workflow — 可独立使用的工作流引擎 | A standalone workflow engine

`github.com/shibingli/ydx/workflow` 是一个**不依赖 Web 框架、不依赖具体页面**的 Go 工作流引擎，
实现了 BPMN 2.0 的可执行子集与中国式审批语义。yd 生成的项目的流程模块只是在它之上加了页面、
JSON API、权限守卫、配置装配与调度器接线。

- **领域与存储分离**：`workflow` 只定义类型、规则、引擎与 `Store` 接口；GORM 实现在
  [`gormstore`](gormstore)，覆盖 ydx/gorm 支持的 MySQL、PostgreSQL、SQLite 与达梦 DM8。
- **没有隐藏状态**：单机与多机跑同一份代码，调度、催办、通知投递都通过数据库条件更新领取，
  任意数量的副本可以同时运行。
- **失败关闭**：表达式求值错误、AI 低置信度、未知规则都不构成“自动通过”。
- **零 CGO**：纯 Go，静态链接。

## 安装 | Install

```bash
go get github.com/shibingli/ydx/workflow
go get github.com/shibingli/ydx/workflow/gormstore
go get github.com/shibingli/ydx/workflow/notify
go get github.com/shibingli/ydx/workflow/ai
```

## 快速开始 | Quick start

```go
package main

import (
    "context"
    "log"

    "github.com/shibingli/ydx/workflow"
    "github.com/shibingli/ydx/workflow/gormstore"
    "gorm.io/gorm"
)

func main() {
    db, err := gorm.Open( /* 任意 ydx/gorm 支持的方言 */ )
    if err != nil {
        log.Fatal(err)
    }
    ctx := context.Background()
    if err := gormstore.Migrate(ctx, db); err != nil {
        log.Fatal(err)
    }
    store, err := gormstore.New(db)
    if err != nil {
        log.Fatal(err)
    }
    svc, err := workflow.New(store, workflow.Deps{
        Directory: myDirectory{}, // 实现 workflow.Directory：解析用户与角色成员
        Logger:    myLogger{},
        Options:   workflow.DefaultOptions(),
    })
    if err != nil {
        log.Fatal(err)
    }
    _ = svc
}
```

`Directory` 是引擎与身份系统之间唯一的边界：

```go
type Directory interface {
    User(ctx context.Context, tenantID, userID string) (Assignee, error)
    Users(ctx context.Context, tenantID string, userIDs []string) ([]Assignee, error)
    UsersByRole(ctx context.Context, tenantID, role string) ([]Assignee, error)
}
```

## 定义、版本与设计

```go
def, err := svc.CreateDefinition(ctx, tenantID, actorID, workflow.DefinitionInput{
    Key: "leave", Name: "请假申请", Category: "hr",
})
ver, err := svc.CreateVersion(ctx, tenantID, def.ID, actorID, workflow.VersionInput{
    Design: workflow.Design{
        SchemaVersion: 1,
        Nodes: []workflow.Node{
            {ID: "start_1", Type: workflow.NodeStart, Name: "开始", Position: workflow.Position{X: 80, Y: 200}},
            {ID: "user_1", Type: workflow.NodeUserTask, Name: "主管审批",
                Position: workflow.Position{X: 280, Y: 180},
                Assignee: workflow.Assignment{Type: workflow.AssigneeInitiator, Claim: workflow.ClaimAssigned},
                Completion: workflow.Completion{Mode: workflow.CompletionAny}},
            {ID: "end_1", Type: workflow.NodeEnd, Name: "结束", Position: workflow.Position{X: 560, Y: 200}},
        },
        Edges: []workflow.Edge{
            {ID: "edge_1", Source: "start_1", Target: "user_1"},
            {ID: "edge_2", Source: "user_1", Target: "end_1"},
        },
    },
})
_, err = svc.PublishVersion(ctx, tenantID, ver.ID, actorID, "v1")
```

- 节点类型：`start`、`end`、`user`、`service`、`exclusive`、`parallel`、`inclusive`、`catch`、`event`。
- 完成方式：`any`（或签）、`all`（会签）、`vote`（票签；`threshold_type` 为 `count` 或 `percent`）。
- 指派：`user`、`role`、`group`、`initiator`；签收方式 `assigned` / `claim` / `grab`。
- 表单：`Design.Forms["start"]` 是发起表单，`Design.Forms[nodeID]` 是审批任务表单。
- 自动规则：`Design.Rules`，作用域 `category` / `role` / `user` / `group` / `event` / `variable`。
- 条件表达式：安全递归下降求值器（`==`、`!=`、`>`、`<`、`contains`、`in`、`&&`、`||`、`!`），
  不使用 `eval`，有深度与长度上限。

## 运行时

```go
inst, err := svc.Start(ctx, tenantID, actor, workflow.StartInput{
    DefinitionKey: "leave",
    Title:         "请假两天",
    FormData:      map[string]any{"days": 2},
})

tasks, err := svc.ListTasks(ctx, tenantID, workflow.TaskFilter{
    ActorID: actor.ID, Statuses: []string{workflow.TaskPending, workflow.TaskClaimed},
})

task, err := svc.Approve(ctx, tenantID, actor, tasks.Items[0].ID, workflow.ActionInput{
    Decision: workflow.DecisionApprove, Comment: "同意",
})

err = svc.WithdrawInstance(ctx, tenantID, actor, inst.ID, workflow.ReasonInput{Reason: "填错了"})
```

完整动作：`Claim`、`Transfer`、`Delegate`、`AddSign`、`RemoveSign`、`Return`、`WithdrawInstance`、
`TerminateInstance`、`Remind`、`AddComment`、`Signal`。

## 调度器

```go
scheduler := workflow.NewScheduler(svc, 30*time.Second, logger)
if err := scheduler.Start(ctx); err != nil { ... }
defer scheduler.Stop(10 * time.Second)
```

调度器负责：到期催办、通知 outbox 投递、定时捕获事件与超时处理。它由 `ydx/cron` 的调度器驱动：
工作流侧只注册一个固定间隔任务调用 `Service.RunDue`，不自带定时循环。多副本同时运行是安全的，
每条记录通过条件更新领取；`Stop` 幂等并带有界等待。

默认情况下工作流创建一个私有 cron 调度器。若应用已有自己的 cron 调度器，可把扫描任务挂上去，
避免同一进程出现两个调度循环：

```go
shared := cron.New(cron.Options{Concurrency: 1, QueueSize: 1, HistoryLimit: -1})
scheduler := workflow.NewScheduler(svc, 30*time.Second, logger, workflow.WithCronScheduler(shared))

_ = shared.Start(ctx)          // 共享调度器的生命周期由应用负责
if err := scheduler.Start(ctx); err != nil { ... } // 只添加扫描任务
defer scheduler.Stop(10 * time.Second)             // 只移除扫描任务
_ = shared.Stop(ctx)
```

实例与多节点语义：

- 私有实例与应用的其它 cron 实例互不干扰：堆、工作池、`Store`/`Locker` 都是独立的，
  `workflow-scan` 只存在于该私有实例中；应用即使同时直接使用 `ydx/cron`，也是各用各的。
- 共享实例上不要配置 `Store`：`Reload` 会按 Store 内容重建任务表，并丢弃内存中的扫描任务。
  多个流程服务共享同一实例时，用 `workflow.WithScanJobID` 指定不同的任务 ID。
- 每个节点都可以运行扫描器：到期项通过数据库条件更新领取，不会重复处理；共享实例且配置了
  `Locker` 时，扫描任务还带 `Singleton`，每个周期只有一个节点扫描。
- 取消传给 `Start` 的上下文不会停止共享实例；调用 `Stop` 卸载任务即可。

## 通知

```go
webhook, err := notify.NewWebhook(notify.WebhookOptions{URL: url, Kind: notify.KindDingTalk, Secret: secret})
if err != nil { ... }
smtp, err := notify.NewSMTP(notify.SMTPOptions{Host: "smtp.example.com", Port: 587, From: "noreply@example.com"})
if err != nil { ... }
dispatcher := workflow.NewDispatcher(5*time.Second, &notify.LogChannel{}, webhook, smtp)
svc.SetDispatcher(dispatcher)
```

通知先写 `yd_workflow_notifications`，再由调度器领取投递；通道失败只告警，不回滚审批事务。

## AI 决策

```go
decider, err := ai.New(ai.Options{
    Enabled:       true,
    Provider:      ai.ProviderAnthropic, // 或 ProviderOpenAI / ProviderOpenAIResponses
    BaseURL:       "https://api.anthropic.com",
    APIKey:        os.Getenv("ANTHROPIC_API_KEY"),
    Model:         "claude-sonnet-5-5",
    MaxTokens:     512,
    Timeout:       20 * time.Second,
    MinConfidence: 0.7,
})
if err != nil { ... }
svc.SetDecider(decider)
```

规则需要 `UseAI=true`，节点需要 `AllowAuto=true`。未配置、HTTP 失败、非法 JSON 或低置信度都保持人工审批。
决策器在数据库事务之外运行：引擎先回滚并释放行锁，再调用决策器，随后用缓存答案重放事务，
因此外部调用的延迟不会阻塞其它流程动作。

## BPMN 与导入导出

```go
bundle, err := svc.ExportBundle(ctx, tenantID, []string{"leave"})
report, err := svc.ImportBundle(ctx, tenantID, actorID, bundle)
xmlDoc, err := workflow.BuildBPMN(def, ver.Version, design)
process, err := workflow.ParseBPMN(xmlDoc)
def2, ver2, err := svc.ImportBPMN(ctx, tenantID, actorID, process)
```

写出包含 BPMN DI 坐标与 Camunda 扩展属性；YD 专有字段写在 `extensionElements` 的 JSON 中，
导入时可无损往返。导入按校验和幂等。

## 存储

`gormstore.Migrate` 幂等创建 `yd_workflow_*` 表（无外键、全部以 `tenant_id` 打头建索引）。
`gormstore.New(db)` 返回 `workflow.Store` 实现；任何自定义后端只需实现 `workflow.Store`。

多副本要求：

- 所有副本连接同一个数据库；
- SQLite 使用文件库并保留 `_txlock=immediate`（不要加 `_time_format`）；
- 每个副本的节点身份唯一（见 `ydx/nodeid`）。

## 性能 | Performance

运行期的热点路径做了三处有界缓存与多处查询收窄：

- **已发布版本缓存**：最多 128 个版本、约 16 MiB，按 `tenant_id + version_id` 保存已解析设计；
  发布版本不可变，缓存无需跨节点失效。`Start` 仍实时读取最新发布指针，命中缓存时只查主键。
- **条件 AST 缓存**：最多 512 条表达式，边条件与变量规则命中后不再解析。
- **设计索引**：解析时预计算节点表、出/入邻接与按优先级排序的规则；运行期零拷贝遍历。
- `refreshCurrentNodes` 只查 waiting 令牌（命中 `(tenant_id, instance_id, status)` 索引）。
- 单条任务读取不重复投影实例；详情抽屉复用已读实例。列表初始容量上限 32，空结果不预分配。
- 版本列表走 `VersionSummary` 轻量投影，工作台/版本抽屉/设计器/API 列表不再加载全部历史设计；
  单版本读取才返回完整设计。
- 定义列表的版本数与实例数由两条分组查询一次填充（`CountVersionsForDefinitions` /
  `CountInstancesForDefinitions`），取代每行各查两次；未实现该可选扩展的自定义 Store 自动回退。
- 实例列表使用精简投影，省略变量与节点快照载荷；完整变量只在实例详情读取。
- 普通动作不再查询定义行：定义只在 AI 决策需要时惰性加载，其余逻辑使用实例与版本快照。
- 概览统计每张表一条条件聚合查询。
- AI 决策器在事务之外调用，失败关闭；输入指纹不序列化设计/BPMN 串。

## 测试

```bash
go test ./... -race
```

覆盖：设计校验、表达式、BPMN 往返、或签/会签/票签/顺序审批、加签/减签、转办/委派、退回/撤回/终止、
定时与消息事件、事件网关、自动规则、AI 三种协议、Webhook 签名、SMTP、并发抢单、多副本调度、
租户隔离与导入导出。

## 许可证

Apache-2.0。
