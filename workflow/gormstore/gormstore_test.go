package gormstore_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/shibingli/ydx/workflow"
	"github.com/shibingli/ydx/workflow/gormstore"
	gormlib "gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// openTestDB opens a fresh file-backed SQLite database. | openTestDB 打开一个全新的文件型 SQLite 数据库。
func openTestDB(t *testing.T) *gormlib.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "workflow.db") + "?_txlock=immediate&_pragma=busy_timeout(5000)"
	db, err := gormlib.Open(sqlite.Open(dsn), &gormlib.Config{Logger: logger.Discard, TranslateError: true})
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

// TestMigrateIsIdempotentAndTenantFirst covers DDL invariants. | TestMigrateIsIdempotentAndTenantFirst
// 覆盖建表不变量。
func TestMigrateIsIdempotentAndTenantFirst(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if err := gormstore.Migrate(ctx, db); err != nil {
		t.Fatalf("首次迁移失败: %v", err)
	}
	if err := gormstore.Migrate(ctx, db); err != nil {
		t.Fatalf("二次迁移失败: %v", err)
	}
	tables := []string{
		"yd_workflow_definitions", "yd_workflow_versions", "yd_workflow_instances",
		"yd_workflow_tokens", "yd_workflow_tasks", "yd_workflow_events",
		"yd_workflow_tasks", "yd_workflow_task_candidates", "yd_workflow_comments", "yd_workflow_notifications", "yd_workflow_groups",
		"yd_workflow_group_members",
	}
	for _, table := range tables {
		if !db.Migrator().HasTable(table) {
			t.Fatalf("缺少表 %s", table)
		}
		var foreignKeys []struct {
			Table string `gorm:"column:table"`
		}
		if err := db.Raw("PRAGMA foreign_key_list('" + table + "')").Scan(&foreignKeys).Error; err != nil {
			t.Fatalf("读取 %s 外键失败: %v", table, err)
		}
		if len(foreignKeys) != 0 {
			t.Fatalf("%s 存在外键: %+v", table, foreignKeys)
		}
		var indexes []struct {
			Name   string `gorm:"column:name"`
			Unique int    `gorm:"column:unique"`
		}
		if err := db.Raw("PRAGMA index_list('" + table + "')").Scan(&indexes).Error; err != nil {
			t.Fatalf("读取 %s 索引失败: %v", table, err)
		}
		for _, index := range indexes {
			if strings.HasPrefix(index.Name, "sqlite_autoindex") {
				continue
			}
			var columns []struct {
				Name string `gorm:"column:name"`
			}
			if err := db.Raw("PRAGMA index_info('" + index.Name + "')").Scan(&columns).Error; err != nil {
				t.Fatalf("读取索引 %s 失败: %v", index.Name, err)
			}
			if len(columns) == 0 || columns[0].Name != "tenant_id" {
				t.Fatalf("索引 %s 的首列 = %+v, 期望 tenant_id", index.Name, columns)
			}
		}
	}
}

// TestNotificationLeaseIsExclusive covers the multi-node outbox claim. | TestNotificationLeaseIsExclusive
// 覆盖多节点发件箱租约。
func TestNotificationLeaseIsExclusive(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if err := gormstore.Migrate(ctx, db); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	store, err := gormstore.New(db)
	if err != nil {
		t.Fatalf("构建存储失败: %v", err)
	}
	now := time.Now().UTC()
	note := workflow.Notification{
		CreatedAt: now, UpdatedAt: now, NextAttemptAt: now,
		ID: "wfntf_lease", TenantID: "tn", RecipientID: "u1", Kind: workflow.NotifyAssigned,
		Status: workflow.NotificationPending, Title: "t", Body: "b",
	}
	if err := store.CreateNotification(ctx, note); err != nil {
		t.Fatalf("写入通知失败: %v", err)
	}
	first, ok, err := store.ClaimNotification(ctx, "tn", note.ID, now, now.Add(time.Minute))
	if err != nil || !ok || first.ID != note.ID {
		t.Fatalf("首次租约 = %+v %v %v", first, ok, err)
	}
	if _, ok, err := store.ClaimNotification(ctx, "tn", note.ID, now, now.Add(time.Minute)); err != nil || ok {
		t.Fatalf("第二次租约应失败: %v %v", ok, err)
	}
	if _, ok, err := store.ClaimNotification(ctx, "other", note.ID, now, now.Add(time.Minute)); err != nil || ok {
		t.Fatalf("跨租户租约应失败: %v %v", ok, err)
	}
}

// TestTaskFilterActorAndOverdue covers inbox and overdue queries. | TestTaskFilterActorAndOverdue
// 覆盖收件箱与超期查询。
func TestTaskFilterActorAndOverdue(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if err := gormstore.Migrate(ctx, db); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	store, err := gormstore.New(db)
	if err != nil {
		t.Fatalf("构建存储失败: %v", err)
	}
	now := time.Now().UTC()
	tasks := []workflow.Task{
		{
			CreatedAt: now, UpdatedAt: now, DueAt: now.Add(-time.Hour), NextRemindAt: now.Add(-time.Hour),
			ID: "wftsk_1", TenantID: "tn", InstanceID: "wfins_1", TokenID: "wftok_1", NodeID: "a", NodeName: "A",
			AssigneeID: "u1", Status: workflow.TaskPending, Decision: workflow.DecisionNone,
			Candidates: []string{"u1"}, MaxRemind: 3,
		},
		{
			CreatedAt: now, UpdatedAt: now, DueAt: now.Add(time.Hour), NextRemindAt: now.Add(time.Hour),
			ID: "wftsk_2", TenantID: "tn", InstanceID: "wfins_1", TokenID: "wftok_1", NodeID: "a", NodeName: "A",
			Candidates: []string{"u2"}, Status: workflow.TaskPending, Decision: workflow.DecisionNone, MaxRemind: 3,
		},
		{
			CreatedAt: now, UpdatedAt: now, ID: "wftsk_3", TenantID: "other", InstanceID: "wfins_2", TokenID: "wftok_2",
			NodeID: "a", NodeName: "A", AssigneeID: "u1", Status: workflow.TaskPending, Decision: workflow.DecisionNone, MaxRemind: 3,
		},
	}
	for _, task := range tasks {
		if err := store.CreateTask(ctx, task); err != nil {
			t.Fatalf("写入任务失败: %v", err)
		}
	}
	page, total, err := store.ListTasks(ctx, "tn", workflow.TaskFilter{ActorID: "u1", Page: 1, PageSize: 10})
	if err != nil || total != 1 || page[0].ID != "wftsk_1" {
		t.Fatalf("按处理人过滤 = %+v %d %v", page, total, err)
	}
	page, total, err = store.ListTasks(ctx, "tn", workflow.TaskFilter{CandidateID: "u2", Page: 1, PageSize: 10})
	if err != nil || total != 1 || page[0].ID != "wftsk_2" {
		t.Fatalf("按候选池过滤 = %+v %d %v", page, total, err)
	}
	page, total, err = store.ListTasks(ctx, "tn", workflow.TaskFilter{Overdue: true, Page: 1, PageSize: 10})
	if err != nil || total != 1 || page[0].ID != "wftsk_1" {
		t.Fatalf("超期过滤 = %+v %d %v", page, total, err)
	}
	due, err := store.ListDueTasks(ctx, now, 10)
	if err != nil || len(due) != 1 || due[0].ID != "wftsk_1" {
		t.Fatalf("到期催办查询 = %+v %v", due, err)
	}
}

// TestDefinitionMetricsGroupByDefinition covers the grouped counts the definition list uses in
// place of two queries per row. | TestDefinitionMetricsGroupByDefinition 覆盖定义列表用来取代
// 每行两次查询的分组统计。
func TestDefinitionMetricsGroupByDefinition(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if err := gormstore.Migrate(ctx, db); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	store, err := gormstore.New(db)
	if err != nil {
		t.Fatalf("创建存储失败: %v", err)
	}
	now := time.Now().UTC()
	definitions := []workflow.Definition{
		{CreatedAt: now, UpdatedAt: now, ID: "wfdef_a", TenantID: "tn", Key: "a", Name: "A", Status: workflow.DefinitionPublished},
		{CreatedAt: now, UpdatedAt: now, ID: "wfdef_b", TenantID: "tn", Key: "b", Name: "B", Status: workflow.DefinitionDraft},
	}
	for _, definition := range definitions {
		if err := store.CreateDefinition(ctx, definition); err != nil {
			t.Fatalf("写入定义失败: %v", err)
		}
	}
	versions := []workflow.Version{
		{CreatedAt: now, UpdatedAt: now, ID: "wfver_a1", TenantID: "tn", DefinitionID: "wfdef_a", Status: workflow.VersionPublished, Version: 1, Design: "{}"},
		{CreatedAt: now, UpdatedAt: now, ID: "wfver_a2", TenantID: "tn", DefinitionID: "wfdef_a", Status: workflow.VersionDraft, Version: 2, Design: "{}"},
		{CreatedAt: now, UpdatedAt: now, ID: "wfver_other", TenantID: "other", DefinitionID: "wfdef_c", Status: workflow.VersionDraft, Version: 1, Design: "{}"},
	}
	for _, version := range versions {
		if err := store.CreateVersion(ctx, version); err != nil {
			t.Fatalf("写入版本失败: %v", err)
		}
	}
	instances := []workflow.Instance{
		{CreatedAt: now, UpdatedAt: now, StartedAt: now, ID: "wfins_a1", TenantID: "tn", DefinitionID: "wfdef_a", VersionID: "wfver_a1", DefinitionKey: "a", DefinitionName: "A", Title: "one", InitiatorID: "u1", Status: workflow.InstanceRunning, Version: 1},
		{CreatedAt: now, UpdatedAt: now, StartedAt: now, ID: "wfins_a2", TenantID: "tn", DefinitionID: "wfdef_a", VersionID: "wfver_a1", DefinitionKey: "a", DefinitionName: "A", Title: "two", InitiatorID: "u1", Status: workflow.InstanceCompleted, Version: 1},
		{CreatedAt: now, UpdatedAt: now, StartedAt: now, ID: "wfins_other", TenantID: "other", DefinitionID: "wfdef_a", VersionID: "wfver_a1", DefinitionKey: "a", DefinitionName: "A", Title: "other", InitiatorID: "u2", Status: workflow.InstanceRunning, Version: 1},
	}
	for _, instance := range instances {
		if err := store.CreateInstance(ctx, instance); err != nil {
			t.Fatalf("写入实例失败: %v", err)
		}
	}
	versionCounts, err := store.CountVersionsForDefinitions(ctx, "tn", []string{"wfdef_a", "wfdef_b", "wfdef_missing"})
	if err != nil {
		t.Fatalf("统计版本失败: %v", err)
	}
	if versionCounts["wfdef_a"] != 2 || versionCounts["wfdef_b"] != 0 || versionCounts["wfdef_missing"] != 0 {
		t.Fatalf("版本统计 = %+v", versionCounts)
	}
	instanceCounts, err := store.CountInstancesForDefinitions(ctx, "tn", []string{"wfdef_a", "wfdef_b", "wfdef_missing"})
	if err != nil {
		t.Fatalf("统计实例失败: %v", err)
	}
	if instanceCounts["wfdef_a"] != 2 || instanceCounts["wfdef_b"] != 0 || instanceCounts["wfdef_missing"] != 0 {
		t.Fatalf("实例统计 = %+v", instanceCounts)
	}
}

// TestListInstancesLeanOmitsPayloads proves the lean list projection drops the variable and node
// snapshots while the full read still returns them. | TestListInstancesLeanOmitsPayloads 验证精简
// 列表投影省略变量与节点快照，而完整读取仍返回它们。
func TestListInstancesLeanOmitsPayloads(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if err := gormstore.Migrate(ctx, db); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	store, err := gormstore.New(db)
	if err != nil {
		t.Fatalf("创建存储失败: %v", err)
	}
	now := time.Now().UTC()
	instance := workflow.Instance{
		CreatedAt: now, UpdatedAt: now, StartedAt: now,
		ID: "wfins_lean", TenantID: "tn", DefinitionID: "wfdef_a", VersionID: "wfver_a",
		DefinitionKey: "a", DefinitionName: "A", Title: "lean", BusinessKey: "biz",
		Category: "hr", InitiatorID: "u1", InitiatorName: "User", Status: workflow.InstanceRunning,
		Variables: `{"note":"payload"}`, VisitedNodes: `["a"]`, CurrentNodes: `["a"]`, Version: 1,
	}
	if err := store.CreateInstance(ctx, instance); err != nil {
		t.Fatalf("写入实例失败: %v", err)
	}
	lean, total, err := store.ListInstances(ctx, "tn", workflow.InstanceFilter{Page: 1, PageSize: 10, Lean: true})
	if err != nil || total != 1 || len(lean) != 1 {
		t.Fatalf("精简列表 = %+v %d %v", lean, total, err)
	}
	if lean[0].Title != "lean" || lean[0].Category != "hr" || lean[0].Variables != "" || lean[0].VisitedNodes != "" || lean[0].CurrentNodes != "" {
		t.Fatalf("精简列表字段 = %+v", lean[0])
	}
	full, _, err := store.ListInstances(ctx, "tn", workflow.InstanceFilter{Page: 1, PageSize: 10})
	if err != nil || len(full) != 1 || full[0].Variables == "" || full[0].VisitedNodes == "" {
		t.Fatalf("完整列表 = %+v %v", full, err)
	}
}
