package gormstore_test

import (
	"sync"
	"testing"

	"github.com/shibingli/ydx/workflow"
	"gorm.io/gorm/schema"
)

// TestTaskIndexColumnsAreUnique guards the task table against a duplicated index column. MySQL
// rejects CREATE TABLE with "Duplicate column name" when one index lists the same column twice; the
// workflow store then degrades to unavailable and the menu disappears. SQLite tolerates it, so this
// must be checked at the schema level. | TestTaskIndexColumnsAreUnique 防止任务表索引重复列。MySQL 在
// 一个索引重复列出同一列时会以 Duplicate column name 拒绝建表，流程存储随之降级为不可用、菜单消失；
// SQLite 容忍这种写法，因此必须在 schema 层检查。
func TestTaskIndexColumnsAreUnique(t *testing.T) {
	parsed, err := schema.Parse(&workflow.Task{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatalf("解析 Task schema 失败 | parse Task schema: %v", err)
	}
	const target = "idx_wf_task_tenant_assignee_status_created"
	found := false
	for _, index := range parsed.ParseIndexes() {
		seen := make(map[string]struct{}, len(index.Fields))
		for _, field := range index.Fields {
			if field.Field == nil {
				continue
			}
			name := field.DBName
			if _, duplicate := seen[name]; duplicate {
				t.Errorf("索引 %s 重复列 %s；MySQL 会以 Error 1060 拒绝建表 | index %s repeats column %s; MySQL rejects it with Error 1060",
					index.Name, name, index.Name, name)
			}
			seen[name] = struct{}{}
		}
		if index.Name != target {
			continue
		}
		found = true
		if len(seen) != 4 {
			t.Errorf("索引 %s 列数 = %d，期望 4 | index %s has %d columns, want 4", target, len(seen), target, len(seen))
		}
		for _, want := range []string{"tenant_id", "assignee_id", "status", "created_at"} {
			if _, ok := seen[want]; !ok {
				t.Errorf("索引 %s 缺少列 %s | index %s lacks column %s", target, want, target, want)
			}
		}
	}
	if !found {
		t.Fatalf("缺少索引 %s | missing index %s", target, target)
	}
}
