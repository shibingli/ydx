package gorm_test

import (
	"errors"
	"testing"

	"gorm.io/gorm/clause"

	frameworkgorm "github.com/shibingli/ydx/gorm"
)

// TestDialectForResolvesEveryDriver verifies the driver-to-dialect mapping, including aliases and
// the unsupported-name error. | TestDialectForResolvesEveryDriver 验证驱动到方言的映射，包括别名
// 与不支持名称的错误。
func TestDialectForResolvesEveryDriver(t *testing.T) {
	cases := map[string]string{
		"mysql":    "MySQL",
		"postgres": "PostgreSQL",
		"sqlite":   "SQLite",
		"dm":       "达梦 DM8 | Dameng DM8",
		"Dameng":   "达梦 DM8 | Dameng DM8",
	}
	for driver, want := range cases {
		d, err := frameworkgorm.DialectFor(driver)
		if err != nil {
			t.Fatalf("DialectFor(%q) failed | 解析失败: %v", driver, err)
		}
		if d.DisplayName != want {
			t.Fatalf("DialectFor(%q).DisplayName = %q, want %q | 方言名不符", driver, d.DisplayName, want)
		}
	}
	if _, err := frameworkgorm.DialectFor("oracle"); !errors.Is(err, frameworkgorm.ErrUnsupportedDriver) {
		t.Fatalf("DialectFor(oracle) error = %v, want ErrUnsupportedDriver | 未拒绝未知驱动", err)
	}
}

// TestDialectFeatures verifies the capability matrix that the helpers branch on. |
// TestDialectFeatures 验证辅助函数据以分支的能力矩阵。
func TestDialectFeatures(t *testing.T) {
	cases := []struct {
		driver string
		want   frameworkgorm.Features
		absent frameworkgorm.Features
	}{
		{"mysql", frameworkgorm.FeatureJSON | frameworkgorm.FeatureRowLock, frameworkgorm.FeatureReturning | frameworkgorm.FeatureILike},
		{"postgres", frameworkgorm.FeatureReturning | frameworkgorm.FeatureJSON | frameworkgorm.FeatureILike | frameworkgorm.FeatureRowLock, 0},
		{"sqlite", frameworkgorm.FeatureReturning | frameworkgorm.FeatureJSON, frameworkgorm.FeatureRowLock | frameworkgorm.FeatureILike},
		{"dm", frameworkgorm.FeatureRowLock | frameworkgorm.FeatureMergeUpsert, frameworkgorm.FeatureReturning | frameworkgorm.FeatureJSON},
	}
	for _, tc := range cases {
		d, err := frameworkgorm.DialectFor(tc.driver)
		if err != nil {
			t.Fatalf("DialectFor(%q) failed | 解析失败: %v", tc.driver, err)
		}
		if !d.Features.Has(tc.want) {
			t.Fatalf("%s lacks features %b | %s 缺少能力 %b", tc.driver, tc.want, tc.driver, tc.want)
		}
		if tc.absent != 0 && d.Features.Has(tc.absent) {
			t.Fatalf("%s should not advertise %b | %s 不应宣称能力 %b", tc.driver, tc.absent, tc.driver, tc.absent)
		}
	}
}

// TestDialectExpressions verifies the SQL spelling of the portable helpers. |
// TestDialectExpressions 验证可移植辅助函数的 SQL 拼写。
func TestDialectExpressions(t *testing.T) {
	sqlite, _ := frameworkgorm.DialectFor("sqlite")
	mysql, _ := frameworkgorm.DialectFor("mysql")
	postgres, _ := frameworkgorm.DialectFor("postgres")
	dm, _ := frameworkgorm.DialectFor("dm")

	if got := sqlite.Random().SQL; got != "random()" {
		t.Fatalf("sqlite random = %q | SQLite 随机函数不符", got)
	}
	if got := dm.Random().SQL; got != "RAND()" {
		t.Fatalf("dm random = %q | 达梦随机函数不符", got)
	}

	if expr, err := postgres.JSONExtract("payload", "$.user.name"); err != nil {
		t.Fatalf("postgres JSONExtract failed | PostgreSQL JSON 取值失败: %v", err)
	} else if expr.SQL != "? #>> ?" || len(expr.Vars) != 2 || expr.Vars[1] != `{"user","name"}` {
		t.Fatalf("postgres JSONExtract = %#v | PostgreSQL JSON 取值不符", expr)
	}
	if expr, err := mysql.JSONExtract("payload", "$.user.name"); err != nil {
		t.Fatalf("mysql JSONExtract failed | MySQL JSON 取值失败: %v", err)
	} else if expr.SQL != "JSON_EXTRACT(?, ?)" || expr.Vars[1] != "$.user.name" {
		t.Fatalf("mysql JSONExtract = %#v | MySQL JSON 取值不符", expr)
	}
	if _, err := dm.JSONExtract("payload", "$.user.name"); !errors.Is(err, frameworkgorm.ErrDialectFeature) {
		t.Fatalf("dm JSONExtract error = %v, want ErrDialectFeature | 达梦应拒绝 JSON 取值", err)
	}

	if expr := postgres.ILike("name", "ann%"); expr.(clause.Expr).SQL != "? ILIKE ?" {
		t.Fatalf("postgres ILike = %#v | PostgreSQL 大小写不敏感匹配不符", expr)
	}
	if expr := mysql.ILike("name", "ann%"); expr.(clause.Expr).SQL != "LOWER(?) LIKE LOWER(?)" {
		t.Fatalf("mysql ILike = %#v | MySQL 大小写不敏感匹配不符", expr)
	}

	if expr := mysql.Concat("first", "last"); expr.(clause.Expr).SQL != "CONCAT(?, ?)" {
		t.Fatalf("mysql Concat = %#v | MySQL 拼接不符", expr)
	}
	if expr := postgres.Concat("first", "last"); expr.(clause.Expr).SQL != "(? || ?)" {
		t.Fatalf("postgres Concat = %#v | PostgreSQL 拼接不符", expr)
	}
	if expr := dm.Concat("first", "last"); expr.(clause.Expr).SQL != "(? || ?)" {
		t.Fatalf("dm Concat = %#v | 达梦拼接不符", expr)
	}
}

// TestDialectLocking verifies row-lock construction and SQLite's explicit rejection. |
// TestDialectLocking 验证行锁构造与 SQLite 的显式拒绝。
func TestDialectLocking(t *testing.T) {
	mysql, _ := frameworkgorm.DialectFor("mysql")
	if locking, err := mysql.LockClause(frameworkgorm.LockUpdate); err != nil || locking.Strength != "UPDATE" {
		t.Fatalf("mysql LockUpdate = %#v, %v | MySQL 行锁不符", locking, err)
	}
	if locking, err := mysql.LockClause(frameworkgorm.LockShare); err != nil || locking.Strength != "SHARE" {
		t.Fatalf("mysql LockShare = %#v, %v | MySQL 共享锁不符", locking, err)
	}
	sqlite, _ := frameworkgorm.DialectFor("sqlite")
	if _, err := sqlite.LockClause(frameworkgorm.LockUpdate); !errors.Is(err, frameworkgorm.ErrDialectFeature) {
		t.Fatalf("sqlite LockClause error = %v, want ErrDialectFeature | SQLite 应拒绝行锁", err)
	}
}

// TestUpsertClauses verifies the portable conflict clause shape used by every dialect. |
// TestUpsertClauses 验证各方言共用的冲突子句形态。
func TestUpsertClauses(t *testing.T) {
	onConflict := frameworkgorm.Upsert([]string{"tenant_id", "name"}, []string{"updated_at"})
	if len(onConflict.Columns) != 2 || onConflict.Columns[1].Name != "name" {
		t.Fatalf("Upsert columns = %#v | 冲突列不符", onConflict.Columns)
	}
	if len(onConflict.DoUpdates) != 1 || onConflict.DoUpdates[0].Column.Name != "updated_at" {
		t.Fatalf("Upsert updates = %#v | 更新列不符", onConflict.DoUpdates)
	}
	assignment, ok := onConflict.DoUpdates[0].Value.(clause.Column)
	if !ok || assignment.Table != "excluded" || assignment.Name != "updated_at" {
		t.Fatalf("Upsert assignment = %#v | 冲突赋值未指向 excluded", onConflict.DoUpdates[0].Value)
	}
	if !frameworkgorm.UpsertDoNothing([]string{"id"}).DoNothing {
		t.Fatal("UpsertDoNothing did not set DoNothing | 未设置 DoNothing")
	}
}

// TestDialectOfNilDB verifies the documented nil-database failure. | TestDialectOfNilDB 验证文档化的
// nil 数据库失败路径。
func TestDialectOfNilDB(t *testing.T) {
	if _, err := frameworkgorm.DialectOf(nil); !errors.Is(err, frameworkgorm.ErrNilDB) {
		t.Fatalf("DialectOf(nil) error = %v, want ErrNilDB | nil 数据库未返回哨兵", err)
	}
}
