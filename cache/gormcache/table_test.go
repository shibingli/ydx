package gormcache

import (
	"strings"
	"testing"

	"gorm.io/gorm"
	"gorm.io/gorm/callbacks"
	"gorm.io/gorm/clause"
)

// tableFrom builds a DB carrying only the statement fields tableOf reads. | tableFrom
// 构造只带 tableOf 所需语句字段的 DB。
func tableFrom(t *testing.T, st *gorm.Statement) *gorm.DB {
	t.Helper()
	return &gorm.DB{Statement: st}
}

// TestTableOfParsesRealTableName covers alias, schema and fail-closed forms. |
// TestTableOfParsesRealTableName 覆盖别名、schema 与失败关闭形态。
func TestTableOfParsesRealTableName(t *testing.T) {
	p := &Plugin{}
	tests := []struct {
		name  string
		expr  *clause.Expr
		table string
		from  *clause.From
		want  string
	}{
		{name: "alias as", expr: &clause.Expr{SQL: "users AS u"}, table: "u", want: "users"},
		{name: "alias implicit", expr: &clause.Expr{SQL: "users u"}, table: "u", want: "users"},
		{name: "quoted", expr: &clause.Expr{SQL: "`users`"}, table: "users", want: "users"},
		{name: "double quoted", expr: &clause.Expr{SQL: `"users"`}, table: "users", want: "users"},
		{name: "schema qualified", expr: &clause.Expr{SQL: "`main`.`users`"}, table: "users", want: "users"},
		{name: "plain table only", table: "users", want: "users"},
		{name: "from clause", table: "u", from: &clause.From{Tables: []clause.Table{{Name: "roles"}}}, want: "roles"},
		{name: "from multiple", from: &clause.From{Tables: []clause.Table{{Name: "users"}, {Name: "roles"}}}, want: ""},
		{name: "from join", from: &clause.From{Joins: []clause.Join{{Table: clause.Table{Name: "roles"}}}}, want: ""},
		{name: "subquery", expr: &clause.Expr{SQL: "(SELECT * FROM users) AS u"}, table: "u", want: ""},
		{name: "cte", expr: &clause.Expr{SQL: "WITH x AS (SELECT 1) SELECT * FROM x"}, table: "x", want: ""},
		{name: "multi table", expr: &clause.Expr{SQL: "users AS u, roles AS r"}, table: "r", want: ""},
		{name: "join", expr: &clause.Expr{SQL: "users u JOIN roles r ON r.id = u.role_id"}, table: "u", want: ""},
		{name: "malformed alias", expr: &clause.Expr{SQL: "users AS"}, table: "users", want: ""},
		{name: "bind placeholders", expr: &clause.Expr{SQL: "users WHERE id = ?", Vars: []any{1}}, table: "u", want: ""},
		{name: "empty expression", expr: &clause.Expr{SQL: "  "}, table: "u", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := &gorm.Statement{TableExpr: tc.expr, Table: tc.table}
			if tc.from != nil {
				st.Clauses = map[string]clause.Clause{"FROM": {Expression: *tc.from}}
			}
			if got := p.tableOf(tableFrom(t, st)); got != tc.want {
				t.Fatalf("tableOf = %q, 期望 %q", got, tc.want)
			}
		})
	}
}

// TestAliasQueryUsesSensitiveNamespace asserts an aliased query is keyed and
// namespaced by the real table, not by the alias. | TestAliasQueryUsesSensitiveNamespace
// 断言别名查询按真实表名而非别名选择命名空间并生成键。
func TestAliasQueryUsesSensitiveNamespace(t *testing.T) {
	db := openTestDB(t, memoryDSN(t))
	seed(t, db, "a", "b")
	p := install(t, db, newLocalManager(t), func(o *Options) {
		o.SensitiveTables = []string{"cachex_gorm_rows"}
	})

	var rows []cacheRow
	if err := db.Table("cachex_gorm_rows AS r").Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("alias Find: %v | 别名查询失败", err)
	}
	if len(rows) != 2 {
		t.Fatalf("alias Find = %d rows, 期望 2", len(rows))
	}
	stats := p.Stats()
	if stats.Cache.Sets != 0 {
		t.Fatalf("别名查询写入了普通命名空间: %+v", stats.Cache)
	}
	if stats.SensitiveCache.Sets != 1 {
		t.Fatalf("别名查询未写入敏感命名空间: %+v", stats.SensitiveCache)
	}

	rows = nil
	if err := db.Table("cachex_gorm_rows AS r").Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("second alias Find: %v | 第二次别名查询失败", err)
	}
	if hits := p.Stats().SensitiveCache.Hits; hits != 1 {
		t.Fatalf("第二次别名查询敏感命中 = %d, 期望 1", hits)
	}
}

// TestAliasQueryKeyUsesRealTable asserts the query key is prefixed with the real
// table rather than the alias. | TestAliasQueryKeyUsesRealTable 断言查询键以真实表名
// 而不是别名开头。
func TestAliasQueryKeyUsesRealTable(t *testing.T) {
	db := openTestDB(t, memoryDSN(t))
	p := barePlugin()
	var rows []cacheRow
	stmt := db.Session(&gorm.Session{DryRun: true}).Table("cachex_gorm_rows AS r").Where("id = ?", 1).Find(&rows)
	callbacks.BuildQuerySQL(stmt)
	if stmt.Error != nil {
		t.Fatalf("build query: %v", stmt.Error)
	}
	key, ok := p.queryKey(stmt)
	if !ok {
		t.Fatal("queryKey 拒绝了别名查询")
	}
	if !strings.HasPrefix(key, "cachex_gorm_rows:") {
		t.Fatalf("查询键 = %q, 期望以真实表名开头", key)
	}
}

// TestAliasQueryInvalidatedByModelWrite asserts a write through the model
// advances the generation used by the aliased query. | TestAliasQueryInvalidatedByModelWrite
// 断言通过模型写入会推进别名查询使用的代际。
func TestAliasQueryInvalidatedByModelWrite(t *testing.T) {
	db := openTestDB(t, memoryDSN(t))
	seed(t, db, "old")
	install(t, db, newLocalManager(t), nil)

	var rows []cacheRow
	if err := db.Table("cachex_gorm_rows AS r").Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("alias Find: %v | 别名查询失败", err)
	}
	if rows[0].Name != "old" {
		t.Fatalf("首次查询 = %q, 期望 old", rows[0].Name)
	}
	if err := db.Model(&cacheRow{}).Where("id = ?", 1).Update("name", "new").Error; err != nil {
		t.Fatalf("Update: %v | 更新失败", err)
	}
	rows = nil
	if err := db.Table("cachex_gorm_rows AS r").Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("second alias Find: %v | 第二次别名查询失败", err)
	}
	if rows[0].Name != "new" {
		t.Fatalf("别名查询返回陈旧值 %q, 期望 new", rows[0].Name)
	}
}

// TestAliasWriteInvalidatesModelRead asserts a write through an aliased table
// expression advances the generation read by a model query. | TestAliasWriteInvalidatesModelRead
// 断言通过别名表表达式的写入会推进模型查询读取的代际。
func TestAliasWriteInvalidatesModelRead(t *testing.T) {
	db := openTestDB(t, memoryDSN(t))
	seed(t, db, "old")
	install(t, db, newLocalManager(t), nil)

	var rows []cacheRow
	if err := db.Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("model Find: %v", err)
	}
	if rows[0].Name != "old" {
		t.Fatalf("首次查询 = %q, 期望 old", rows[0].Name)
	}
	if err := db.Table("cachex_gorm_rows AS w").Where("id = ?", 1).Update("name", "new").Error; err != nil {
		t.Fatalf("alias Update: %v", err)
	}
	rows = nil
	if err := db.Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("second model Find: %v", err)
	}
	if rows[0].Name != "new" {
		t.Fatalf("模型查询返回陈旧值 %q, 期望 new", rows[0].Name)
	}
}

// TestAliasQueryHonoursIgnoreTables asserts IgnoreTables matches the real table. |
// TestAliasQueryHonoursIgnoreTables 断言 IgnoreTables 按真实表名匹配。
func TestAliasQueryHonoursIgnoreTables(t *testing.T) {
	db := openTestDB(t, memoryDSN(t))
	seed(t, db, "a")
	p := install(t, db, newLocalManager(t), func(o *Options) {
		o.IgnoreTables = []string{"cachex_gorm_rows"}
	})
	var rows []cacheRow
	if err := db.Table("cachex_gorm_rows AS r").Find(&rows).Error; err != nil {
		t.Fatalf("alias Find: %v", err)
	}
	stats := p.Stats()
	if stats.Cache.Sets != 0 || stats.Cache.Hits != 0 || stats.SensitiveCache.Sets != 0 {
		t.Fatalf("被忽略的表进入了缓存: %+v", stats)
	}
}

// TestAliasQueryHonoursAllowlist asserts Tables matches the real table. |
// TestAliasQueryHonoursAllowlist 断言 Tables 按真实表名匹配。
func TestAliasQueryHonoursAllowlist(t *testing.T) {
	db := openTestDB(t, memoryDSN(t))
	seed(t, db, "a")
	p := install(t, db, newLocalManager(t), func(o *Options) {
		o.Tables = []string{"cachex_gorm_rows"}
	})
	var rows []cacheRow
	if err := db.Table("cachex_gorm_rows AS r").Find(&rows).Error; err != nil {
		t.Fatalf("alias Find: %v", err)
	}
	if sets := p.Stats().Cache.Sets; sets != 1 {
		t.Fatalf("白名单别名查询写入 = %d, 期望 1", sets)
	}
}

// TestUnparseableTableExpressionSkipsCache asserts a subquery cannot be cached
// under a guessed table name. | TestUnparseableTableExpressionSkipsCache 断言无法
// 可靠解析的子查询不会被猜测表名后缓存。
func TestUnparseableTableExpressionSkipsCache(t *testing.T) {
	db := openTestDB(t, memoryDSN(t))
	seed(t, db, "a")
	p := install(t, db, newLocalManager(t), nil)
	var rows []cacheRow
	err := db.Table("(SELECT * FROM cachex_gorm_rows) AS r").Find(&rows).Error
	if err != nil {
		t.Fatalf("subquery Find: %v", err)
	}
	stats := p.Stats()
	if stats.Cache.Sets != 0 || stats.Cache.Hits != 0 || stats.SensitiveCache.Sets != 0 {
		t.Fatalf("无法解析的表表达式进入了缓存: %+v", stats)
	}
}
