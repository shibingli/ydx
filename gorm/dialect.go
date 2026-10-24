package gorm

// Dialect capabilities and cross-dialect SQL helpers. | 方言能力与跨方言 SQL 辅助函数。
//
// GORM already hides most dialect differences behind its dialector, but a few features differ in
// support or spelling and cannot be expressed portably without a branch: JSON extraction, case-
// insensitive matching, row locking, random ordering and string concatenation. This file names
// those differences once, per dialect, and builds the corresponding GORM expressions so callers do
// not have to switch on the driver name themselves. | GORM 已把多数方言差异藏在 dialector 之后，
// 但仍有少数能力在支持与否或拼写方式上不同，无法不使用分支就可移植地表达：JSON 取值、大小写
// 不敏感匹配、行锁、随机排序与字符串拼接。本文件按方言把差异只声明一次，并构造对应的 GORM
// 表达式，调用方无需自行按驱动名分支。

import (
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/shibingli/ydx/errs"
)

// ErrDialectFeature indicates that the selected dialect does not support the requested SQL
// feature. | ErrDialectFeature 表示所选方言不支持请求的 SQL 能力。
var ErrDialectFeature = errs.New("gormx: dialect does not support the feature | gormx：方言不支持该能力")

// Features is a bit set of optional SQL capabilities whose support differs between dialects. |
// Features 是不同方言间支持情况不同的可选 SQL 能力位集。
type Features uint32

const (
	// FeatureReturning marks dialects whose INSERT/UPDATE/DELETE can return rows. | FeatureReturning
	// 标记 INSERT/UPDATE/DELETE 能返回行的方言。
	FeatureReturning Features = 1 << iota
	// FeatureJSON marks dialects with built-in JSON path extraction. | FeatureJSON 标记内置 JSON
	// 路径取值的方言。
	FeatureJSON
	// FeatureRowLock marks dialects that support SELECT ... FOR UPDATE / FOR SHARE. | FeatureRowLock
	// 标记支持 SELECT ... FOR UPDATE / FOR SHARE 的方言。
	FeatureRowLock
	// FeatureILike marks dialects with a native case-insensitive LIKE operator. | FeatureILike
	// 标记原生提供大小写不敏感 LIKE 运算符的方言。
	FeatureILike
	// FeatureSavepoint marks dialects that support savepoints. | FeatureSavepoint 标记支持保存点的方言。
	FeatureSavepoint
	// FeatureCTE marks dialects that support common table expressions. | FeatureCTE 标记支持公共表表达式的方言。
	FeatureCTE
	// FeatureWindow marks dialects that support window functions. | FeatureWindow 标记支持窗口函数的方言。
	FeatureWindow
	// FeatureMergeUpsert marks dialects whose upsert is implemented as MERGE rather than
	// ON CONFLICT / ON DUPLICATE KEY. | FeatureMergeUpsert 标记以 MERGE 而非
	// ON CONFLICT / ON DUPLICATE KEY 实现 upsert 的方言。
	FeatureMergeUpsert
)

// Has reports whether every bit in want is present. | Has 报告 want 中的每个位是否都存在。
func (f Features) Has(want Features) bool { return f&want == want }

// Dialect is the SQL dialect behind one driver name, together with the capabilities and SQL
// spellings that GORM cannot hide. | Dialect 是一个驱动名背后的 SQL 方言，以及 GORM 无法隐藏的
// 能力与 SQL 拼写。
type Dialect struct {
	// Driver is the canonical driver name (mysql, postgres, sqlite or dm). | Driver 是规范驱动名。
	Driver string
	// DisplayName is the human-readable DBMS name used in logs and generated docs. | DisplayName
	// 是用于日志与生成文档的可读数据库名。
	DisplayName string
	// Features is the set of optional capabilities the dialect supports. | Features 是方言支持的
	// 可选能力集合。
	Features Features
	// RandomFunc is the SQL function that yields a random value suitable for ORDER BY. | RandomFunc
	// 是可用于 ORDER BY 的随机函数。
	RandomFunc string
	// ConcatFunc is "CONCAT" when concatenation is a function and "" when the dialect uses the
	// || operator. | ConcatFunc 在拼接是函数时为 "CONCAT"，使用 || 运算符时为空串。
	ConcatFunc string
}

// dialectCatalog is the single table describing every supported dialect. | dialectCatalog 是描述
// 所有受支持方言的唯一表。
//
// MySQL's CTE and window-function bits assume 8.0+, which is the version GORM itself targets;
// earlier 5.7 servers reject both syntaxes. DM has no RETURNING support in the GORM dialect (insert
// IDs come from the driver), so that bit is deliberately absent. | MySQL 的 CTE 与窗口函数位按
// 8.0+ 标记，这也是 GORM 自身的目标版本；更早的 5.7 服务端会拒绝这两种语法。达梦的 GORM 方言
// 不支持 RETURNING（插入 ID 由驱动取回），因此刻意不标记该位。
var dialectCatalog = map[string]Dialect{
	DriverMySQL: {
		Driver:      DriverMySQL,
		DisplayName: "MySQL",
		Features:    FeatureSavepoint | FeatureCTE | FeatureWindow | FeatureRowLock | FeatureJSON,
		RandomFunc:  "RAND()",
		ConcatFunc:  "CONCAT",
	},
	DriverPostgres: {
		Driver:      DriverPostgres,
		DisplayName: "PostgreSQL",
		Features: FeatureReturning | FeatureJSON | FeatureRowLock | FeatureILike |
			FeatureSavepoint | FeatureCTE | FeatureWindow,
		RandomFunc: "random()",
	},
	DriverSQLite: {
		Driver:      DriverSQLite,
		DisplayName: "SQLite",
		Features:    FeatureReturning | FeatureJSON | FeatureSavepoint | FeatureCTE | FeatureWindow,
		RandomFunc:  "random()",
	},
	DriverDM: {
		Driver:      DriverDM,
		DisplayName: "达梦 DM8 | Dameng DM8",
		Features:    FeatureSavepoint | FeatureCTE | FeatureWindow | FeatureRowLock | FeatureMergeUpsert,
		RandomFunc:  "RAND()",
	},
}

// DialectFor returns the dialect for a driver name, reading aliases exactly as dialectorFor does.
// | DialectFor 返回驱动名对应的方言，别名读法与 dialectorFor 一致。
func DialectFor(driver string) (Dialect, error) {
	kind := driverKind(driver)
	if kind == "" {
		return Dialect{}, errs.Detail(ErrUnsupportedDriver,
			"driver %q is not one of mysql/postgres/sqlite/dm | 驱动 %q 不在 mysql/postgres/sqlite/dm 之列",
			driver, driver)
	}
	return dialectCatalog[kind], nil
}

// Upsert builds the conflict clause for an INSERT ... ON CONFLICT style statement. GORM translates
// it per dialect: MySQL emits ON DUPLICATE KEY UPDATE, PostgreSQL and SQLite emit ON CONFLICT, and
// the Dameng dialect rewrites it to MERGE INTO. | Upsert 构造 INSERT ... ON CONFLICT 风格的冲突子句。
// GORM 会按方言翻译：MySQL 生成 ON DUPLICATE KEY UPDATE，PostgreSQL 与 SQLite 生成 ON CONFLICT，
// 达梦方言改写为 MERGE INTO。
//
// conflictColumns are the key columns that identify a duplicate (ignored by MySQL and used as the
// MERGE join key by Dameng); updateColumns are overwritten on conflict. | conflictColumns 是判定
// 重复的键列（MySQL 忽略它，达梦把它用作 MERGE 的连接键）；updateColumns 在冲突时被覆盖。
func Upsert(conflictColumns, updateColumns []string) clause.OnConflict {
	onConflict := clause.OnConflict{}
	for _, name := range conflictColumns {
		onConflict.Columns = append(onConflict.Columns, clause.Column{Name: name})
	}
	for _, name := range updateColumns {
		onConflict.DoUpdates = append(onConflict.DoUpdates, clause.Assignment{
			Column: clause.Column{Name: name},
			Value:  clause.Column{Table: "excluded", Name: name},
		})
	}
	return onConflict
}

// UpsertDoNothing returns a conflict clause that leaves the existing row untouched. | UpsertDoNothing
// 返回保留既有行不变的冲突子句。
func UpsertDoNothing(conflictColumns []string) clause.OnConflict {
	onConflict := Upsert(conflictColumns, nil)
	onConflict.DoNothing = true
	return onConflict
}

// JSONExtract returns an expression that reads a JSON path as text. The path uses the MySQL/SQLite
// form such as "$.user.name"; PostgreSQL receives the equivalent #>> path array. | JSONExtract 返回
// 把 JSON 路径读为文本的表达式。路径采用 MySQL/SQLite 的 "$.user.name" 形式；PostgreSQL 收到等价
// 的 #>> 路径数组。
func (d Dialect) JSONExtract(column, path string) (clause.Expr, error) {
	if !d.Features.Has(FeatureJSON) {
		return clause.Expr{}, errs.Detail(ErrDialectFeature,
			"%s has no built-in JSON path extraction | %s 没有内置 JSON 路径取值", d.DisplayName, d.DisplayName)
	}
	col := clause.Column{Name: column}
	if d.Driver == DriverPostgres {
		return clause.Expr{SQL: "? #>> ?", Vars: []any{col, postgresJSONPath(path)}}, nil
	}
	return clause.Expr{SQL: "JSON_EXTRACT(?, ?)", Vars: []any{col, path}}, nil
}

// postgresJSONPath converts "$.a.b" into PostgreSQL's "{a,b}" array literal form. | postgresJSONPath
// 把 "$.a.b" 转换为 PostgreSQL 的 "{a,b}" 数组字面量形式。
//
// Unsupported forms are passed through unchanged so the database reports the error instead of this
// helper silently dropping a path segment. | 不支持的形式原样传递，让数据库报错，而不是让本辅助
// 函数悄悄丢弃路径段。
func postgresJSONPath(path string) string {
	if !strings.HasPrefix(path, "$.") {
		return path
	}
	parts := strings.Split(strings.TrimPrefix(path, "$."), ".")
	for i, part := range parts {
		if part == "" || part == "*" {
			return path
		}
		parts[i] = `"` + strings.ReplaceAll(part, `"`, `\"`) + `"`
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// Random returns the dialect's random function expression, for example ORDER BY Random(). |
// Random 返回方言的随机函数表达式，例如 ORDER BY Random()。
func (d Dialect) Random() clause.Expr { return clause.Expr{SQL: d.RandomFunc} }

// ILike builds a case-insensitive LIKE comparison. PostgreSQL uses its native ILIKE; the other
// dialects compare the lowercased forms, which works regardless of collation. | ILike 构造大小写
// 不敏感的 LIKE 比较。PostgreSQL 使用原生 ILIKE；其它方言比较小写形式，不受排序规则影响。
func (d Dialect) ILike(column, pattern string) clause.Expression {
	col := clause.Column{Name: column}
	if d.Features.Has(FeatureILike) {
		return clause.Expr{SQL: "? ILIKE ?", Vars: []any{col, pattern}}
	}
	return clause.Expr{SQL: "LOWER(?) LIKE LOWER(?)", Vars: []any{col, pattern}}
}

// Concat builds string concatenation from column names. MySQL uses CONCAT(...); PostgreSQL,
// SQLite and Dameng use the || operator. | Concat 用列名构造字符串拼接。MySQL 使用 CONCAT(...)；
// PostgreSQL、SQLite 与达梦使用 || 运算符。
func (d Dialect) Concat(columns ...string) clause.Expression {
	if len(columns) == 0 {
		return clause.Expr{SQL: "''"}
	}
	args := make([]any, 0, len(columns))
	placeholders := make([]string, 0, len(columns))
	for _, name := range columns {
		args = append(args, clause.Column{Name: name})
		placeholders = append(placeholders, "?")
	}
	if d.ConcatFunc != "" {
		return clause.Expr{SQL: d.ConcatFunc + "(" + strings.Join(placeholders, ", ") + ")", Vars: args}
	}
	return clause.Expr{SQL: "(" + strings.Join(placeholders, " || ") + ")", Vars: args}
}

// LockStrength selects the row-lock mode for LockClause. | LockStrength 选择 LockClause 的行锁模式。
type LockStrength uint8

const (
	// LockUpdate is SELECT ... FOR UPDATE. | LockUpdate 是 SELECT ... FOR UPDATE。
	LockUpdate LockStrength = iota
	// LockShare is SELECT ... FOR SHARE. | LockShare 是 SELECT ... FOR SHARE。
	LockShare
)

// LockClause returns the GORM locking clause for the dialect. SQLite has no row-level locking, so
// it reports ErrDialectFeature instead of silently dropping the request. | LockClause 返回方言对应的
// GORM 行锁子句。SQLite 没有行级锁，因此返回 ErrDialectFeature，而不是悄悄丢弃请求。
func (d Dialect) LockClause(strength LockStrength) (clause.Locking, error) {
	if !d.Features.Has(FeatureRowLock) {
		return clause.Locking{}, errs.Detail(ErrDialectFeature,
			"%s has no row-level locking | %s 没有行级锁", d.DisplayName, d.DisplayName)
	}
	locking := clause.Locking{Strength: "UPDATE"}
	if strength == LockShare {
		locking.Strength = "SHARE"
	}
	return locking, nil
}

// Now returns the dialect's current-timestamp expression. All four dialects accept the SQL
// standard CURRENT_TIMESTAMP. | Now 返回方言的当前时间表达式。四种方言都接受 SQL 标准的
// CURRENT_TIMESTAMP。
func (d Dialect) Now() clause.Expr { return clause.Expr{SQL: "CURRENT_TIMESTAMP"} }

// IsZero reports whether the dialect was not initialized. | IsZero 报告方言是否为零值。
func (d Dialect) IsZero() bool { return d.Driver == "" }

// DialectOf returns the dialect of an open connection, so helpers follow the actual dialector
// rather than a separately passed driver name. | DialectOf 返回已打开连接的方言，使辅助函数跟随
// 真实 dialector，而不是另传一个驱动名。
func DialectOf(db *gorm.DB) (Dialect, error) {
	if db == nil || db.Dialector == nil {
		return Dialect{}, errs.Detail(ErrNilDB, "dialect lookup | 方言查询")
	}
	return DialectFor(db.Dialector.Name())
}
