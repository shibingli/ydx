package gormcache

import (
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// tableOf returns the physical table name, or "" when it cannot be parsed
// reliably. | tableOf 返回物理表名；无法可靠解析时返回空串。
//
// GORM stores the alias in Statement.Table for "users AS u", so the table
// expression is parsed first; a subquery, CTE, join or comma-separated table
// list is rejected instead of caching under a guessed name. | GORM 对
// "users AS u" 会把别名写进 Statement.Table，因此优先解析表表达式；子查询、CTE、
// JOIN 或逗号分隔的多表一律拒绝，而不是按猜测的表名缓存。
func (p *Plugin) tableOf(db *gorm.DB) string {
	if db == nil || db.Statement == nil {
		return ""
	}
	st := db.Statement
	if table, decided := tableFromClause(st); decided {
		return table
	}
	if st.TableExpr != nil {
		switch expr := any(st.TableExpr).(type) {
		case *clause.Expr:
			if expr == nil || len(expr.Vars) > 0 {
				return ""
			}
			table, ok := parseTableExpression(expr.SQL)
			if !ok {
				return ""
			}
			return table
		case *clause.Table:
			if expr == nil {
				return ""
			}
			table, ok := tableName(expr.Name)
			if !ok {
				return ""
			}
			return table
		default:
			// An unknown expression form cannot be parsed safely. | 未知表达式形态无法安全解析。
			return ""
		}
	}
	if st.Table != "" {
		table, ok := tableName(st.Table)
		if !ok {
			return ""
		}
		return table
	}
	if st.Schema != nil {
		table, ok := tableName(st.Schema.Table)
		if !ok {
			return ""
		}
		return table
	}
	return ""
}

// tableFromClause returns a concrete FROM table. The second result reports
// whether the FROM clause decided the outcome; false means the caller should
// fall back to the table expression. | tableFromClause 返回 FROM 子句中的具体表。
// 第二个结果表示 FROM 子句是否已决定结果；false 表示调用方应回退到表表达式。
func tableFromClause(st *gorm.Statement) (string, bool) {
	if st.Clauses == nil {
		return "", false
	}
	from, ok := st.Clauses["FROM"].Expression.(clause.From)
	if !ok || len(from.Tables) == 0 {
		return "", false
	}
	if len(from.Tables) > 1 || len(from.Joins) > 0 {
		return "", true
	}
	name := from.Tables[0].Name
	if name == "" || name == clause.CurrentTable {
		return "", false
	}
	table, ok := tableName(name)
	if !ok {
		return "", true
	}
	return table, true
}

// parseTableExpression extracts a single physical table from a raw FROM
// expression. | parseTableExpression 从原始 FROM 表达式提取单个物理表。
func parseTableExpression(sql string) (string, bool) {
	tokens, ok := splitTableTokens(sql)
	if !ok || len(tokens) == 0 {
		return "", false
	}
	if !quotedTableToken(tokens[0]) && sqlKeyword(tokens[0]) {
		return "", false
	}
	switch len(tokens) {
	case 1:
		return tableName(tokens[0])
	case 2:
		if sqlKeyword(tokens[1]) {
			return "", false
		}
		if _, ok := tableName(tokens[1]); !ok {
			return "", false
		}
		return tableName(tokens[0])
	case 3:
		if !strings.EqualFold(tokens[1], "AS") || sqlKeyword(tokens[2]) {
			return "", false
		}
		if _, ok := tableName(tokens[2]); !ok {
			return "", false
		}
		return tableName(tokens[0])
	default:
		return "", false
	}
}

// splitTableTokens splits a table expression on whitespace outside quoted
// identifiers. Parentheses, commas and semicolons mean the expression is not a
// single table and are rejected. | splitTableTokens 在引号标识符之外按空白切分表
// 表达式。括号、逗号与分号表示不是单表，直接拒绝。
func splitTableTokens(sql string) ([]string, bool) {
	var tokens []string
	start := -1
	var quote byte
	for i := 0; i < len(sql); i++ {
		c := sql[i]
		if quote != 0 {
			if i+1 < len(sql) && sql[i+1] == closingQuote(quote) && c == closingQuote(quote) {
				i++
				continue
			}
			if c == closingQuote(quote) {
				quote = 0
			}
			continue
		}
		switch c {
		case '`', '"', '[':
			quote = c
			if start < 0 {
				start = i
			}
		case '(', ')', ',', ';':
			return nil, false
		case ' ', '\t', '\r', '\n':
			if start >= 0 {
				tokens = append(tokens, sql[start:i])
				start = -1
			}
		default:
			if c < 0x20 || c == 0x7f {
				return nil, false
			}
			if start < 0 {
				start = i
			}
		}
	}
	if quote != 0 {
		return nil, false
	}
	if start >= 0 {
		tokens = append(tokens, sql[start:])
	}
	return tokens, true
}

// tableName extracts the last component of a possibly schema-qualified and
// quoted table identifier. | tableName 提取可能带 schema 与引号的表标识符的末段。
func tableName(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == clause.CurrentTable {
		return "", false
	}
	parts, ok := splitQualifiedTable(raw)
	if !ok || len(parts) == 0 {
		return "", false
	}
	name, ok := unquoteTableIdentifier(parts[len(parts)-1])
	if !ok || name == "" || name == clause.CurrentTable {
		return "", false
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 0x20 || name[i] == 0x7f {
			return "", false
		}
	}
	return name, true
}

// splitQualifiedTable splits "schema.table" on dots outside quoted identifiers. |
// splitQualifiedTable 在引号标识符之外按点切分 "schema.table"。
func splitQualifiedTable(raw string) ([]string, bool) {
	var parts []string
	start := 0
	var quote byte
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if quote != 0 {
			if c == closingQuote(quote) {
				if i+1 < len(raw) && raw[i+1] == closingQuote(quote) {
					i++
					continue
				}
				quote = 0
			}
			continue
		}
		switch c {
		case '`', '"', '[':
			quote = c
		case '.':
			parts = append(parts, raw[start:i])
			start = i + 1
		case ' ', '\t', '\r', '\n', '(', ')', ',', ';':
			return nil, false
		}
	}
	if quote != 0 {
		return nil, false
	}
	parts = append(parts, raw[start:])
	return parts, true
}

// unquoteTableIdentifier strips one pair of identifier quotes and collapses the
// doubled quote escape. | unquoteTableIdentifier 去掉一层标识符引号并折叠双写转义。
func unquoteTableIdentifier(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if len(raw) >= 2 {
		switch raw[0] {
		case '`', '"':
			if raw[len(raw)-1] != raw[0] {
				return "", false
			}
			return unescapeQuotedTable(raw[1:len(raw)-1], raw[0])
		case '[':
			if raw[len(raw)-1] != ']' {
				return "", false
			}
			return unescapeQuotedTable(raw[1:len(raw)-1], ']')
		}
	}
	if strings.ContainsAny(raw, "`\"[]'() ,;*") {
		return "", false
	}
	return raw, true
}

// unescapeQuotedTable collapses doubled quote characters inside an identifier. |
// unescapeQuotedTable 折叠标识符内双写的引号字符。
func unescapeQuotedTable(inner string, quote byte) (string, bool) {
	var b strings.Builder
	b.Grow(len(inner))
	for i := 0; i < len(inner); i++ {
		if inner[i] != quote {
			b.WriteByte(inner[i])
			continue
		}
		if i+1 < len(inner) && inner[i+1] == quote {
			b.WriteByte(quote)
			i++
			continue
		}
		return "", false
	}
	return b.String(), true
}

// closingQuote maps an opening identifier quote to its closing byte. | closingQuote
// 把标识符起始引号映射为结束字节。
func closingQuote(open byte) byte {
	if open == '[' {
		return ']'
	}
	return open
}

// quotedTableToken reports whether token starts with an identifier quote. |
// quotedTableToken 报告 token 是否以标识符引号开头。
func quotedTableToken(token string) bool {
	if token == "" {
		return false
	}
	switch token[0] {
	case '`', '"', '[':
		return true
	default:
		return false
	}
}

// sqlKeyword reports whether token is a SQL keyword that cannot be an unquoted
// table or alias in this grammar. | sqlKeyword 报告 token 是否为本语法中不能作为
// 未加引号表名或别名的 SQL 关键字。
func sqlKeyword(token string) bool {
	switch strings.ToLower(strings.TrimSpace(token)) {
	case "select", "from", "where", "join", "left", "right", "inner", "outer",
		"full", "cross", "natural", "on", "using", "union", "intersect", "except",
		"group", "order", "limit", "offset", "with", "values", "table", "lateral",
		"straight_join", "as", "returning":
		return true
	default:
		return false
	}
}
