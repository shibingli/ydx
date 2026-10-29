package workflow

import (
	"strings"
	"sync"
)

// conditionCacheLimit bounds the compiled-expression cache. Each entry is at most maxConditionLen
// bytes of source plus its immutable AST, so the whole cache stays in the low megabytes. |
// conditionCacheLimit 限制已编译表达式缓存。每项最多 maxConditionLen 字节源码加上不可变 AST，
// 整个缓存维持在数 MB 以内。
const conditionCacheLimit = 512

// conditionCache is a FIFO cache of compiled condition ASTs. Runtime edge and rule evaluation
// hits the same handful of expressions thousands of times; parsing them again on every token step
// allocated tokens, substrings and AST nodes for no benefit. | conditionCache 是已编译条件 AST 的
// FIFO 缓存。运行期的连线与规则求值会把同一小批表达式命中成千上万次；每次令牌推进都重新解析只会
// 凭空分配记号、子串与 AST 节点。
type conditionCache struct {
	// items maps the trimmed expression onto its AST. | items 把去空白后的表达式映射到 AST。
	items map[string]condNode
	// order is the insertion order used for FIFO eviction. | order 是 FIFO 淘汰使用的插入顺序。
	order []string
	// limit is the maximum number of entries. | limit 是最大条目数。
	limit int
	// mu guards items and order. | mu 保护 items 与 order。
	mu sync.RWMutex
}

// newConditionCache builds a cache with the given limit. | newConditionCache 构建指定上限的缓存。
func newConditionCache(limit int) *conditionCache {
	if limit <= 0 {
		limit = conditionCacheLimit
	}
	return &conditionCache{items: make(map[string]condNode, limit), limit: limit}
}

// get returns one compiled AST. | get 返回一个已编译 AST。
func (c *conditionCache) get(expr string) (condNode, bool) {
	c.mu.RLock()
	node, ok := c.items[expr]
	c.mu.RUnlock()
	return node, ok
}

// put stores one compiled AST and evicts the oldest entry when full. | put 保存一个已编译 AST，
// 满载时淘汰最旧的条目。
func (c *conditionCache) put(expr string, node condNode) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.items[expr]; exists {
		c.items[expr] = node
		return
	}
	for len(c.items) >= c.limit && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.items, oldest)
	}
	c.items[expr] = node
	c.order = append(c.order, expr)
}

// compiledConditions is the process-wide cache. | compiledConditions 是进程级缓存。
var compiledConditions = newConditionCache(conditionCacheLimit)

// compileCondition returns the cached AST for expr, parsing it on first use. Empty expressions
// compile to the constant true node. | compileCondition 返回 expr 的缓存 AST，首次使用时解析。
// 空表达式编译为常量 true。
func compileCondition(expr string) (condNode, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return condLiteral{value: true}, nil
	}
	if node, ok := compiledConditions.get(expr); ok {
		return node, nil
	}
	node, err := parseCondition(expr)
	if err != nil {
		return nil, err
	}
	compiledConditions.put(expr, node)
	return node, nil
}
