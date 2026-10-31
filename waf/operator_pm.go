package waf

// acNode is one Aho-Corasick trie node. | acNode 是 Aho-Corasick 前缀树的一个节点。
type acNode struct {
	next map[byte]int32
	fail int32
	out  bool
}

// acMatcher finds any of a fixed pattern set in one linear scan. | acMatcher 在一次线性扫描中
// 查找固定模式集合中的任意一个。
type acMatcher struct {
	nodes    []acNode
	rootNext [256]int32
}

// newACMatcher builds an Aho-Corasick automaton. Empty patterns are ignored. | newACMatcher
// 构建 Aho-Corasick 自动机；空模式会被忽略。
func newACMatcher(patterns []string) *acMatcher {
	m := &acMatcher{nodes: make([]acNode, 1)}
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		state := int32(0)
		for i := 0; i < len(pattern); i++ {
			c := pattern[i]
			next := m.nodes[state].next
			if next == nil {
				next = make(map[byte]int32, 2)
				m.nodes[state].next = next
			}
			child, ok := next[c]
			if !ok {
				child = int32(len(m.nodes))
				next[c] = child
				m.nodes = append(m.nodes, acNode{})
			}
			state = child
		}
		m.nodes[state].out = true
	}
	m.buildFailures()
	for c, child := range m.nodes[0].next {
		m.rootNext[c] = child
	}
	return m
}

// buildFailures fills failure links breadth-first and propagates terminal flags. | buildFailures
// 按广度优先填充失败链接并传播终止标记。
func (m *acMatcher) buildFailures() {
	queue := make([]int32, 0, len(m.nodes))
	for _, child := range m.nodes[0].next {
		m.nodes[child].fail = 0
		queue = append(queue, child)
	}
	for head := 0; head < len(queue); head++ {
		state := queue[head]
		for c, child := range m.nodes[state].next {
			fail := m.nodes[state].fail
			for fail != 0 {
				if _, ok := m.nodes[fail].next[c]; ok {
					break
				}
				fail = m.nodes[fail].fail
			}
			if next, ok := m.nodes[fail].next[c]; ok && next != child {
				m.nodes[child].fail = next
			} else {
				m.nodes[child].fail = 0
			}
			if m.nodes[m.nodes[child].fail].out {
				m.nodes[child].out = true
			}
			queue = append(queue, child)
		}
	}
}

// match reports whether any pattern occurs in s. | match 报告 s 中是否出现任一模式。
func (m *acMatcher) match(s string) bool {
	if m == nil || len(m.nodes) == 1 {
		return false
	}
	state := int32(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if state == 0 {
			// The root is traversed after every mismatch; a dense row avoids a map lookup. |
			// 每次失配后都会回到根节点；密集转移行避免 map 查找。
			next := m.rootNext[c]
			if next == 0 {
				continue
			}
			state = next
			if m.nodes[state].out {
				return true
			}
			continue
		}
		for {
			if next, ok := m.nodes[state].next[c]; ok {
				state = next
				break
			}
			if state == 0 {
				break
			}
			state = m.nodes[state].fail
		}
		if state != 0 && m.nodes[state].out {
			return true
		}
	}
	return false
}
