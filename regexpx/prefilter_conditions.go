package regexpx

// maxRequiredConditions bounds the number of independent necessary byte conditions checked per
// search. Each condition is a cheap single pass over the input. | maxRequiredConditions 限制每次搜索
// 检查的独立必需字节条件数量。每个条件都是对输入的一次廉价扫描。
const maxRequiredConditions = 4

// requiredByteSet collects the independent necessary byte conditions of a node. Conditions in the
// list are conjunctive: every match of the node satisfies all of them. | requiredByteSet 收集节点的
// 独立必需字节条件。列表中的条件为合取关系：节点的每个匹配都满足全部条件。
type requiredByteSet struct {
	conditions [maxRequiredConditions]requiredBytes
	count      uint8
}

// analyzeRequiredByteSet derives conjunctive byte conditions from n. Unlike analyzeRequiredBytes,
// which keeps one condition, this keeps the mandatory conditions contributed by every part of a
// concatenation. An alternation retains only conditions common to every branch. | analyzeRequiredByteSet
// 从 n 推导合取字节条件。与只保留一个条件的 analyzeRequiredBytes 不同，它保留连接各部分贡献的
// 必需条件；分支只保留所有分支共有的条件。
func analyzeRequiredByteSet(n node) requiredByteSet {
	var out requiredByteSet
	switch n := n.(type) {
	case nil, *nEmpty, *nAssert, *nLook, *nBackref, *nAny:
		return out
	case *nLiteral, *nString, *nAmbig, *nClass:
		out.add(analyzeRequiredBytes(n))
		return out
	case *nCapture:
		return analyzeRequiredByteSet(n.sub)
	case *nAtomic:
		return analyzeRequiredByteSet(n.sub)
	case *nRepeat:
		if n.min <= 0 {
			return out
		}
		child := analyzeRequiredByteSet(n.sub)
		for i := uint8(0); i < child.count; i++ {
			condition := child.conditions[i]
			condition.minCount = saturatingByteCount(condition.minCount, n.min)
			out.add(condition)
		}
		return out
	case *nAlt:
		return requiredAlternationSet(n.sub)
	case *nConcat:
		for _, sub := range n.sub {
			child := analyzeRequiredByteSet(sub)
			for i := uint8(0); i < child.count; i++ {
				out.add(child.conditions[i])
			}
		}
		// The union/sum condition is a different sound consequence of the whole concatenation. |
		// 并集/计数条件是整个连接产生的另一种可靠推论。
		out.add(requiredConcatBytes(n.sub))
		return out
	default:
		return out
	}
}

// requiredAlternationSet retains only conditions present in every branch. A condition with the same
// byte set but a larger count in one branch is weakened to the smallest count across branches. |
// requiredAlternationSet 只保留每个分支都存在的条件。同一字节集在某分支中计数更大时，按所有分支
// 中的最小计数弱化。
func requiredAlternationSet(subs []node) requiredByteSet {
	var out requiredByteSet
	if len(subs) == 0 {
		return out
	}
	first := analyzeRequiredByteSet(subs[0])
	if first.count == 0 {
		return out
	}
	out = first
	for _, sub := range subs[1:] {
		branch := analyzeRequiredByteSet(sub)
		var next requiredByteSet
		for i := uint8(0); i < out.count; i++ {
			condition := out.conditions[i]
			if common, ok := branch.common(condition); ok {
				if common.minCount < condition.minCount {
					condition.minCount = common.minCount
				}
				next.add(condition)
			}
		}
		out = next
		if out.count == 0 {
			return out
		}
	}
	// The union/min condition is sound for the whole alternation and may be stronger than any
	// condition common to all branches. | 并集/最小计数条件对整个分支可靠，可能强于所有分支共有的
	// 条件。
	out.add(requiredAlternationBytes(subs))
	return out
}

// common returns the condition with the same byte set as want, if any. | common 返回与 want 具有
// 相同字节集的条件（如果存在）。
func (s requiredByteSet) common(want requiredBytes) (requiredBytes, bool) {
	for i := uint8(0); i < s.count; i++ {
		if sameRequiredByteSet(s.conditions[i], want) {
			return s.conditions[i], true
		}
	}
	return requiredBytes{}, false
}

// add inserts a condition, drops conditions implied by a stronger one, and keeps the most selective
// conditions when the cap is reached. | add 插入条件，删除被更强条件蕴含的条件，并在达到上限时保留
// 最具选择性的条件。
func (s *requiredByteSet) add(condition requiredBytes) {
	if !condition.ok || condition.minCount <= 0 {
		return
	}
	for i := uint8(0); i < s.count; i++ {
		existing := s.conditions[i]
		if sameRequiredByteSet(existing, condition) {
			if condition.minCount > existing.minCount {
				s.conditions[i].minCount = condition.minCount
			}
			return
		}
		if requiredBytesImplies(existing, condition) {
			return
		}
	}
	// Remove conditions that the new condition implies. | 删除被新条件蕴含的条件。
	write := uint8(0)
	for i := uint8(0); i < s.count; i++ {
		if requiredBytesImplies(condition, s.conditions[i]) {
			continue
		}
		s.conditions[write] = s.conditions[i]
		write++
	}
	s.count = write
	if s.count < maxRequiredConditions {
		s.conditions[s.count] = condition
		s.count++
		return
	}
	// Keep the smallest sets and highest counts: they reject the most inputs per byte scanned. |
	// 保留最小集合与最高计数：它们每次扫描拒绝的输入最多。
	weakest := 0
	for i := 1; i < int(s.count); i++ {
		if betterRequiredCondition(s.conditions[weakest], s.conditions[i]) {
			weakest = i
		}
	}
	if betterRequiredCondition(condition, s.conditions[weakest]) {
		s.conditions[weakest] = condition
	}
}

// betterRequiredCondition reports whether left is more selective than right. | betterRequiredCondition
// 报告 left 是否比 right 更具选择性。
func betterRequiredCondition(left, right requiredBytes) bool {
	leftSize, rightSize := requiredByteSetSize(left), requiredByteSetSize(right)
	if leftSize != rightSize {
		return leftSize < rightSize
	}
	return left.minCount > right.minCount
}

// requiredBytesImplies reports whether every input satisfying strong also satisfies weak. | requiredBytesImplies
// 报告满足 strong 的输入是否必然满足 weak。
func requiredBytesImplies(strong, weak requiredBytes) bool {
	if !strong.ok || !weak.ok {
		return false
	}
	if strong.minCount < weak.minCount {
		return false
	}
	if strong.anyHigh && !weak.anyHigh {
		return false
	}
	for word := 0; word < 2; word++ {
		if strong.ascii[word]&^weak.ascii[word] != 0 {
			return false
		}
	}
	return true
}

// sameRequiredByteSet reports whether two conditions use the same byte set. | sameRequiredByteSet
// 报告两个条件是否使用相同字节集。
func sameRequiredByteSet(left, right requiredBytes) bool {
	return left.anyHigh == right.anyHigh && left.ascii == right.ascii
}
