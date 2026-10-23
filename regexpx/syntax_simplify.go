package regexpx

import (
	"errors"
	"fmt"
)

// resolveAmbiguous replaces nAmbig nodes with backreferences or octal literals once the group count is
// known. | resolveAmbiguous 在分组数量确定后把 nAmbig 节点替换为反向引用或八进制字面量。
func resolveAmbiguous(n node, numCap int) node {
	switch n := n.(type) {
	case nil:
		return nil
	case *nAmbig:
		if int(n.value) <= numCap && numCap > 0 {
			return &nBackref{index: int(n.value), fold: n.fold}
		}
		return &nLiteral{r: n.value, fold: n.fold}
	case *nConcat:
		for i := range n.sub {
			n.sub[i] = resolveAmbiguous(n.sub[i], numCap)
		}
	case *nAlt:
		for i := range n.sub {
			n.sub[i] = resolveAmbiguous(n.sub[i], numCap)
		}
	case *nRepeat:
		n.sub = resolveAmbiguous(n.sub, numCap)
	case *nCapture:
		n.sub = resolveAmbiguous(n.sub, numCap)
	case *nLook:
		n.sub = resolveAmbiguous(n.sub, numCap)
	case *nAtomic:
		n.sub = resolveAmbiguous(n.sub, numCap)
	}
	return n
}

// resolveNamedBackrefs fills in the index of every named backreference. | resolveNamedBackrefs 填充每个
// 命名反向引用的下标。
func resolveNamedBackrefs(n node, names map[string]int, err *error) {
	switch n := n.(type) {
	case nil:
		return
	case *nBackref:
		if n.index < 0 {
			index, ok := names[n.name]
			if !ok {
				if *err == nil {
					*err = errors.New("undefined group name " + fmt.Sprintf("%q", n.name) + " | 未定义的分组名 " + fmt.Sprintf("%q", n.name))
				}
				return
			}
			n.index = index
		}
	case *nConcat:
		for _, sub := range n.sub {
			resolveNamedBackrefs(sub, names, err)
		}
	case *nAlt:
		for _, sub := range n.sub {
			resolveNamedBackrefs(sub, names, err)
		}
	case *nRepeat:
		resolveNamedBackrefs(n.sub, names, err)
	case *nCapture:
		resolveNamedBackrefs(n.sub, names, err)
	case *nLook:
		resolveNamedBackrefs(n.sub, names, err)
	case *nAtomic:
		resolveNamedBackrefs(n.sub, names, err)
	}
}

// simplify flattens nested sequences and merges adjacent literals with the same folding option. |
// simplify 展平嵌套序列，并合并折叠选项相同的相邻字面量。
func simplify(n node) node {
	switch n := n.(type) {
	case *nConcat:
		out := make([]node, 0, len(n.sub))
		for _, sub := range n.sub {
			sub = simplify(sub)
			switch s := sub.(type) {
			case *nEmpty:
				continue
			case *nConcat:
				out = append(out, s.sub...)
			default:
				out = append(out, sub)
			}
		}
		out = mergeLiterals(out)
		switch len(out) {
		case 0:
			return &nEmpty{}
		case 1:
			return out[0]
		default:
			return &nConcat{sub: out}
		}
	case *nAlt:
		out := make([]node, 0, len(n.sub))
		for _, sub := range n.sub {
			sub = simplify(sub)
			if alt, ok := sub.(*nAlt); ok {
				out = append(out, alt.sub...)
				continue
			}
			out = append(out, sub)
		}
		if len(out) == 1 {
			return out[0]
		}
		return &nAlt{sub: out}
	case *nRepeat:
		n.sub = simplify(n.sub)
		return n
	case *nCapture:
		n.sub = simplify(n.sub)
		return n
	case *nLook:
		n.sub = simplify(n.sub)
		return n
	case *nAtomic:
		n.sub = simplify(n.sub)
		return n
	}
	return n
}

// mergeLiterals merges adjacent literal and string nodes that share the same folding option. |
// mergeLiterals 合并折叠选项相同的相邻字面量与字符串节点。
func mergeLiterals(nodes []node) []node {
	out := nodes[:0]
	for _, n := range nodes {
		var runes []rune
		var fold bool
		switch s := n.(type) {
		case *nLiteral:
			runes, fold = []rune{s.r}, s.fold
		case *nString:
			runes, fold = s.runes, s.fold
		default:
			out = append(out, n)
			continue
		}
		if len(out) > 0 {
			switch prev := out[len(out)-1].(type) {
			case *nLiteral:
				if prev.fold == fold {
					out[len(out)-1] = &nString{runes: append([]rune{prev.r}, runes...), fold: fold}
					continue
				}
			case *nString:
				if prev.fold == fold {
					out[len(out)-1] = &nString{runes: append(prev.runes, runes...), fold: fold}
					continue
				}
			}
		}
		if len(runes) == 1 {
			out = append(out, &nLiteral{r: runes[0], fold: fold})
		} else {
			out = append(out, &nString{runes: runes, fold: fold})
		}
	}
	return out
}
