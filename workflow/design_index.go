package workflow

import "sort"

// designIndex is the immutable lookup table attached to a parsed design. Runtime code reads it
// concurrently; nothing mutates it after buildDesignIndex returns. | designIndex 是附在解析后设计上的
// 不可变查找表。运行期代码并发读取，buildDesignIndex 返回后没有任何代码修改它。
type designIndex struct {
	// nodes maps a node id onto its first position in Design.Nodes. | nodes 把节点 ID 映射到它在
	// Design.Nodes 中的首个位置。
	nodes map[string]int
	// outgoing maps a source id onto its already sorted outgoing edges. | outgoing 把源节点 ID 映射到
	// 已排序的出线。
	outgoing map[string][]Edge
	// incoming maps a target id onto its incoming edges in design order. | incoming 把目标节点 ID 映射到
	// 按设计顺序排列的入线。
	incoming map[string][]Edge
	// rules is the automatic-approval rules in evaluation order (priority desc, id asc). |
	// rules 是按求值顺序（优先级降序、ID 升序）排列的自动审批规则。
	rules []AutoRule
	// nodesLen and edgesLen detect appends made after parsing. | nodesLen 与 edgesLen 用于发现解析后的追加。
	nodesLen int
	edgesLen int
}

// buildDesignIndex precomputes node lookups and adjacency once per parsed design. Linear scans in
// FindNode, Outgoing and Incoming dominate token processing on large graphs, and Outgoing used to
// insertion-sort on every call. | buildDesignIndex 为每个解析后的设计预计算节点查找与邻接表。
// 在大型图上，FindNode、Outgoing 与 Incoming 的线性扫描会主导令牌推进，而 Outgoing 过去每次调用都要
// 做插入排序。
func buildDesignIndex(design Design) *designIndex {
	index := &designIndex{
		nodes:    make(map[string]int, len(design.Nodes)),
		outgoing: make(map[string][]Edge, len(design.Nodes)),
		incoming: make(map[string][]Edge, len(design.Nodes)),
		nodesLen: len(design.Nodes),
		edgesLen: len(design.Edges),
	}
	for position := range design.Nodes {
		id := design.Nodes[position].ID
		if _, exists := index.nodes[id]; !exists {
			index.nodes[id] = position
		}
	}
	for _, edge := range design.Edges {
		index.outgoing[edge.Source] = append(index.outgoing[edge.Source], edge)
		index.incoming[edge.Target] = append(index.incoming[edge.Target], edge)
	}
	for source := range index.outgoing {
		edges := index.outgoing[source]
		sort.SliceStable(edges, func(i, j int) bool {
			if edges[i].Sort == edges[j].Sort {
				return edges[i].ID < edges[j].ID
			}
			return edges[i].Sort < edges[j].Sort
		})
		index.outgoing[source] = edges
	}
	index.rules = append([]AutoRule(nil), design.Rules...)
	sort.SliceStable(index.rules, func(i, j int) bool {
		if index.rules[i].Priority == index.rules[j].Priority {
			return index.rules[i].ID < index.rules[j].ID
		}
		return index.rules[i].Priority > index.rules[j].Priority
	})
	return index
}
