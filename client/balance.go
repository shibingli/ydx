package client

import (
	"math"
	"math/rand/v2"
	"net/http"
)

// Balance names a host selection strategy. | Balance 命名一种 Host 选择策略。
type Balance string

const (
	// BalanceWeighted selects hosts by smooth weighted round-robin. | BalanceWeighted 按平滑加权轮询选择 Host。
	BalanceWeighted Balance = "weighted"
	// BalanceLeastInflight selects the host with the fewest in-flight requests. | BalanceLeastInflight 选择在途请求最少的 Host。
	BalanceLeastInflight Balance = "least-inflight"
	// BalanceRandom selects uniformly at random. | BalanceRandom 均匀随机选择。
	BalanceRandom Balance = "random"
	// BalanceHash selects by a consistent hash of the configured key. | BalanceHash 按配置键的一致性哈希选择。
	BalanceHash Balance = "hash"
	// BalanceOrdered selects the first eligible host in registration order. | BalanceOrdered 按注册顺序选择第一个可用 Host。
	BalanceOrdered Balance = "ordered"
)

// validBalance reports whether b is a supported strategy. | validBalance 报告 b 是否为受支持的策略。
func validBalance(b Balance) bool {
	switch b {
	case BalanceWeighted, BalanceLeastInflight, BalanceRandom, BalanceHash, BalanceOrdered:
		return true
	default:
		return false
	}
}

// buildRing expands host weights into an index ring for O(1) weighted selection. | buildRing 把 Host 权重展开为索引环，实现 O(1) 加权选择。
func buildRing(entries []*hostEntry, total int) []int {
	if total <= 0 {
		return nil
	}
	ring := make([]int, 0, total)
	for i, entry := range entries {
		for n := 0; n < entry.host.Weight; n++ {
			ring = append(ring, i)
		}
	}
	return ring
}

// choose returns the selected entry index, or -1 when none is eligible. | choose 返回选中的条目索引，没有可用项时返回 -1。
func (hs *HostSet) choose(req *http.Request, eligible []bool) int {
	switch hs.balance {
	case BalanceLeastInflight:
		return hs.chooseLeastInflight(eligible)
	case BalanceRandom:
		return chooseRandom(eligible)
	case BalanceHash:
		return hs.chooseHash(req, eligible)
	case BalanceOrdered:
		return chooseOrdered(eligible)
	default:
		return hs.chooseWeighted(eligible)
	}
}

// chooseWeighted walks the weighted ring from a rotating start. | chooseWeighted 从轮转起点遍历加权环。
func (hs *HostSet) chooseWeighted(eligible []bool) int {
	if len(hs.ring) == 0 {
		return -1
	}
	start := int(hs.next.Add(1)-1) % len(hs.ring)
	for offset := 0; offset < len(hs.ring); offset++ {
		index := hs.ring[(start+offset)%len(hs.ring)]
		if eligible[index] {
			return index
		}
	}
	return -1
}

// chooseLeastInflight scans eligible hosts for the smallest in-flight count. | chooseLeastInflight 扫描可用 Host 的在途数并取最小者。
func (hs *HostSet) chooseLeastInflight(eligible []bool) int {
	if len(eligible) == 0 {
		return -1
	}
	start := int(hs.next.Add(1)-1) % len(eligible)
	best := -1
	bestInflight := int64(math.MaxInt64)
	for offset := 0; offset < len(eligible); offset++ {
		index := (start + offset) % len(eligible)
		if !eligible[index] {
			continue
		}
		inflight := hs.entries[index].inflight.Load()
		if inflight < bestInflight {
			best = index
			bestInflight = inflight
		}
	}
	return best
}

// chooseRandom picks a uniformly random eligible index. | chooseRandom 均匀随机选择一个可用索引。
func chooseRandom(eligible []bool) int {
	count := 0
	for _, ok := range eligible {
		if ok {
			count++
		}
	}
	if count == 0 {
		return -1
	}
	pick := rand.IntN(count)
	for index, ok := range eligible {
		if !ok {
			continue
		}
		if pick == 0 {
			return index
		}
		pick--
	}
	return -1
}

// chooseHash picks an eligible host by the FNV-1a hash of the request key. | chooseHash 按请求键的 FNV-1a 哈希选择可用 Host。
func (hs *HostSet) chooseHash(req *http.Request, eligible []bool) int {
	count := 0
	for _, ok := range eligible {
		if ok {
			count++
		}
	}
	if count == 0 {
		return -1
	}
	pick := int(fnv64aString(safeHashKey(hs.hashKey, req)) % uint64(count))
	for index, ok := range eligible {
		if !ok {
			continue
		}
		if pick == 0 {
			return index
		}
		pick--
	}
	return -1
}

// safeHashKey invokes a user hash key function with panic isolation. | safeHashKey 以 panic 隔离调用用户哈希键函数。
func safeHashKey(fn func(*http.Request) string, req *http.Request) (key string) {
	if fn == nil {
		return ""
	}
	defer func() {
		if recover() != nil {
			key = ""
		}
	}()
	return fn(req)
}

// chooseOrdered returns the first eligible index. | chooseOrdered 返回第一个可用索引。
func chooseOrdered(eligible []bool) int {
	for index, ok := range eligible {
		if ok {
			return index
		}
	}
	return -1
}
