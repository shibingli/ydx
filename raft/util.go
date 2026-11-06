package raft

import "math/rand/v2"

// fastrand returns a fast, per-P random value used for election jitter. | fastrand
// 返回用于选举抖动的快速每-P 随机数。
func fastrand() uint64 {
	return rand.Uint64()
}

// entryBytes sums the approximate sizes of entries. | entryBytes 汇总日志项的近似
// 大小。
func entryBytes(entries []Entry) int {
	total := 0
	for i := range entries {
		total += entries[i].size()
	}
	return total
}

// sameConfState reports whether two serialized configurations are equal. | sameConfState
// 报告两个序列化配置是否相等。
func sameConfState(a, b ConfState) bool {
	if len(a.Voters) != len(b.Voters) || len(a.Learners) != len(b.Learners) ||
		len(a.VotersOutgoing) != len(b.VotersOutgoing) ||
		len(a.LearnersOutgoing) != len(b.LearnersOutgoing) ||
		len(a.Addresses) != len(b.Addresses) {
		return false
	}
	for i := range a.Voters {
		if a.Voters[i] != b.Voters[i] {
			return false
		}
	}
	for i := range a.Learners {
		if a.Learners[i] != b.Learners[i] {
			return false
		}
	}
	for i := range a.VotersOutgoing {
		if a.VotersOutgoing[i] != b.VotersOutgoing[i] {
			return false
		}
	}
	for i := range a.LearnersOutgoing {
		if a.LearnersOutgoing[i] != b.LearnersOutgoing[i] {
			return false
		}
	}
	for i := range a.Addresses {
		if a.Addresses[i] != b.Addresses[i] {
			return false
		}
	}
	return true
}
