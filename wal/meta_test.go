package wal

import (
	"errors"
	"testing"
)

// TestCheckMetaTransitionFlags verifies the META flag transition rules: no bit
// may ever be cleared, the anchor bit may be added at any time, and serializable
// durability or encryption may only be enabled on an empty WAL, with the digest
// algorithm fixed at the moment serializable durability is enabled. | 验证 META
// 标志迁移规则：任何位都不得被清除，锚点位可随时新增，可串行化持久化或加密只能
// 在空 WAL 上启用，且摘要算法在启用可串行化持久化时一次性确定。
func TestCheckMetaTransitionFlags(t *testing.T) {
	id := [16]byte{0x11, 0x22, 0x33}
	emptyState := func(flags uint16) metaState {
		return metaState{walID: id, flags: flags, nextSeq: 1, nextLSN: 1, firstLSN: 1, commitSeq: 0}
	}
	liveState := func(flags uint16) metaState {
		return metaState{walID: id, flags: flags, nextSeq: 2, nextLSN: 5, firstLSN: 1, commitSeq: 2}
	}
	sm3Bits := (uint16(HashSM3) & metaFlagHashMask) << metaFlagHashShift

	cases := []struct {
		name   string
		older  metaState
		newer  metaState
		wantOK bool
	}{
		{name: "unchanged flags", older: emptyState(metaFlagAnchor), newer: emptyState(metaFlagAnchor), wantOK: true},
		{name: "anchor added after data", older: liveState(0), newer: liveState(metaFlagAnchor), wantOK: true},
		{name: "anchor added on empty WAL", older: emptyState(0), newer: emptyState(metaFlagAnchor), wantOK: true},
		{name: "anchor cleared", older: emptyState(metaFlagAnchor), newer: emptyState(0)},
		{name: "serializable enabled on empty WAL", older: emptyState(0), newer: emptyState(metaFlagSerializable), wantOK: true},
		{name: "serializable with SM3 enabled on empty WAL", older: emptyState(0), newer: emptyState(metaFlagSerializable | sm3Bits), wantOK: true},
		{name: "serializable and anchor enabled on empty WAL", older: emptyState(0), newer: emptyState(metaFlagSerializable | metaFlagAnchor), wantOK: true},
		{name: "serializable enabled while nextLSN advances", older: liveState(0), newer: func() metaState {
			st := liveState(metaFlagSerializable)
			st.nextLSN = 6
			return st
		}()},
		{name: "encryption enabled while commitSeq advances", older: liveState(0), newer: func() metaState {
			st := liveState(metaFlagEncrypted)
			st.commitSeq = 3
			return st
		}()},
		{name: "encryption enabled on empty WAL", older: emptyState(0), newer: emptyState(metaFlagEncrypted), wantOK: true},
		{name: "encryption and serializable enabled together on empty WAL", older: emptyState(0), newer: emptyState(metaFlagEncrypted | metaFlagSerializable), wantOK: true},
		{name: "anchor cleared while serializable enabled", older: emptyState(metaFlagAnchor), newer: emptyState(metaFlagSerializable)},
		{name: "encryption cleared while serializable enabled", older: emptyState(metaFlagEncrypted), newer: emptyState(metaFlagSerializable)},
		{name: "hash algorithm moved to SHA256 with serializable enabled", older: emptyState(metaFlagSerializable | sm3Bits), newer: emptyState(metaFlagSerializable)},
		{name: "hash algorithm moved to SM3 with serializable enabled", older: emptyState(metaFlagSerializable), newer: emptyState(metaFlagSerializable | sm3Bits)},
		{name: "hash bits without serializable", older: emptyState(0), newer: emptyState(sm3Bits)},
		{name: "unknown flag bit added", older: emptyState(0), newer: emptyState(1 << 5)},
		{name: "high-water rolled back", older: liveState(0), newer: func() metaState {
			st := liveState(0)
			st.nextLSN = 4
			return st
		}()},
		{name: "walID changed", older: emptyState(0), newer: func() metaState {
			st := emptyState(0)
			st.walID = [16]byte{0x44}
			return st
		}()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkMetaTransition(tc.newer, tc.older)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("checkMetaTransition() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("checkMetaTransition() = %v, want ErrCorrupt", err)
			}
		})
	}
}
