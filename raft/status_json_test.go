package raft

import (
	"testing"

	ydxjson "github.com/shibingli/ydx/json"
)

// TestStatusMarshalJSON verifies Status uses the ydx/json codec and a stable
// snake_case API shape, including a string state and peer state. |
// TestStatusMarshalJSON 验证 Status 使用 ydx/json 编解码器与稳定的 snake_case API
// 形状，包括字符串状态与对端状态。
func TestStatusMarshalJSON(t *testing.T) {
	st := Status{
		ID: 1, Group: 2, State: StateLeader, Term: 3, Leader: 1,
		Commit: 9, Applied: 8, LastIndex: 10, LastTerm: 3, FirstIndex: 1,
		SnapshotIndex: 5, Snapshotting: true, Joint: true,
		Voters: []NodeID{1, 2}, Learners: []NodeID{3},
		Peers: []PeerStatus{{
			ID: 2, Addr: "tcp://2", State: "replicate", Match: 9, Next: 10,
			InflightMsgs: 1, InflightBytes: 128, PendingSnapshot: 4,
			SnapshotError: "frame limit", RecentActive: true,
		}},
	}
	raw, err := ydxjson.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := ydxjson.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got["state"] != "leader" {
		t.Fatalf("state = %v", got["state"])
	}
	if got["id"] != float64(1) || got["last_index"] != float64(10) ||
		got["snapshot_index"] != float64(5) || got["snapshotting"] != true {
		t.Fatalf("status json = %v", got)
	}
	peers, ok := got["peers"].([]any)
	if !ok || len(peers) != 1 {
		t.Fatalf("peers = %#v", got["peers"])
	}
	peer, ok := peers[0].(map[string]any)
	if !ok {
		t.Fatalf("peer = %#v", peers[0])
	}
	if peer["state"] != "replicate" || peer["match"] != float64(9) ||
		peer["snapshot_error"] != "frame limit" {
		t.Fatalf("peer json = %v", peer)
	}
	emptyRaw, err := ydxjson.Marshal(Status{State: StateFollower})
	if err != nil {
		t.Fatal(err)
	}
	var empty map[string]any
	if err := ydxjson.Unmarshal(emptyRaw, &empty); err != nil {
		t.Fatal(err)
	}
	if voters, ok := empty["voters"].([]any); !ok || len(voters) != 0 {
		t.Fatalf("empty voters = %#v, want empty array", empty["voters"])
	}
	if peers, ok := empty["peers"].([]any); !ok || len(peers) != 0 {
		t.Fatalf("empty peers = %#v, want empty array", empty["peers"])
	}
}

// TestStatsMarshalJSON verifies Stats uses the ydx/json codec with stable field
// names. | TestStatsMarshalJSON 验证 Stats 使用 ydx/json 编解码器与稳定字段名。
func TestStatsMarshalJSON(t *testing.T) {
	st := Stats{Proposals: 7, Applies: 6, SnapshotsCreated: 2,
		SnapshotChunksOut: 5, PersistBatches: 3}
	raw, err := ydxjson.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := ydxjson.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got["proposals"] != float64(7) || got["applies"] != float64(6) ||
		got["snapshots_created"] != float64(2) ||
		got["snapshot_chunks_out"] != float64(5) ||
		got["persist_batches"] != float64(3) {
		t.Fatalf("stats json = %v", got)
	}
}
