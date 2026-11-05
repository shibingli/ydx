package raft

import (
	"reflect"
	"testing"
)

// TestMembershipJointQuorum checks quorum rules during a joint transition.
// | TestMembershipJointQuorum 检查联合过渡期间的法定人数规则。
func TestMembershipJointQuorum(t *testing.T) {
	m := newMembership([]NodeID{1, 2, 3}, nil, map[NodeID]string{1: "a", 2: "b", 3: "c"})
	next, err := m.apply(ConfChange{Type: ConfChangeAddNode, NodeID: 4, Addr: "d"})
	if err != nil {
		t.Fatal(err)
	}
	if !next.joint() {
		t.Fatal("expected joint configuration")
	}
	check := func(ids ...NodeID) bool {
		set := make(map[NodeID]bool)
		for _, id := range ids {
			set[id] = true
		}
		return next.hasQuorum(func(id NodeID) bool { return set[id] })
	}
	if !check(1, 2, 3) || !check(1, 2, 4) || !check(2, 3, 4) {
		t.Fatal("expected quorum")
	}
	if check(1, 4) || check(1, 2) {
		t.Fatal("unexpected quorum")
	}
	final, err := next.apply(ConfChange{Type: ConfChangeLeaveJoint})
	if err != nil {
		t.Fatal(err)
	}
	if final.joint() {
		t.Fatal("joint flag survived leave")
	}
	if !final.hasQuorum(func(id NodeID) bool { return id == 1 || id == 2 || id == 4 }) {
		t.Fatal("new configuration has no quorum")
	}
	if final.hasQuorum(func(id NodeID) bool { return id == 1 || id == 2 }) {
		t.Fatal("2 of 4 should not be a quorum")
	}
}

// TestMembershipRemove checks removal and the last-voter guard. | TestMembershipRemove
// 检查移除与最后投票成员保护。
func TestMembershipRemove(t *testing.T) {
	m := newMembership([]NodeID{1, 2, 3}, nil, nil)
	next, err := m.apply(ConfChange{Type: ConfChangeRemoveNode, NodeID: 3})
	if err != nil {
		t.Fatal(err)
	}
	if !next.joint() || !next.isMember(3) {
		t.Fatalf("outgoing member missing from joint config: %+v", next)
	}
	final, err := next.apply(ConfChange{Type: ConfChangeLeaveJoint})
	if err != nil {
		t.Fatal(err)
	}
	if final.isMember(3) || final.joint() {
		t.Fatalf("node 3 still a member after leave: %+v", final)
	}
	single := newMembership([]NodeID{1}, nil, nil)
	if _, err := single.apply(ConfChange{Type: ConfChangeRemoveNode, NodeID: 1}); err == nil {
		t.Fatal("removed the last voter")
	}
}

// TestMembershipConfStateDeterministic checks stable snapshot metadata. | TestMembershipConfStateDeterministic
// 检查稳定的快照元数据。
func TestMembershipConfStateDeterministic(t *testing.T) {
	m := newMembership([]NodeID{3, 1, 2}, []NodeID{5, 4}, map[NodeID]string{1: "a", 2: "b", 3: "c", 4: "d", 5: "e"})
	a := m.confState()
	b := m.confState()
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("nondeterministic: %+v vs %+v", a, b)
	}
	if !reflect.DeepEqual(a.Voters, []NodeID{1, 2, 3}) || !reflect.DeepEqual(a.Learners, []NodeID{4, 5}) {
		t.Fatalf("conf state = %+v", a)
	}
	round, err := decodeConfStateBytes(appendConfState(nil, a))
	if err != nil {
		t.Fatal(err)
	}
	if !sameConfState(round, a) {
		t.Fatalf("round trip = %+v", round)
	}
}
