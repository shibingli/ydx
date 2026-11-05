package raft

import "testing"

// FuzzUnmarshalMessage checks that arbitrary wire bytes never panic and that
// accepted messages round-trip through the encoder. | FuzzUnmarshalMessage 检查
// 任意线数据不会 panic，且被接受的消息可经编码器往返。
func FuzzUnmarshalMessage(f *testing.F) {
	seed, _ := MarshalMessage(Message{Type: MsgApp, From: 1, To: 2, Term: 3,
		LogIndex: 4, LogTerm: 2, Commit: 4,
		Entries: []Entry{{Index: 5, Term: 3, Type: EntryNormal, Data: []byte("hello")}}})
	f.Add(seed)
	f.Add([]byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := UnmarshalMessage(data)
		if err != nil {
			return
		}
		encoded, err := MarshalMessage(m)
		if err != nil {
			t.Fatalf("re-marshal: %v", err)
		}
		again, err := UnmarshalMessage(encoded)
		if err != nil {
			t.Fatalf("re-unmarshal: %v", err)
		}
		if again.Type != m.Type || again.From != m.From || again.To != m.To || again.Term != m.Term {
			t.Fatalf("round trip mismatch: %+v vs %+v", again, m)
		}
	})
}

// FuzzDecodeWALBatch checks WAL payload decoding. | FuzzDecodeWALBatch 检查 WAL
// 载荷解码。
func FuzzDecodeWALBatch(f *testing.F) {
	f.Add(encodeWALBatch(nil, PersistBatch{Entries: []Entry{{Index: 1, Term: 1, Type: EntryNormal, Data: []byte("x")}}}))
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if _, err := decodeWALBatch(data); err != nil {
			return
		}
	})
}
