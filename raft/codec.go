package raft

import (
	"encoding/binary"

	"github.com/shibingli/ydx/errs"
)

// Wire limits. They bound memory used by a malicious or corrupt peer before any
// allocation proportional to the claimed length happens. | 线格式限制。它们在按声明
// 长度分配内存之前，约束恶意或损坏对端可能造成的内存占用。
const (
	protocolVersion   = 2
	maxMessageBytes   = 256 << 20
	maxEntryBytes     = 64 << 20
	maxSnapshotBytes  = 256 << 20
	maxContextBytes   = 1 << 20
	maxAddressBytes   = 1 << 20
	maxMessageEntries = 1 << 20
	maxConfNodes      = 1 << 16
)

// marshalFlags packs optional Message fields. | marshalFlags 打包 Message 的可选字段。
const (
	flagReject   = 1 << 0
	flagContext  = 1 << 1
	flagEntries  = 1 << 2
	flagSnapshot = 1 << 3
)

// MarshalMessage encodes one message using the stable binary wire format.
// | MarshalMessage 使用稳定的二进制线格式编码一条消息。
func MarshalMessage(m Message) ([]byte, error) {
	return encodeMessage(nil, m)
}

// UnmarshalMessage decodes one message and rejects trailing or malformed data.
// | UnmarshalMessage 解码一条消息，并拒绝尾随或损坏的数据。
func UnmarshalMessage(data []byte) (Message, error) {
	if len(data) > maxMessageBytes {
		return Message{}, errs.Detail(ErrTooLarge, "message %d bytes", len(data))
	}
	d := decoder{src: data}
	version := d.byte()
	if d.err != nil {
		return Message{}, d.err
	}
	if version != protocolVersion {
		return Message{}, errs.Detail(ErrCorrupt, "wire version %d", version)
	}
	typ := MessageType(d.byte())
	if d.err != nil || typ < MsgHup || typ > maxMessageType {
		if d.err != nil {
			return Message{}, d.err
		}
		return Message{}, errs.Detail(ErrCorrupt, "message type %d", typ)
	}
	flags := d.byte()
	if d.err != nil {
		return Message{}, d.err
	}
	m := Message{
		Type:       typ,
		Reject:     flags&flagReject != 0,
		From:       NodeID(d.uvarint()),
		To:         NodeID(d.uvarint()),
		Group:      GroupID(d.uvarint()),
		Term:       d.uvarint(),
		LogIndex:   d.uvarint(),
		LogTerm:    d.uvarint(),
		Index:      d.uvarint(),
		Commit:     d.uvarint(),
		RejectHint: d.uvarint(),
		RejectTerm: d.uvarint(),
	}
	if d.err != nil {
		return Message{}, d.err
	}
	if flags&flagContext != 0 {
		m.Context = d.bytes(maxContextBytes)
	}
	if d.err != nil {
		return Message{}, d.err
	}
	if flags&flagEntries != 0 {
		m.Entries = d.entries()
	}
	if d.err != nil {
		return Message{}, d.err
	}
	if flags&flagSnapshot != 0 {
		m.Snapshot = d.snapshot()
	}
	if d.err != nil {
		return Message{}, d.err
	}
	if d.pos != len(d.src) {
		return Message{}, errs.Detail(ErrCorrupt, "trailing %d bytes", len(d.src)-d.pos)
	}
	return m, nil
}

// encodeMessage appends the wire form to dst. | encodeMessage 将线格式追加到 dst。
func encodeMessage(dst []byte, m Message) ([]byte, error) {
	flags := byte(0)
	if m.Reject {
		flags |= flagReject
	}
	if len(m.Context) > 0 {
		if len(m.Context) > maxContextBytes {
			return nil, errs.Detail(ErrTooLarge, "context %d bytes", len(m.Context))
		}
		flags |= flagContext
	}
	if len(m.Entries) > 0 {
		if len(m.Entries) > maxMessageEntries {
			return nil, errs.Detail(ErrTooLarge, "entries %d", len(m.Entries))
		}
		flags |= flagEntries
	}
	if m.Snapshot != nil {
		if len(m.Snapshot.Data) > maxSnapshotBytes {
			return nil, errs.Detail(ErrTooLarge, "snapshot %d bytes", len(m.Snapshot.Data))
		}
		flags |= flagSnapshot
	}
	dst = append(dst, protocolVersion, byte(m.Type), flags)
	dst = binary.AppendUvarint(dst, uint64(m.From))
	dst = binary.AppendUvarint(dst, uint64(m.To))
	dst = binary.AppendUvarint(dst, uint64(m.Group))
	dst = binary.AppendUvarint(dst, m.Term)
	dst = binary.AppendUvarint(dst, m.LogIndex)
	dst = binary.AppendUvarint(dst, m.LogTerm)
	dst = binary.AppendUvarint(dst, m.Index)
	dst = binary.AppendUvarint(dst, m.Commit)
	dst = binary.AppendUvarint(dst, m.RejectHint)
	dst = binary.AppendUvarint(dst, m.RejectTerm)
	if flags&flagContext != 0 {
		dst = appendBytes(dst, m.Context)
	}
	if flags&flagEntries != 0 {
		dst = appendEntries(dst, m.Entries)
	}
	if flags&flagSnapshot != 0 {
		dst = appendSnapshot(dst, m.Snapshot)
	}
	if len(dst) > maxMessageBytes {
		return nil, errs.Detail(ErrTooLarge, "message %d bytes", len(dst))
	}
	return dst, nil
}

// appendBytes writes a length-prefixed byte slice. | appendBytes 写入带长度前缀的
// 字节切片。
func appendBytes(dst, b []byte) []byte {
	dst = binary.AppendUvarint(dst, uint64(len(b)))
	return append(dst, b...)
}

// appendString writes a length-prefixed string. | appendString 写入带长度前缀的字符串。
func appendString(dst []byte, s string) []byte {
	dst = binary.AppendUvarint(dst, uint64(len(s)))
	return append(dst, s...)
}

// appendEntries writes a contiguous entry list with index deltas. | appendEntries
// 使用索引增量写入连续日志项列表。
func appendEntries(dst []byte, entries []Entry) []byte {
	dst = binary.AppendUvarint(dst, uint64(len(entries)))
	var prev uint64
	for i := range entries {
		e := &entries[i]
		if i == 0 {
			dst = binary.AppendUvarint(dst, e.Index)
		} else {
			dst = binary.AppendUvarint(dst, e.Index-prev)
		}
		prev = e.Index
		dst = binary.AppendUvarint(dst, e.Term)
		dst = append(dst, byte(e.Type))
		dst = appendBytes(dst, e.Data)
	}
	return dst
}

// appendSnapshot writes snapshot metadata and data. | appendSnapshot 写入快照元数据与
// 数据。
func appendSnapshot(dst []byte, s *Snapshot) []byte {
	dst = binary.AppendUvarint(dst, s.Index)
	dst = binary.AppendUvarint(dst, s.Term)
	dst = appendConfState(dst, s.ConfState)
	return appendBytes(dst, s.Data)
}

// appendConfState writes a deterministic configuration view. | appendConfState 写入
// 确定性的配置视图。
func appendConfState(dst []byte, cs ConfState) []byte {
	for _, list := range [][]NodeID{cs.Voters, cs.Learners, cs.VotersOutgoing, cs.LearnersOutgoing} {
		dst = binary.AppendUvarint(dst, uint64(len(list)))
		for _, id := range list {
			dst = binary.AppendUvarint(dst, uint64(id))
		}
	}
	dst = binary.AppendUvarint(dst, uint64(len(cs.Addresses)))
	for _, p := range cs.Addresses {
		dst = binary.AppendUvarint(dst, uint64(p.ID))
		dst = appendString(dst, p.Addr)
	}
	return dst
}

// encodeConfChange serializes a membership command. | encodeConfChange 序列化成员命令。
func encodeConfChange(cc ConfChange) ([]byte, error) {
	if cc.Type < ConfChangeAddNode || cc.Type > ConfChangeLeaveJoint {
		return nil, errs.Detail(ErrInvalidConfig, "change type %d", cc.Type)
	}
	if cc.Type != ConfChangeLeaveJoint && cc.NodeID == 0 {
		return nil, errs.Detail(ErrInvalidConfig, "change node must be non-zero")
	}
	if len(cc.Addr) > maxAddressBytes {
		return nil, errs.Detail(ErrTooLarge, "address %d bytes", len(cc.Addr))
	}
	dst := make([]byte, 0, 16+len(cc.Addr))
	dst = append(dst, byte(cc.Type))
	dst = binary.AppendUvarint(dst, uint64(cc.NodeID))
	dst = appendString(dst, cc.Addr)
	return dst, nil
}

// decodeConfChange parses a membership command. | decodeConfChange 解析成员命令。
func decodeConfChange(data []byte) (ConfChange, error) {
	d := decoder{src: data}
	typ := ConfChangeType(d.byte())
	if d.err != nil || typ < ConfChangeAddNode || typ > ConfChangeLeaveJoint {
		if d.err != nil {
			return ConfChange{}, d.err
		}
		return ConfChange{}, errs.Detail(ErrCorrupt, "change type %d", typ)
	}
	cc := ConfChange{Type: typ, NodeID: NodeID(d.uvarint())}
	cc.Addr = d.string(maxAddressBytes)
	if d.err != nil {
		return ConfChange{}, d.err
	}
	if d.pos != len(d.src) {
		return ConfChange{}, errs.Detail(ErrCorrupt, "trailing %d bytes", len(d.src)-d.pos)
	}
	if typ != ConfChangeLeaveJoint && cc.NodeID == 0 {
		return ConfChange{}, errs.Detail(ErrCorrupt, "change node zero")
	}
	return cc, nil
}

// decodeConfStateBytes parses a standalone confined configuration payload.
// | decodeConfStateBytes 解析独立的配置载荷。
func decodeConfStateBytes(data []byte) (ConfState, error) {
	d := decoder{src: data}
	cs := d.confState()
	if d.err != nil {
		return ConfState{}, d.err
	}
	if d.pos != len(data) {
		return ConfState{}, errs.Detail(ErrCorrupt, "trailing %d conf bytes", len(data)-d.pos)
	}
	return cs, nil
}

// decoder is a bounds-checked cursor over a wire payload. | decoder 是带边界检查的
// 线载荷游标。
type decoder struct {
	src []byte
	pos int
	err error
}

// fail records the first decode error. | fail 记录第一个解码错误。
func (d *decoder) fail(err error) {
	if d.err == nil {
		d.err = err
	}
}

// byte reads one byte. | byte 读取一个字节。
func (d *decoder) byte() byte {
	if d.err != nil {
		return 0
	}
	if d.pos >= len(d.src) {
		d.fail(errs.Detail(ErrCorrupt, "truncated byte"))
		return 0
	}
	b := d.src[d.pos]
	d.pos++
	return b
}

// uvarint reads an unsigned varint. | uvarint 读取无符号 varint。
func (d *decoder) uvarint() uint64 {
	if d.err != nil {
		return 0
	}
	v, n := binary.Uvarint(d.src[d.pos:])
	if n <= 0 {
		d.fail(errs.Detail(ErrCorrupt, "bad varint at %d", d.pos))
		return 0
	}
	d.pos += n
	return v
}

// take reads n bytes without copying. | take 读取 n 字节，不复制。
func (d *decoder) take(n int) []byte {
	if d.err != nil {
		return nil
	}
	if n < 0 || n > len(d.src)-d.pos {
		d.fail(errs.Detail(ErrCorrupt, "length %d past end", n))
		return nil
	}
	b := d.src[d.pos : d.pos+n]
	d.pos += n
	return b
}

// bytes reads a length-prefixed slice with a maximum. | bytes 读取带长度前缀且受上限
// 约束的切片。
func (d *decoder) bytes(max int) []byte {
	n := d.uvarint()
	if d.err != nil {
		return nil
	}
	if n > uint64(max) {
		d.fail(errs.Detail(ErrTooLarge, "field %d bytes", n))
		return nil
	}
	return d.take(int(n))
}

// string reads a length-prefixed string with a maximum. | string 读取带长度前缀且受
// 上限约束的字符串。
func (d *decoder) string(max int) string {
	return string(d.bytes(max))
}

// entries reads a contiguous entry list. | entries 读取连续日志项列表。
func (d *decoder) entries() []Entry {
	count := d.uvarint()
	if d.err != nil {
		return nil
	}
	if count > maxMessageEntries {
		d.fail(errs.Detail(ErrTooLarge, "entries %d", count))
		return nil
	}
	entries := make([]Entry, count)
	total := 0
	var prev uint64
	for i := range entries {
		var index uint64
		if i == 0 {
			index = d.uvarint()
		} else {
			delta := d.uvarint()
			if d.err != nil {
				return nil
			}
			if delta != 1 {
				d.fail(errs.Detail(ErrCorrupt, "entry delta %d", delta))
				return nil
			}
			index = prev + delta
		}
		if d.err != nil {
			return nil
		}
		term := d.uvarint()
		typ := EntryType(d.byte())
		data := d.bytes(maxEntryBytes - total)
		if d.err != nil {
			return nil
		}
		if term == 0 || index == 0 || typ > EntryBootstrap {
			d.fail(errs.Detail(ErrCorrupt, "bad entry index=%d term=%d type=%d", index, term, typ))
			return nil
		}
		total += len(data)
		if total > maxEntryBytes {
			d.fail(errs.Detail(ErrTooLarge, "entries total %d bytes", total))
			return nil
		}
		entries[i] = Entry{Index: index, Term: term, Type: typ, Data: data}
		prev = index
	}
	return entries
}

// snapshot reads a snapshot payload. | snapshot 读取快照载荷。
func (d *decoder) snapshot() *Snapshot {
	s := &Snapshot{
		Index:     d.uvarint(),
		Term:      d.uvarint(),
		ConfState: d.confState(),
		Data:      d.bytes(maxSnapshotBytes),
	}
	if d.err != nil {
		return nil
	}
	if s.Index == 0 || s.Term == 0 {
		d.fail(errs.Detail(ErrCorrupt, "snapshot index=%d term=%d", s.Index, s.Term))
		return nil
	}
	return s
}

// confState reads a serialized configuration. | confState 读取序列化配置。
func (d *decoder) confState() ConfState {
	lists := [4][]NodeID{}
	for i := range lists {
		count := d.uvarint()
		if d.err != nil {
			return ConfState{}
		}
		if count > maxConfNodes {
			d.fail(errs.Detail(ErrTooLarge, "conf nodes %d", count))
			return ConfState{}
		}
		list := make([]NodeID, count)
		for j := range list {
			list[j] = NodeID(d.uvarint())
			if d.err != nil {
				return ConfState{}
			}
			if list[j] == 0 {
				d.fail(errs.Detail(ErrCorrupt, "zero node in conf"))
				return ConfState{}
			}
		}
		lists[i] = list
	}
	count := d.uvarint()
	if d.err != nil {
		return ConfState{}
	}
	if count > maxConfNodes {
		d.fail(errs.Detail(ErrTooLarge, "addresses %d", count))
		return ConfState{}
	}
	addresses := make([]Peer, count)
	for i := range addresses {
		addresses[i].ID = NodeID(d.uvarint())
		addresses[i].Addr = d.string(maxAddressBytes)
		if d.err != nil {
			return ConfState{}
		}
		if addresses[i].ID == 0 {
			d.fail(errs.Detail(ErrCorrupt, "zero address node"))
			return ConfState{}
		}
	}
	return ConfState{
		Voters:           lists[0],
		Learners:         lists[1],
		VotersOutgoing:   lists[2],
		LearnersOutgoing: lists[3],
		Addresses:        addresses,
	}
}
