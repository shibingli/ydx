package ntlm

import (
	"encoding/binary"
	"time"

	"github.com/shibingli/ydx/errs"
)

// AVType identifies an MS-NLMP target-info AV pair. | AVType 标识一个 MS-NLMP
// target-info AV 对。
type AVType uint16

// Target-info AV pair identifiers from MS-NLMP 2.2.2.1. | MS-NLMP 2.2.2.1 的
// target-info AV 对标识。
const (
	// AVEndOfList terminates the AV pair sequence. | AVEndOfList 终止 AV 对序列。
	AVEndOfList AVType = 0
	// AVNbComputerName is the NetBIOS computer name. | AVNbComputerName 是 NetBIOS 计算机名。
	AVNbComputerName AVType = 1
	// AVNbDomainName is the NetBIOS domain name. | AVNbDomainName 是 NetBIOS 域名。
	AVNbDomainName AVType = 2
	// AVDNSComputerName is the DNS computer name. | AVDNSComputerName 是 DNS 计算机名。
	AVDNSComputerName AVType = 3
	// AVDNSDomainName is the DNS domain name. | AVDNSDomainName 是 DNS 域名。
	AVDNSDomainName AVType = 4
	// AVDNSTreeName is the DNS forest tree name. | AVDNSTreeName 是 DNS 林树名。
	AVDNSTreeName AVType = 5
	// AVFlags carries a 32-bit AV flag word. | AVFlags 携带 32 位 AV 标志字。
	AVFlags AVType = 6
	// AVTimestamp carries the server FILETIME. | AVTimestamp 携带服务端 FILETIME。
	AVTimestamp AVType = 7
	// AVRestrictions carries the MsvAvRestrictions structure. | AVRestrictions 携带
	// MsvAvRestrictions 结构。
	AVRestrictions AVType = 8
	// AVTargetName carries the service principal name. | AVTargetName 携带服务主体名称。
	AVTargetName AVType = 9
	// AVChannelBindings carries the 16-byte GSS channel-binding hash. |
	// AVChannelBindings 携带 16 字节 GSS 通道绑定哈希。
	AVChannelBindings AVType = 10
)

// AV flags carried by the AVFlags pair. | AVFlags 对携带的 AV 标志。
const (
	// AVFlagConstrainedAuth marks constrained authentication. | AVFlagConstrainedAuth
	// 标记约束认证。
	AVFlagConstrainedAuth uint32 = 0x00000001
	// AVFlagMICPresent requests a MIC in the Type 3 message. | AVFlagMICPresent 请求在
	// Type 3 消息中携带 MIC。
	AVFlagMICPresent uint32 = 0x00000002
	// AVFlagUntrustedTargetSPN marks an untrusted target SPN. | AVFlagUntrustedTargetSPN
	// 标记不可信的目标 SPN。
	AVFlagUntrustedTargetSPN uint32 = 0x00000004
)

// AVPair is one target-info AV pair. Value is arbitrary octets whose meaning
// depends on Type. | AVPair 是一个 target-info AV 对。Value 是任意八位组，其含义
// 取决于 Type。
type AVPair struct {
	// Value is the AV pair payload. | Value 是 AV 对载荷。
	Value []byte
	// Type is the AV pair identifier. | Type 是 AV 对标识。
	Type AVType
}

// TargetInfo is the ordered AV pair sequence carried in a Type 2 challenge and
// echoed by an NTLMv2 response. | TargetInfo 是 Type 2 挑战携带、并由 NTLMv2 响应回显的
// 有序 AV 对序列。
type TargetInfo []AVPair

// ParseTargetInfo parses an AV pair sequence that must be terminated by an
// AVEndOfList pair, as MS-NLMP 2.2.2.1 requires. Trailing bytes after the
// terminator are rejected. | ParseTargetInfo 解析必须以 AVEndOfList 对终止的 AV 对
// 序列，这是 MS-NLMP 2.2.2.1 的要求。终止符之后的多余字节会被拒绝。
func ParseTargetInfo(data []byte) (TargetInfo, error) {
	info := make(TargetInfo, 0, 8)
	sawEnd := false
	for offset := 0; offset < len(data); {
		if len(data)-offset < 4 {
			return nil, errs.Detail(ErrTargetInfo, "AV pair header is truncated | AV 对头部被截断")
		}
		id := AVType(binary.LittleEndian.Uint16(data[offset : offset+2]))
		length := int(binary.LittleEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4
		if length > len(data)-offset {
			return nil, errs.Detail(ErrTargetInfo, "AV pair %d length %d exceeds remaining bytes | AV 对 %d 长度 %d 超过剩余字节", id, length, id, length)
		}
		value := make([]byte, length)
		copy(value, data[offset:offset+length])
		offset += length
		info = append(info, AVPair{Type: id, Value: value})
		if id == AVEndOfList {
			if length != 0 {
				return nil, errs.Detail(ErrTargetInfo, "AVEndOfList has nonzero length | AVEndOfList 长度非零")
			}
			if offset != len(data) {
				return nil, errs.Detail(ErrTargetInfo, "bytes follow AVEndOfList | AVEndOfList 之后仍有字节")
			}
			sawEnd = true
			break
		}
	}
	if !sawEnd {
		return nil, errs.Detail(ErrTargetInfo, "target info lacks AVEndOfList | 目标信息缺少 AVEndOfList")
	}
	if err := info.Validate(); err != nil {
		return nil, err
	}
	return info, nil
}

// Validate checks the structural rules this client relies on. Duplicate
// security-relevant AV pairs are rejected so a server cannot smuggle two
// conflicting timestamps, flag words or channel bindings. | Validate 检查本客户端
// 依赖的结构规则。安全相关的重复 AV 对被拒绝，防止服务端夹带两个冲突的时间戳、标志字或
// 通道绑定。
func (t TargetInfo) Validate() error {
	seen := make(map[AVType]struct{}, len(t))
	for index, pair := range t {
		switch pair.Type {
		case AVEndOfList:
			if len(pair.Value) != 0 {
				return errs.Detail(ErrTargetInfo, "AVEndOfList has nonzero length | AVEndOfList 长度非零")
			}
			if index != len(t)-1 {
				return errs.Detail(ErrTargetInfo, "AVEndOfList is not last | AVEndOfList 不在末尾")
			}
		case AVFlags:
			if len(pair.Value) != 4 {
				return errs.Detail(ErrTargetInfo, "AVFlags length %d, want 4 | AVFlags 长度 %d，期望 4", len(pair.Value), len(pair.Value))
			}
		case AVTimestamp:
			if len(pair.Value) != 8 {
				return errs.Detail(ErrTargetInfo, "AVTimestamp length %d, want 8 | AVTimestamp 长度 %d，期望 8", len(pair.Value), len(pair.Value))
			}
		case AVChannelBindings:
			if len(pair.Value) != 16 {
				return errs.Detail(ErrTargetInfo, "AVChannelBindings length %d, want 16 | AVChannelBindings 长度 %d，期望 16", len(pair.Value), len(pair.Value))
			}
		case AVNbComputerName, AVNbDomainName, AVDNSComputerName, AVDNSDomainName, AVDNSTreeName, AVTargetName:
			if len(pair.Value)%2 != 0 {
				return errs.Detail(ErrTargetInfo, "AV pair %d UTF-16LE value has odd length %d | AV 对 %d 的 UTF-16LE 值长度为奇数 %d", pair.Type, len(pair.Value), pair.Type, len(pair.Value))
			}
		}
		if pair.Type != AVEndOfList {
			if _, duplicate := seen[pair.Type]; duplicate && (pair.Type == AVFlags || pair.Type == AVTimestamp || pair.Type == AVChannelBindings) {
				return errs.Detail(ErrTargetInfo, "duplicate AV pair %d | 重复的 AV 对 %d", pair.Type, pair.Type)
			}
			seen[pair.Type] = struct{}{}
		}
	}
	return nil
}

// Encode serializes the AV pair sequence with a terminating AVEndOfList pair. |
// Encode 序列化 AV 对序列并追加终止的 AVEndOfList 对。
func (t TargetInfo) Encode() ([]byte, error) {
	size := 4
	for _, pair := range t {
		if pair.Type == AVEndOfList {
			continue
		}
		if err := checkFieldSize("AV pair value", pair.Value); err != nil {
			return nil, err
		}
		size += 4 + len(pair.Value)
	}
	out := make([]byte, 0, size)
	for _, pair := range t {
		if pair.Type == AVEndOfList {
			continue
		}
		var header [4]byte
		binary.LittleEndian.PutUint16(header[0:2], uint16(pair.Type))
		binary.LittleEndian.PutUint16(header[2:4], uint16(len(pair.Value)))
		out = append(out, header[:]...)
		out = append(out, pair.Value...)
	}
	return append(out, 0, 0, 0, 0), nil
}

// Get returns a copy of the first value for id. | Get 返回 id 对应第一个值的副本。
func (t TargetInfo) Get(id AVType) ([]byte, bool) {
	for _, pair := range t {
		if pair.Type == id {
			value := make([]byte, len(pair.Value))
			copy(value, pair.Value)
			return value, true
		}
	}
	return nil, false
}

// Flags returns the AVFlags value. | Flags 返回 AVFlags 值。
func (t TargetInfo) Flags() (uint32, bool) {
	value, ok := t.Get(AVFlags)
	if !ok || len(value) != 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(value), true
}

// Timestamp returns the server timestamp from the AVTimestamp pair. | Timestamp
// 返回 AVTimestamp 对中的服务端时间戳。
func (t TargetInfo) Timestamp() (time.Time, bool) {
	value, ok := t.Get(AVTimestamp)
	if !ok || len(value) != 8 {
		return time.Time{}, false
	}
	return timeFromFiletime(binary.LittleEndian.Uint64(value)), true
}

// Clone returns a deep copy. | Clone 返回深拷贝。
func (t TargetInfo) Clone() TargetInfo {
	if t == nil {
		return nil
	}
	out := make(TargetInfo, len(t))
	for index, pair := range t {
		out[index] = AVPair{Type: pair.Type, Value: append([]byte(nil), pair.Value...)}
	}
	return out
}

// withoutEndOfList returns a deep copy with AVEndOfList pairs removed. |
// withoutEndOfList 返回移除 AVEndOfList 对后的深拷贝。
func (t TargetInfo) withoutEndOfList() TargetInfo {
	out := make(TargetInfo, 0, len(t))
	for _, pair := range t {
		if pair.Type == AVEndOfList {
			continue
		}
		out = append(out, AVPair{Type: pair.Type, Value: append([]byte(nil), pair.Value...)})
	}
	return out
}

// set replaces the first pair with id or appends a new pair. | set 替换第一个 id 对，
// 或追加新对。
func (t *TargetInfo) set(id AVType, value []byte) {
	copied := append([]byte(nil), value...)
	for index := range *t {
		if (*t)[index].Type == id {
			(*t)[index].Value = copied
			return
		}
	}
	*t = append(*t, AVPair{Type: id, Value: copied})
}

// filetimeEpochOffsetSeconds is the number of seconds between the FILETIME
// epoch (1601-01-01) and the Unix epoch. | filetimeEpochOffsetSeconds 是 FILETIME
// 纪元（1601-01-01）与 Unix 纪元之间的秒数。
const filetimeEpochOffsetSeconds = 11644473600

// filetimeFromTime converts t to a Windows FILETIME. Zero, pre-1601 and
// overflowing values become zero. | filetimeFromTime 把 t 转换为 Windows FILETIME。
// 零值、1601 年之前以及溢出的值变为零。
func filetimeFromTime(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	adjusted := t.Unix() + filetimeEpochOffsetSeconds
	if adjusted < 0 {
		return 0
	}
	const maxValue = ^uint64(0)
	fraction := uint64(t.Nanosecond()) / 100
	if uint64(adjusted) > (maxValue-fraction)/10_000_000 {
		return 0
	}
	return uint64(adjusted)*10_000_000 + fraction
}

// timeFromFiletime converts a Windows FILETIME to UTC. | timeFromFiletime 把 Windows
// FILETIME 转换为 UTC。
func timeFromFiletime(ticks uint64) time.Time {
	seconds := int64(ticks/10_000_000) - filetimeEpochOffsetSeconds
	nanoseconds := int64(ticks%10_000_000) * 100
	return time.Unix(seconds, nanoseconds).UTC()
}
