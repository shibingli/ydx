package ntlm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

// encodeTestTargetInfo encodes pairs without the automatic terminator. |
// encodeTestTargetInfo 编码不含自动终止符的 AV 对。
func encodeTestTargetInfo(t *testing.T, pairs TargetInfo) []byte {
	t.Helper()
	out := make([]byte, 0, 64)
	for _, pair := range pairs {
		var header [4]byte
		binary.LittleEndian.PutUint16(header[0:2], uint16(pair.Type))
		binary.LittleEndian.PutUint16(header[2:4], uint16(len(pair.Value)))
		out = append(out, header[:]...)
		out = append(out, pair.Value...)
	}
	return out
}

func TestParseTargetInfoRoundTrip(t *testing.T) {
	timestamp := testTimestamp()
	timestampBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestampBytes, filetimeFromTime(timestamp))
	flags := make([]byte, 4)
	binary.LittleEndian.PutUint32(flags, AVFlagMICPresent|AVFlagConstrainedAuth)
	bindings := bytes.Repeat([]byte{0x5a}, 16)
	original := TargetInfo{
		{Type: AVNbDomainName, Value: encodeString("Domain", true)},
		{Type: AVNbComputerName, Value: encodeString("SERVER", true)},
		{Type: AVDNSComputerName, Value: encodeString("server.example.com", true)},
		{Type: AVFlags, Value: flags},
		{Type: AVTimestamp, Value: timestampBytes},
		{Type: AVChannelBindings, Value: bindings},
		{Type: AVTargetName, Value: encodeString("ldap/server.example.com", true)},
	}
	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	parsed, err := ParseTargetInfo(encoded)
	if err != nil {
		t.Fatalf("ParseTargetInfo: %v", err)
	}
	trimmed := parsed.withoutEndOfList()
	if len(trimmed) != len(original) {
		t.Fatalf("parsed %d pairs, want %d", len(trimmed), len(original))
	}
	for index := range original {
		if trimmed[index].Type != original[index].Type || !bytes.Equal(trimmed[index].Value, original[index].Value) {
			t.Fatalf("pair %d = %#v, want %#v", index, trimmed[index], original[index])
		}
	}
	gotFlags, ok := parsed.Flags()
	if !ok || gotFlags != AVFlagMICPresent|AVFlagConstrainedAuth {
		t.Fatalf("flags = %#x, %v", gotFlags, ok)
	}
	gotTime, ok := parsed.Timestamp()
	if !ok || !gotTime.Equal(timestamp) {
		t.Fatalf("timestamp = %v, %v, want %v", gotTime, ok, timestamp)
	}
	value, ok := parsed.Get(AVNbComputerName)
	if !ok || string(value) != string(encodeString("SERVER", true)) {
		t.Fatalf("computer name = %x, %v", value, ok)
	}
	if _, ok := parsed.Get(AVDNSTreeName); ok {
		t.Fatalf("unexpected DNSTreeName")
	}
	reencoded, err := parsed.withoutEndOfList().Encode()
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if !bytes.Equal(reencoded, encoded) {
		t.Fatalf("re-encoded target info differs")
	}
}

func TestParseTargetInfoRequiresEndOfList(t *testing.T) {
	raw := encodeTestTargetInfo(t, TargetInfo{{Type: AVNbDomainName, Value: encodeString("Domain", true)}})
	if _, err := ParseTargetInfo(raw); !errors.Is(err, ErrTargetInfo) {
		t.Fatalf("error = %v, want ErrTargetInfo", err)
	}
	if _, err := ParseTargetInfo(nil); !errors.Is(err, ErrTargetInfo) {
		t.Fatalf("empty error = %v, want ErrTargetInfo", err)
	}
}

func TestParseTargetInfoMalformed(t *testing.T) {
	oddName := []byte{1, 0, 1, 0, 'a', 0, 0, 0}
	tests := []struct {
		name string
		data []byte
	}{
		{name: "truncated header", data: []byte{2, 0, 0}},
		{name: "value exceeds data", data: []byte{2, 0, 4, 0, 1}},
		{name: "nonzero EOL length", data: []byte{0, 0, 1, 0, 0}},
		{name: "bytes after EOL", data: []byte{0, 0, 0, 0, 0, 0, 0, 0}},
		{name: "odd UTF-16 name", data: oddName},
		{name: "duplicate flags", data: []byte{6, 0, 4, 0, 2, 0, 0, 0, 6, 0, 4, 0, 2, 0, 0, 0, 0, 0, 0, 0}},
		{name: "duplicate timestamp", data: []byte{7, 0, 8, 0, 1, 2, 3, 4, 5, 6, 7, 8, 7, 0, 8, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0}},
		{name: "duplicate channel bindings", data: append(append([]byte{10, 0, 16, 0}, make([]byte, 16)...), append([]byte{10, 0, 16, 0}, append(make([]byte, 16), 0, 0, 0, 0)...)...)},
		{name: "flags length", data: []byte{6, 0, 3, 0, 1, 2, 3, 0, 0, 0}},
		{name: "timestamp length", data: []byte{7, 0, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0}},
		{name: "channel bindings length", data: append(append([]byte{10, 0, 15, 0}, make([]byte, 15)...), 0, 0, 0, 0)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseTargetInfo(test.data); !errors.Is(err, ErrTargetInfo) {
				t.Fatalf("error = %v, want ErrTargetInfo", err)
			}
		})
	}
}

func TestTargetInfoValidate(t *testing.T) {
	valid := TargetInfo{
		{Type: AVNbDomainName, Value: encodeString("Domain", true)},
		{Type: AVFlags, Value: make([]byte, 4)},
		{Type: AVEndOfList},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid target info: %v", err)
	}
	tests := []struct {
		name string
		info TargetInfo
	}{
		{name: "EOL with value", info: TargetInfo{{Type: AVEndOfList, Value: []byte{1}}}},
		{name: "EOL not last", info: TargetInfo{{Type: AVEndOfList}, {Type: AVNbDomainName, Value: []byte{0, 0}}}},
		{name: "flags length", info: TargetInfo{{Type: AVFlags, Value: make([]byte, 3)}}},
		{name: "timestamp length", info: TargetInfo{{Type: AVTimestamp, Value: make([]byte, 7)}}},
		{name: "channel bindings length", info: TargetInfo{{Type: AVChannelBindings, Value: make([]byte, 15)}}},
		{name: "odd name", info: TargetInfo{{Type: AVNbComputerName, Value: []byte{1}}}},
		{name: "duplicate flags", info: TargetInfo{{Type: AVFlags, Value: make([]byte, 4)}, {Type: AVFlags, Value: make([]byte, 4)}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.info.Validate(); !errors.Is(err, ErrTargetInfo) {
				t.Fatalf("error = %v, want ErrTargetInfo", err)
			}
		})
	}
}

func TestTargetInfoEncodeSkipsExistingEndOfList(t *testing.T) {
	info := TargetInfo{
		{Type: AVNbDomainName, Value: encodeString("Domain", true)},
		{Type: AVEndOfList},
	}
	encoded, err := info.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(encoded[len(encoded)-4:], []byte{0, 0, 0, 0}) {
		t.Fatalf("missing EOL: %x", encoded)
	}
	if bytes.Count(encoded, []byte{0, 0, 0, 0}) < 1 {
		t.Fatalf("unexpected encoding: %x", encoded)
	}
	if len(encoded) != 4+len(encodeString("Domain", true))+4 {
		t.Fatalf("length = %d", len(encoded))
	}
	if _, err := (TargetInfo{{Type: AVNbDomainName, Value: make([]byte, 65536)}}).Encode(); !errors.Is(err, ErrMessage) {
		t.Fatalf("oversized value error = %v", err)
	}
	if encoded, err := (TargetInfo(nil)).Encode(); err != nil || !bytes.Equal(encoded, []byte{0, 0, 0, 0}) {
		t.Fatalf("nil encode = %x, %v", encoded, err)
	}
}

func TestTargetInfoGetFlagsTimestamp(t *testing.T) {
	var empty TargetInfo
	if value, ok := empty.Get(AVFlags); ok || value != nil {
		t.Fatalf("empty Get = %x, %v", value, ok)
	}
	if flags, ok := empty.Flags(); ok || flags != 0 {
		t.Fatalf("empty Flags = %x, %v", flags, ok)
	}
	if timestamp, ok := empty.Timestamp(); ok || !timestamp.IsZero() {
		t.Fatalf("empty Timestamp = %v, %v", timestamp, ok)
	}
	short := TargetInfo{{Type: AVFlags, Value: make([]byte, 3)}, {Type: AVTimestamp, Value: make([]byte, 7)}}
	if flags, ok := short.Flags(); ok || flags != 0 {
		t.Fatalf("short Flags = %x, %v", flags, ok)
	}
	if timestamp, ok := short.Timestamp(); ok || !timestamp.IsZero() {
		t.Fatalf("short Timestamp = %v, %v", timestamp, ok)
	}
}

func TestTargetInfoClone(t *testing.T) {
	if cloned := TargetInfo(nil).Clone(); cloned != nil {
		t.Fatalf("nil clone = %#v", cloned)
	}
	original := TargetInfo{{Type: AVNbDomainName, Value: []byte{1, 2}}}
	cloned := original.Clone()
	cloned[0].Value[0] = 9
	if original[0].Value[0] != 1 {
		t.Fatalf("clone shares storage")
	}
	trimmed := TargetInfo{{Type: AVNbDomainName, Value: []byte{1}}, {Type: AVEndOfList}}.withoutEndOfList()
	if len(trimmed) != 1 || trimmed[0].Type != AVNbDomainName {
		t.Fatalf("withoutEndOfList = %#v", trimmed)
	}
	trimmed[0].Value[0] = 7
	if original[0].Value[0] != 1 {
		t.Fatalf("withoutEndOfList shares storage")
	}
}

func TestTargetInfoSet(t *testing.T) {
	info := TargetInfo{{Type: AVFlags, Value: []byte{1, 0, 0, 0}}}
	info.set(AVFlags, []byte{2, 0, 0, 0})
	if len(info) != 1 || info[0].Value[0] != 2 {
		t.Fatalf("replace = %#v", info)
	}
	info.set(AVTimestamp, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	if len(info) != 2 || info[1].Type != AVTimestamp {
		t.Fatalf("append = %#v", info)
	}
	source := []byte{9, 9, 9, 9}
	info.set(AVFlags, source)
	source[0] = 0
	if info[0].Value[0] != 9 {
		t.Fatalf("set did not copy")
	}
}

func TestFiletimeConversion(t *testing.T) {
	if got := filetimeFromTime(time.Time{}); got != 0 {
		t.Fatalf("zero time filetime = %d", got)
	}
	if got := filetimeFromTime(time.Date(1500, 1, 1, 0, 0, 0, 0, time.UTC)); got != 0 {
		t.Fatalf("pre-1601 filetime = %d", got)
	}
	if got := filetimeFromTime(time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)); got != 0 {
		t.Fatalf("1601 filetime = %d", got)
	}
	if got := filetimeFromTime(time.Unix(1e13, 0)); got != 0 {
		t.Fatalf("overflow filetime = %d", got)
	}
	moment := time.Date(2023, 11, 14, 22, 13, 20, 123456700, time.UTC)
	ticks := filetimeFromTime(moment)
	const unixToFiletimeSeconds = 11644473600
	wantTicks := uint64(1700000000+unixToFiletimeSeconds)*10_000_000 + 1234567
	if ticks != wantTicks {
		t.Fatalf("filetime = %d, want %d", ticks, wantTicks)
	}
	roundTrip := timeFromFiletime(ticks)
	if !roundTrip.Equal(moment) {
		t.Fatalf("round trip = %v, want %v", roundTrip, moment)
	}
	if got, want := timeFromFiletime(0), time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("epoch = %v, want %v", got, want)
	}
}

func TestTargetInfoEncodedVector(t *testing.T) {
	// The MS-NLMP 4.2.4 target information, kept as a hex vector so a byte-order
	// regression fails loudly. | MS-NLMP 4.2.4 目标信息，保留为十六进制向量，使字节序
	// 回归能被明确发现。
	raw, err := hex.DecodeString("02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000")
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	parsed, err := ParseTargetInfo(raw)
	if err != nil {
		t.Fatalf("ParseTargetInfo: %v", err)
	}
	encoded, err := parsed.withoutEndOfList().Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(encoded, raw) {
		t.Fatalf("encoded = %x, want %x", encoded, raw)
	}
}
