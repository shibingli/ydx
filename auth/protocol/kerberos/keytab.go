package kerberos

import (
	"encoding/binary"
	"os"
	"time"

	"github.com/shibingli/ydx/errs"
)

// keyTabVersion is the MIT keytab format version. | keyTabVersion 是 MIT keytab 格式版本。
const keyTabVersion = 0x0502

// KeyTabEntry is one decrypted keytab record. | KeyTabEntry 是一条解密后的 keytab 记录。
type KeyTabEntry struct {
	// Principal is the principal name. | Principal 是主体名称。
	Principal PrincipalName
	// Realm is the principal realm. | Realm 是主体所属 realm。
	Realm string
	// Timestamp is the entry creation time. | Timestamp 是条目创建时间。
	Timestamp time.Time
	// KVNO is the key version number; zero means unknown. | KVNO 是密钥版本号；零表示未知。
	KVNO int32
	// Key is the protocol key. | Key 是协议密钥。
	Key EncryptionKey
}

// KeyTab is an in-memory MIT keytab. | KeyTab 是内存中的 MIT keytab。
type KeyTab struct {
	entries []KeyTabEntry
}

// NewKeyTab builds a keytab from entries and preserves duplicates and ordering. | NewKeyTab
// 从条目构建 keytab，并保留重复项与顺序。
func NewKeyTab(entries []KeyTabEntry) *KeyTab {
	return &KeyTab{entries: append([]KeyTabEntry(nil), entries...)}
}

// Entries returns a copy of the keytab entries. | Entries 返回 keytab 条目的副本。
func (k *KeyTab) Entries() []KeyTabEntry {
	if k == nil {
		return nil
	}
	return append([]KeyTabEntry(nil), k.entries...)
}

// ParseKeyTab parses an MIT keytab version 0x0502 image. Duplicate entries and
// entries with either the 8-bit or 32-bit key version are preserved. | ParseKeyTab
// 解析 MIT keytab 0x0502 镜像。重复条目以及带 8 位或 32 位密钥版本的条目都会被保留。
func ParseKeyTab(data []byte) (*KeyTab, error) {
	if len(data) < 2 {
		return nil, errs.Detail(ErrKeytab, "keytab is %d bytes, minimum 2 | keytab 为 %d 字节，至少 2", len(data), len(data))
	}
	if version := binary.BigEndian.Uint16(data); version != keyTabVersion {
		return nil, errs.Detail(ErrKeytab, "keytab version 0x%04x, want 0x%04x | keytab 版本 0x%04x，期望 0x%04x",
			version, keyTabVersion, version, keyTabVersion)
	}
	tab := &KeyTab{}
	offset := 2
	for offset < len(data) {
		if len(data)-offset < 4 {
			return nil, errs.Detail(ErrKeytab, "truncated keytab entry size | keytab 条目长度被截断")
		}
		size := int(int32(binary.BigEndian.Uint32(data[offset:])))
		offset += 4
		if size < 0 || size > len(data)-offset {
			return nil, errs.Detail(ErrKeytab, "keytab entry size %d with %d bytes remaining | keytab 条目长度 %d，剩余 %d 字节",
				size, len(data)-offset, size, len(data)-offset)
		}
		entryData := data[offset : offset+size]
		offset += size
		entry, err := parseKeyTabEntry(entryData)
		if err != nil {
			return nil, err
		}
		tab.entries = append(tab.entries, entry)
	}
	if len(tab.entries) == 0 {
		return nil, errs.Detail(ErrKeytab, "keytab contains no entries | keytab 不包含条目")
	}
	return tab, nil
}

// parseKeyTabEntry decodes one size-delimited keytab record. | parseKeyTabEntry 解码一条
// 以长度分隔的 keytab 记录。
func parseKeyTabEntry(data []byte) (KeyTabEntry, error) {
	var entry KeyTabEntry
	offset := 0
	need := func(n int) error {
		if len(data)-offset < n {
			return errs.Detail(ErrKeytab, "truncated keytab entry at offset %d | keytab 条目在偏移 %d 处被截断", offset, offset)
		}
		return nil
	}
	if err := need(2); err != nil {
		return entry, err
	}
	components := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if components == 0 {
		return entry, errs.Detail(ErrKeytab, "keytab entry has no principal components | keytab 条目没有主体组成部分")
	}
	realm, err := readKeyTabString(data, &offset)
	if err != nil {
		return entry, err
	}
	names := make([]string, 0, components)
	for i := 0; i < components; i++ {
		if err := need(2); err != nil {
			return entry, err
		}
		length := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		if err := need(length); err != nil {
			return entry, err
		}
		names = append(names, string(data[offset:offset+length]))
		offset += length
	}
	if err := need(4 + 4 + 1 + 2 + 2); err != nil {
		return entry, err
	}
	nameType := int32(binary.BigEndian.Uint32(data[offset:]))
	offset += 4
	timestamp := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	kvno8 := int32(data[offset])
	offset++
	etype := int32(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	keyLength := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if err := need(keyLength); err != nil {
		return entry, err
	}
	keyValue := append([]byte(nil), data[offset:offset+keyLength]...)
	offset += keyLength
	kvno := kvno8
	remaining := len(data) - offset
	switch {
	case remaining == 0:
	case remaining == 4:
		kvno32 := int32(binary.BigEndian.Uint32(data[offset:]))
		if kvno32 != 0 {
			kvno = kvno32
		}
		offset += 4
	default:
		return entry, errs.Detail(ErrKeytab, "keytab entry has %d trailing bytes | keytab 条目有 %d 个尾随字节",
			remaining, remaining)
	}
	entry = KeyTabEntry{
		Principal: PrincipalName{NameType: nameType, NameString: names},
		Realm:     realm,
		Timestamp: time.Unix(int64(timestamp), 0).UTC(),
		KVNO:      kvno,
		Key:       EncryptionKey{KeyType: etype, KeyValue: keyValue},
	}
	return entry, nil
}

// readKeyTabString reads one counted octet string. | readKeyTabString 读取一个带计数的
// 八位组字符串。
func readKeyTabString(data []byte, offset *int) (string, error) {
	if len(data)-*offset < 2 {
		return "", errs.Detail(ErrKeytab, "truncated keytab string length | keytab 字符串长度被截断")
	}
	length := int(binary.BigEndian.Uint16(data[*offset:]))
	*offset += 2
	if len(data)-*offset < length {
		return "", errs.Detail(ErrKeytab, "truncated keytab string | keytab 字符串被截断")
	}
	value := string(data[*offset : *offset+length])
	*offset += length
	return value, nil
}

// ReadKeyTabFile reads and parses a keytab file. | ReadKeyTabFile 读取并解析 keytab 文件。
func ReadKeyTabFile(path string) (*KeyTab, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrKeytab, "cannot read keytab file | 无法读取 keytab 文件")
	}
	return ParseKeyTab(data)
}

// Lookup returns the best matching keytab entry. Matching uses the principal
// components and realm only; the principal name type is ignored as in MIT ktutil
// and krb5_kt_get_entry. A zero realm ignores the realm, a zero etype ignores
// the encryption type, and a zero kvno selects the highest version. | Lookup
// 返回最匹配的 keytab 条目。匹配只使用主体组成部分与 realm，像 MIT ktutil 与
// krb5_kt_get_entry 一样忽略主体名称类型。realm 为零值时忽略 realm，etype 为零值时
// 忽略加密类型，kvno 为零值时选择最高版本。
func (k *KeyTab) Lookup(principal PrincipalName, realm string, etype int32, kvno int32) (KeyTabEntry, error) {
	if k == nil {
		return KeyTabEntry{}, errs.Detail(ErrNoKey, "nil keytab | keytab 为空")
	}
	found := false
	var best KeyTabEntry
	for _, entry := range k.entries {
		if !equalPrincipalComponents(entry.Principal, principal) {
			continue
		}
		if realm != "" && entry.Realm != realm {
			continue
		}
		if etype != 0 && entry.Key.KeyType != etype {
			continue
		}
		if kvno != 0 && entry.KVNO != kvno {
			continue
		}
		if !found || entry.KVNO > best.KVNO {
			best = entry
			found = true
		}
	}
	if !found {
		return KeyTabEntry{}, errs.Detail(ErrNoKey, "principal %s, realm %s, enctype %d, kvno %d | 主体 %s，realm %s，加密类型 %d，kvno %d",
			principal.String(), realm, etype, kvno, principal.String(), realm, etype, kvno)
	}
	return best, nil
}
