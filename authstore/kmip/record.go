package kmip

import (
	"time"

	kmipcore "github.com/shibingli/ydx/auth/keymgmt/kmip"
	"github.com/shibingli/ydx/errs"
	ydxjson "github.com/shibingli/ydx/json"
)

// Hash field names used by the record scripts. | 记录脚本使用的哈希字段名。
const (
	// fieldData holds the JSON form of one ObjectRecord. | fieldData 保存单个 ObjectRecord 的 JSON 形式。
	fieldData = "data"
	// fieldRevision holds the compare-and-set revision token. | fieldRevision 保存比较并交换的修订令牌。
	fieldRevision = "rev"
)

// encodeRecord returns the JSON form of record with every non-zero time normalized to UTC. The
// caller's value is not modified. | encodeRecord 返回 record 的 JSON 形式，并把每个非零时间规范化
// 为 UTC；调用方的值不会被修改。
func encodeRecord(record kmipcore.ObjectRecord) ([]byte, error) {
	normalized := record
	normalizeRecordTimes(&normalized)
	data, err := ydxjson.Marshal(normalized)
	if err != nil {
		return nil, errs.Detail(kmipcore.ErrInvalidRequest, "record cannot be encoded | 记录无法编码")
	}
	return data, nil
}

// decodeRecord parses one stored record and normalizes its times to UTC. The returned value owns
// fresh slices, attribute trees and key material, so it never aliases the stored bytes or another
// caller. | decodeRecord 解析一条已存记录并把其时间规范化为 UTC。返回值持有全新的切片、属性树与
// 密钥材料，绝不与已存字节或其它调用方共享。
func decodeRecord(data []byte) (kmipcore.ObjectRecord, error) {
	if len(data) == 0 {
		return kmipcore.ObjectRecord{}, errs.Detail(ErrStoreUnavailable, "stored record is empty | 存储的记录为空")
	}
	var record kmipcore.ObjectRecord
	if err := ydxjson.Unmarshal(data, &record); err != nil {
		return kmipcore.ObjectRecord{}, errs.Detail(ErrStoreUnavailable, "stored record is corrupt | 存储的记录数据损坏")
	}
	if record.UniqueIdentifier == "" {
		return kmipcore.ObjectRecord{}, errs.Detail(ErrStoreUnavailable,
			"stored record has no unique identifier | 存储的记录没有唯一标识符")
	}
	normalizeRecordTimes(&record)
	return record, nil
}

// normalizeRecordTimes converts every non-zero date of record to UTC and keeps zero values in
// their canonical form. | normalizeRecordTimes 把 record 的每个非零日期转换为 UTC，并保持零值的
// 规范形态。
func normalizeRecordTimes(record *kmipcore.ObjectRecord) {
	if record == nil {
		return
	}
	record.InitialDate = utcTime(record.InitialDate)
	record.OriginalCreationDate = utcTime(record.OriginalCreationDate)
	record.ActivationDate = utcTime(record.ActivationDate)
	record.DeactivationDate = utcTime(record.DeactivationDate)
	record.CompromiseDate = utcTime(record.CompromiseDate)
	record.CompromiseOccurrenceDate = utcTime(record.CompromiseOccurrenceDate)
	record.DestroyDate = utcTime(record.DestroyDate)
	record.ArchiveDate = utcTime(record.ArchiveDate)
	record.LastChangeDate = utcTime(record.LastChangeDate)
}

// utcTime normalizes a non-zero time to UTC and keeps the zero value canonical.
// | utcTime 把非零时间规范化为 UTC，并保持零值的规范形态。
func utcTime(t time.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}
	return t.UTC()
}
