package saml

import (
	"context"
	"encoding/binary"
	"time"

	samlapi "github.com/shibingli/ydx/auth/protocol/saml"
	"github.com/shibingli/ydx/errs"
)

// SaveArtifact stores an artifact record and reports saml.ErrReplay when an unexpired record with
// the same artifact already exists. A nil or empty record, a non-HTTP artifact type, or an
// artifact already expired at now reports saml.ErrArtifactInvalid or saml.ErrResponseExpired as
// appropriate. An expired existing record may be replaced. | SaveArtifact 保存工件记录，并在相同
// 工件存在未过期记录时返回 saml.ErrReplay。空记录、非 HTTP 工件类型或 now 时已过期的工件分别返回
// saml.ErrArtifactInvalid 或 saml.ErrResponseExpired。已过期的既有记录可被替换。
func (s *Stores) SaveArtifact(ctx context.Context, record *samlapi.ArtifactRecord, now time.Time) error {
	if err := s.ensure(); err != nil {
		return err
	}
	if record == nil || len(record.Message) == 0 {
		return errs.Detail(samlapi.ErrArtifactInvalid, "artifact record is empty | 工件记录为空")
	}
	if record.Artifact.Type != samlapi.ArtifactTypeHTTP {
		return errs.Detail(samlapi.ErrArtifactInvalid, "artifact type 0x%04x | 工件类型 0x%04x",
			record.Artifact.Type, record.Artifact.Type)
	}
	if !record.ExpiresAt.IsZero() && !now.Before(record.ExpiresAt) {
		return errs.Detail(samlapi.ErrResponseExpired, "artifact already expired | 工件已过期")
	}
	data, err := encodeArtifact(record)
	if err != nil {
		return err
	}
	hasExpiry, expireSec, expireNsec := expiryFields(record.ExpiresAt)
	nowSec, nowNsec := clockFields(now)
	member := s.keys.artifact(artifactStoreKey(record.Artifact))
	code, err := s.runInt(ctx, scriptArtifactSave, "save artifact",
		[]string{member, s.keys.artifactsExpiry()},
		string(data), flag(record.Used), hasExpiry, expireSec, expireNsec, nowSec, nowNsec, member)
	if err != nil {
		return err
	}
	switch code {
	case 0:
		return nil
	case 1:
		return errs.Detail(samlapi.ErrReplay, "artifact already exists | 工件已存在")
	default:
		return errs.Detail(ErrStoreUnavailable, "save artifact returned %d | 保存工件返回 %d", code, code)
	}
}

// TakeArtifact atomically consumes an artifact and returns a deep copy with Used set. Unknown
// artifacts report saml.ErrArtifactInvalid, expired artifacts report saml.ErrResponseExpired and
// replays report saml.ErrReplay. The expired record is removed when discovered. | TakeArtifact 原子
// 消费工件并返回 Used 已置位的深拷贝。未知工件返回 saml.ErrArtifactInvalid，过期工件返回
// saml.ErrResponseExpired，重放返回 saml.ErrReplay。发现过期记录时将其删除。
func (s *Stores) TakeArtifact(ctx context.Context, artifact samlapi.Artifact, now time.Time) (*samlapi.ArtifactRecord, error) {
	if err := s.ensure(); err != nil {
		return nil, err
	}
	nowSec, nowNsec := clockFields(now)
	member := s.keys.artifact(artifactStoreKey(artifact))
	reply, err := s.runSlice(ctx, scriptArtifactTake, "take artifact",
		[]string{member, s.keys.artifactsExpiry()}, nowSec, nowNsec, member)
	if err != nil {
		return nil, err
	}
	if len(reply) < 2 {
		return nil, errs.Detail(ErrStoreUnavailable, "take artifact returned an invalid reply | 消费工件返回无效应答")
	}
	switch stringValue(reply[0]) {
	case "-1":
		return nil, errs.Detail(samlapi.ErrArtifactInvalid, "unknown artifact | 未知工件")
	case "-2":
		return nil, errs.Detail(samlapi.ErrReplay, "artifact already resolved | 工件已解析")
	case "-3":
		return nil, errs.Detail(samlapi.ErrResponseExpired, "artifact expired | 工件已过期")
	case "0":
		record, decodeErr := decodeArtifact([]byte(stringValue(reply[1])))
		if decodeErr != nil {
			return nil, decodeErr
		}
		record.Used = true
		return record, nil
	default:
		return nil, errs.Detail(ErrStoreUnavailable, "take artifact returned an unknown status | 消费工件返回未知状态")
	}
}

// artifactStoreKey returns the store lookup key of artifact. It covers the type, source identifier
// and message handle but not the endpoint index, matching the lookup key used by the in-memory
// SAML store. | artifactStoreKey 返回工件的存储查找键。它覆盖类型、源标识与消息句柄，但不包含
// 端点索引，与内存 SAML 存储使用的查找键一致。
func artifactStoreKey(artifact samlapi.Artifact) string {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], artifact.Type)
	key := make([]byte, 0, len(encoded)+len(artifact.SourceID)+len(artifact.MessageHandle))
	key = append(key, encoded[:]...)
	key = append(key, artifact.SourceID[:]...)
	key = append(key, artifact.MessageHandle[:]...)
	return string(key)
}
