package kmip

import (
	"context"
	"errors"
	"sort"

	goredis "github.com/redis/go-redis/v9"

	kmipcore "github.com/shibingli/ydx/auth/keymgmt/kmip"
	"github.com/shibingli/ydx/errs"
)

// Create stores a new record and rejects a duplicate unique identifier atomically. It returns
// kmip.ErrInvalidRequest for an empty identifier and kmip.ErrObjectExists when the identifier is
// already in use. | Create 存储新记录并以原子方式拒绝重复的唯一标识符。标识符为空时返回
// kmip.ErrInvalidRequest，标识符已被使用时返回 kmip.ErrObjectExists。
func (s *Store) Create(ctx context.Context, record kmipcore.ObjectRecord) error {
	if err := s.ensure(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if record.UniqueIdentifier == "" {
		return errs.Detail(kmipcore.ErrInvalidRequest, "record has no unique identifier | 记录没有唯一标识符")
	}
	data, err := encodeRecord(record)
	if err != nil {
		return err
	}
	code, err := s.runInt(ctx, scriptCreate, "create object",
		[]string{s.keys.object(record.UniqueIdentifier), s.keys.all()},
		string(data), s.nextRevision())
	if err != nil {
		return err
	}
	switch code {
	case 0:
		return nil
	case 1:
		return errs.Detail(kmipcore.ErrObjectExists, "object %q already exists | 对象 %q 已存在",
			record.UniqueIdentifier, record.UniqueIdentifier)
	default:
		return errs.Detail(ErrStoreUnavailable, "create object returned %d | 创建对象返回 %d", code, code)
	}
}

// Get loads a record by unique identifier. It returns kmip.ErrItemNotFound when the object does
// not exist. The returned record owns fresh slices, attributes and key material.
// | Get 按唯一标识符加载记录。对象不存在时返回 kmip.ErrItemNotFound。返回的记录持有全新的切片、
// 属性与密钥材料。
func (s *Store) Get(ctx context.Context, uniqueIdentifier string) (kmipcore.ObjectRecord, error) {
	if err := s.ensure(); err != nil {
		return kmipcore.ObjectRecord{}, err
	}
	if err := ctx.Err(); err != nil {
		return kmipcore.ObjectRecord{}, err
	}
	data, err := s.client.HGet(ctx, s.keys.object(uniqueIdentifier), fieldData).Result()
	if errors.Is(err, goredis.Nil) {
		return kmipcore.ObjectRecord{}, errs.Detail(kmipcore.ErrItemNotFound,
			"object %q was not found | 未找到对象 %q", uniqueIdentifier, uniqueIdentifier)
	}
	if err != nil {
		return kmipcore.ObjectRecord{}, s.backend("get object", err)
	}
	return decodeRecord([]byte(data))
}

// Update replaces an existing record. It returns kmip.ErrItemNotFound when the object was
// removed and kmip.ErrConflict when concurrent writers keep changing the record beyond the retry
// budget. | Update 替换既有记录。对象已被删除时返回 kmip.ErrItemNotFound；并发写入持续改变记录
// 超出重试预算时返回 kmip.ErrConflict。
func (s *Store) Update(ctx context.Context, record kmipcore.ObjectRecord) error {
	if err := s.ensure(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := encodeRecord(record)
	if err != nil {
		return err
	}
	objectKey := s.keys.object(record.UniqueIdentifier)
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		revision, err := s.client.HGet(ctx, objectKey, fieldRevision).Result()
		if errors.Is(err, goredis.Nil) {
			exists, existsErr := s.client.Exists(ctx, objectKey).Result()
			if existsErr != nil {
				return s.backend("update object", existsErr)
			}
			if exists == 0 {
				return errs.Detail(kmipcore.ErrItemNotFound,
					"object %q was not found | 未找到对象 %q", record.UniqueIdentifier, record.UniqueIdentifier)
			}
			return errs.Detail(ErrStoreUnavailable, "stored record has no revision | 存储的记录缺少修订号")
		}
		if err != nil {
			return s.backend("update object", err)
		}
		if !validRevision(revision) {
			return errs.Detail(ErrStoreUnavailable, "stored record revision is corrupt | 存储的记录修订号损坏")
		}
		code, err := s.runInt(ctx, scriptUpdate, "update object",
			[]string{objectKey}, string(data), revision, s.nextRevision())
		if err != nil {
			return err
		}
		switch code {
		case 0:
			return nil
		case 1:
			return errs.Detail(kmipcore.ErrItemNotFound,
				"object %q was not found | 未找到对象 %q", record.UniqueIdentifier, record.UniqueIdentifier)
		case 2:
			continue
		default:
			return errs.Detail(ErrStoreUnavailable, "update object returned %d | 更新对象返回 %d", code, code)
		}
	}
	return errs.Detail(ErrConflict, "update object %q is contended | 更新对象 %q 存在竞争",
		record.UniqueIdentifier, record.UniqueIdentifier)
}

// Delete removes a record and its index membership atomically. It returns kmip.ErrItemNotFound
// when the object does not exist. | Delete 原子删除记录及其索引成员关系。对象不存在时返回
// kmip.ErrItemNotFound。
func (s *Store) Delete(ctx context.Context, uniqueIdentifier string) error {
	if err := s.ensure(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	code, err := s.runInt(ctx, scriptDelete, "delete object",
		[]string{s.keys.object(uniqueIdentifier), s.keys.all()})
	if err != nil {
		return err
	}
	switch code {
	case 0:
		return nil
	case 1:
		return errs.Detail(kmipcore.ErrItemNotFound,
			"object %q was not found | 未找到对象 %q", uniqueIdentifier, uniqueIdentifier)
	default:
		return errs.Detail(ErrStoreUnavailable, "delete object returned %d | 删除对象返回 %d", code, code)
	}
}

// List returns every record sorted by unique identifier. Each record owns fresh slices, attributes
// and key material. | List 按唯一标识符排序返回全部记录。每条记录持有全新的切片、属性与密钥材料。
func (s *Store) List(ctx context.Context) ([]kmipcore.ObjectRecord, error) {
	if err := s.ensure(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	members, err := s.client.SMembers(ctx, s.keys.all()).Result()
	if err != nil {
		return nil, s.backend("list objects", err)
	}
	records := make([]kmipcore.ObjectRecord, 0, len(members))
	if len(members) > 0 {
		cmds := make([]*goredis.StringCmd, len(members))
		_, pipelineErr := s.client.Pipelined(ctx, func(pipe goredis.Pipeliner) error {
			for i, member := range members {
				cmds[i] = pipe.HGet(ctx, member, fieldData)
			}
			return nil
		})
		if pipelineErr != nil && !errors.Is(pipelineErr, goredis.Nil) {
			return nil, s.backend("list objects", pipelineErr)
		}
		for i := range cmds {
			if cmds[i] == nil {
				continue
			}
			data, err := cmds[i].Result()
			if errors.Is(err, goredis.Nil) {
				continue
			}
			if err != nil {
				return nil, s.backend("list objects", err)
			}
			record, err := decodeRecord([]byte(data))
			if err != nil {
				return nil, err
			}
			records = append(records, record)
		}
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].UniqueIdentifier < records[j].UniqueIdentifier
	})
	return records, nil
}

// Reset removes every record stored below the configured key prefix. It is an operational
// extension, not part of kmip.Store. Concurrent writers may create records that survive Reset;
// callers that need an empty store should quiesce writers first. | Reset 删除配置键前缀下的全部记录。
// 它是运维扩展，不属于 kmip.Store。并发写入可能创建在 Reset 之后存活的记录；需要空存储的调用方
// 应先停止写入。
func (s *Store) Reset(ctx context.Context) error {
	if err := s.ensure(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	allKey := s.keys.all()
	for pass := 0; pass < maxResetPasses; pass++ {
		members, err := s.client.SMembers(ctx, allKey).Result()
		if err != nil {
			return s.backend("reset objects", err)
		}
		scriptKeys := make([]string, 0, len(members)+1)
		scriptKeys = append(scriptKeys, allKey)
		scriptKeys = append(scriptKeys, members...)
		if _, err := s.runInt(ctx, scriptReset, "reset objects", scriptKeys); err != nil {
			return err
		}
		if len(members) == 0 {
			return nil
		}
	}
	// A writer kept adding records. Delete the index one last time; every write that completes
	// after this point is ordered after Reset. | 写入方持续添加记录。最后再删除一次索引；此后完成
	// 的写入都排在 Reset 之后。
	if _, err := s.runInt(ctx, scriptReset, "reset objects", []string{allKey}); err != nil {
		return err
	}
	return nil
}
