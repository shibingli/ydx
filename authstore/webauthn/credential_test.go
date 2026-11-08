package webauthn_test

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	authwebauthn "github.com/shibingli/ydx/auth/mfa/webauthn"
	webauthnstore "github.com/shibingli/ydx/authstore/webauthn"
	"github.com/shibingli/ydx/base64"
)

// credentialKey returns the length-prefixed credential hash key used by the default prefix.
// | credentialKey 返回默认前缀使用的长度前缀凭据哈希键。
func credentialKey(id []byte) string {
	encoded := base64.RawURLEncoding.EncodeToString(id)
	return webauthnstore.DefaultKeyPrefix + "{authstore:webauthn}:credential:" +
		strconv.Itoa(len(encoded)) + ":" + encoded
}

// TestCredentialCRUD covers save, get, counter updates, backup-state updates and user queries
// across two instances. | TestCredentialCRUD 覆盖两实例间的保存、读取、计数器更新、备份状态更新与
// 用户查询。
func TestCredentialCRUD(t *testing.T) {
	first, second := newPair(t)
	zone := time.FixedZone("CST", 8*60*60)
	created := time.Date(2026, time.November, 8, 10, 0, 0, 0, zone)
	credential := sampleCredential(t, "cred-1", "alice", created)
	savedID := append([]byte(nil), credential.ID...)
	savedX := append([]byte(nil), credential.PublicKey.X...)
	if err := first.Save(testContext, credential); err != nil {
		t.Fatalf("save: %v | 保存失败", err)
	}
	if err := second.Save(testContext, credential); !errors.Is(err, authwebauthn.ErrCredentialExists) {
		t.Fatalf("duplicate save = %v, want ErrCredentialExists | 重复保存错误不符", err)
	}
	got, err := second.GetByCredentialID(testContext, savedID)
	if err != nil {
		t.Fatalf("get: %v | 读取失败", err)
	}
	if string(got.ID) != string(savedID) || got.UserID != credential.UserID ||
		got.Username != credential.Username || got.UserDisplayName != credential.UserDisplayName {
		t.Fatalf("identity fields = %+v | 身份字段不一致", got)
	}
	if string(got.UserHandle) != string(credential.UserHandle) {
		t.Fatalf("user handle = %x | 用户句柄不一致", got.UserHandle)
	}
	if got.PublicKey == nil || got.PublicKey.Kty != credential.PublicKey.Kty ||
		got.PublicKey.Kid == nil || string(got.PublicKey.Kid) != string(credential.PublicKey.Kid) ||
		got.PublicKey.Alg != credential.PublicKey.Alg || got.PublicKey.Crv != credential.PublicKey.Crv ||
		string(got.PublicKey.X) != string(savedX) {
		t.Fatalf("public key = %+v | 公钥不一致", got.PublicKey)
	}
	if got.SignCount != credential.SignCount || got.AAGUID != credential.AAGUID {
		t.Fatalf("counter or AAGUID = %d/%v | 计数器或 AAGUID 不一致", got.SignCount, got.AAGUID)
	}
	if len(got.Transports) != 2 || got.Transports[0] != credential.Transports[0] {
		t.Fatalf("transports = %v | 传输方式不一致", got.Transports)
	}
	if !got.BackupEligible || got.BackupState || !got.Discoverable || got.Disabled || got.Name != credential.Name {
		t.Fatalf("flags or name = %+v | 标志或名称不一致", got)
	}
	if !got.CreatedAt.Equal(created) || !got.LastUsedAt.Equal(credential.LastUsedAt) {
		t.Fatalf("times = %v/%v | 时间不一致", got.CreatedAt, got.LastUsedAt)
	}
	if got.CreatedAt.Location() != time.UTC || got.LastUsedAt.Location() != time.UTC {
		t.Fatalf("times not UTC: %v/%v | 时间未规范化为 UTC", got.CreatedAt, got.LastUsedAt)
	}

	if err := second.UpdateSignCount(testContext, savedID, 7); err != nil {
		t.Fatalf("update sign count: %v | 更新计数器失败", err)
	}
	if got, err = first.GetByCredentialID(testContext, savedID); err != nil || got.SignCount != 7 {
		t.Fatalf("sign count = %v/%v | 计数器更新未生效", got, err)
	}
	if err := second.UpdateBackupState(testContext, savedID, true); err != nil {
		t.Fatalf("update backup state: %v | 更新备份状态失败", err)
	}
	if got, err = first.GetByCredentialID(testContext, savedID); err != nil || !got.BackupState {
		t.Fatalf("backup state = %v/%v | 备份状态更新未生效", got, err)
	}

	later := sampleCredential(t, "cred-2", "alice", created.Add(time.Minute))
	bob := sampleCredential(t, "cred-3", "bob", created.Add(2*time.Minute))
	if err := second.Save(testContext, later); err != nil {
		t.Fatalf("save later: %v | 保存第二条凭据失败", err)
	}
	if err := second.Save(testContext, bob); err != nil {
		t.Fatalf("save bob: %v | 保存第三凭据失败", err)
	}
	alice, err := first.ListByUser(testContext, "alice")
	if err != nil {
		t.Fatalf("list alice: %v | 查询 alice 失败", err)
	}
	if len(alice) != 2 || string(alice[0].ID) != "cred-1" || string(alice[1].ID) != "cred-2" {
		t.Fatalf("alice list = %v | alice 凭据顺序不正确", credentialIDs(alice))
	}
	bobList, err := first.ListByUser(testContext, "bob")
	if err != nil || len(bobList) != 1 || string(bobList[0].ID) != "cred-3" {
		t.Fatalf("bob list = %v/%v | bob 凭据不正确", credentialIDs(bobList), err)
	}
	unknown, err := first.ListByUser(testContext, "carol")
	if err != nil || len(unknown) != 0 {
		t.Fatalf("unknown list = %v/%v, want empty | 未知用户未返回空列表", credentialIDs(unknown), err)
	}

	if _, err := first.GetByCredentialID(testContext, []byte("missing")); !errors.Is(err, authwebauthn.ErrCredentialNotFound) {
		t.Fatalf("missing get = %v | 未知凭据错误不符", err)
	}
	if _, err := first.GetByCredentialID(testContext, nil); !errors.Is(err, authwebauthn.ErrCredentialNotFound) {
		t.Fatalf("empty get = %v | 空凭据 ID 错误不符", err)
	}
	if err := first.UpdateSignCount(testContext, []byte("missing"), 1); !errors.Is(err, authwebauthn.ErrCredentialNotFound) {
		t.Fatalf("missing sign count = %v | 未知凭据计数器错误不符", err)
	}
	if err := first.UpdateBackupState(testContext, []byte("missing"), true); !errors.Is(err, authwebauthn.ErrCredentialNotFound) {
		t.Fatalf("missing backup state = %v | 未知凭据备份状态错误不符", err)
	}
}

// TestCredentialValidation covers the credential invariants enforced by Save. | TestCredentialValidation
// 覆盖 Save 强制执行的凭据不变量。
func TestCredentialValidation(t *testing.T) {
	store := newStoreOn(t, miniredis.RunT(t), "")
	if err := store.Save(testContext, nil); !errors.Is(err, authwebauthn.ErrInvalidCredential) {
		t.Fatalf("nil credential = %v | nil 凭据错误不符", err)
	}
	credential := sampleCredential(t, "cred-valid", "alice", time.Now())
	credential.ID = nil
	if err := store.Save(testContext, credential); !errors.Is(err, authwebauthn.ErrInvalidCredential) {
		t.Fatalf("empty ID = %v | 空 ID 错误不符", err)
	}
	credential = sampleCredential(t, "cred-valid", "alice", time.Now())
	credential.ID = make([]byte, 1024)
	if err := store.Save(testContext, credential); !errors.Is(err, authwebauthn.ErrInvalidCredential) {
		t.Fatalf("oversized ID = %v | 超长 ID 错误不符", err)
	}
	credential = sampleCredential(t, "cred-valid", "   ", time.Now())
	if err := store.Save(testContext, credential); !errors.Is(err, authwebauthn.ErrInvalidCredential) {
		t.Fatalf("blank user = %v | 空白用户错误不符", err)
	}
	credential = sampleCredential(t, "cred-valid", "alice", time.Now())
	credential.PublicKey = nil
	if err := store.Save(testContext, credential); !errors.Is(err, authwebauthn.ErrInvalidCredential) {
		t.Fatalf("nil public key = %v | nil 公钥错误不符", err)
	}
	credential = sampleCredential(t, "cred-valid", "alice", time.Now())
	credential.PublicKey.X = []byte("short")
	if err := store.Save(testContext, credential); !errors.Is(err, authwebauthn.ErrInvalidCredential) {
		t.Fatalf("invalid public key = %v | 非法公钥错误不符", err)
	}
	credential = sampleCredential(t, "cred-max", "alice", time.Now())
	credential.ID = make([]byte, 1023)
	credential.ID[0] = 1
	if err := store.Save(testContext, credential); err != nil {
		t.Fatalf("max ID = %v, want accepted | 最大 ID 应被接受", err)
	}
}

// TestCredentialDeepCopy verifies Save and every read never share memory with the caller.
// | TestCredentialDeepCopy 验证 Save 与每次读取都不与调用方共享内存。
func TestCredentialDeepCopy(t *testing.T) {
	first, second := newPair(t)
	credential := sampleCredential(t, "cred-copy", "alice", time.Now())
	savedID := append([]byte(nil), credential.ID...)
	wantHandle := string(credential.UserHandle)
	wantTransport := credential.Transports[0]
	wantKey := string(credential.PublicKey.X)
	wantKid := string(credential.PublicKey.Kid)
	if err := first.Save(testContext, credential); err != nil {
		t.Fatalf("save: %v | 保存失败", err)
	}
	credential.UserHandle[0] ^= 0xff
	credential.Transports[0] = "mutated"
	credential.PublicKey.X[0] ^= 0xff
	credential.PublicKey.Kid[0] ^= 0xff
	got, err := second.GetByCredentialID(testContext, savedID)
	if err != nil {
		t.Fatalf("get: %v | 读取失败", err)
	}
	if string(got.UserHandle) != wantHandle || got.Transports[0] != wantTransport ||
		string(got.PublicKey.X) != wantKey || string(got.PublicKey.Kid) != wantKid {
		t.Fatalf("stored credential shares caller memory | 存储凭据共享了调用方内存")
	}
	got.UserHandle[0] ^= 0xff
	got.Transports[0] = "consumer"
	got.PublicKey.X[0] ^= 0xff
	got.PublicKey.Kid[0] ^= 0xff
	got.ID[0] ^= 0xff
	again, err := first.GetByCredentialID(testContext, savedID)
	if err != nil {
		t.Fatalf("get again: %v | 再次读取失败", err)
	}
	if string(again.UserHandle) != wantHandle || again.Transports[0] != wantTransport ||
		string(again.PublicKey.X) != wantKey || string(again.PublicKey.Kid) != wantKid ||
		string(again.ID) != string(savedID) {
		t.Fatalf("returned credential shares memory with another caller | 返回凭据与其它调用方共享内存")
	}
}

// TestCredentialListSkipsDeletedRecord verifies that a stale index member is skipped.
// | TestCredentialListSkipsDeletedRecord 验证过期索引成员会被跳过。
func TestCredentialListSkipsDeletedRecord(t *testing.T) {
	server := miniredis.RunT(t)
	store := newStoreOn(t, server, "")
	credential := sampleCredential(t, "cred-stale", "alice", time.Now())
	if err := store.Save(testContext, credential); err != nil {
		t.Fatalf("save: %v | 保存失败", err)
	}
	if !server.Del(credentialKey(credential.ID)) {
		t.Fatalf("delete credential hash failed | 删除凭据哈希失败")
	}
	list, err := store.ListByUser(testContext, "alice")
	if err != nil || len(list) != 0 {
		t.Fatalf("stale list = %v/%v, want empty | 过期索引未跳过", credentialIDs(list), err)
	}
}

// TestCredentialCorruptRecord verifies that undecodable hash fields report ErrInvalidCredential.
// | TestCredentialCorruptRecord 验证无法解码的哈希字段报告 ErrInvalidCredential。
func TestCredentialCorruptRecord(t *testing.T) {
	server := miniredis.RunT(t)
	store := newStoreOn(t, server, "")
	raw := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = raw.Close()
	})
	broken := sampleCredential(t, "cred-broken", "alice", time.Now())
	if err := store.Save(testContext, broken); err != nil {
		t.Fatalf("save broken: %v | 保存损坏夹具失败", err)
	}
	if err := raw.HSet(testContext, credentialKey(broken.ID), "data", "not-json").Err(); err != nil {
		t.Fatalf("corrupt data: %v | 损坏数据失败", err)
	}
	if _, err := store.GetByCredentialID(testContext, broken.ID); !errors.Is(err, authwebauthn.ErrInvalidCredential) {
		t.Fatalf("corrupt data = %v | 损坏数据错误不符", err)
	}
	if _, err := store.ListByUser(testContext, broken.UserID); !errors.Is(err, authwebauthn.ErrInvalidCredential) {
		t.Fatalf("corrupt list = %v | 损坏数据列表错误不符", err)
	}

	counter := sampleCredential(t, "cred-counter", "alice", time.Now().Add(time.Second))
	if err := store.Save(testContext, counter); err != nil {
		t.Fatalf("save counter: %v | 保存计数器夹具失败", err)
	}
	if err := raw.HSet(testContext, credentialKey(counter.ID), "signCount", "not-a-number").Err(); err != nil {
		t.Fatalf("corrupt sign count: %v | 损坏计数器失败", err)
	}
	if _, err := store.GetByCredentialID(testContext, counter.ID); !errors.Is(err, authwebauthn.ErrInvalidCredential) {
		t.Fatalf("corrupt sign count = %v | 损坏计数器错误不符", err)
	}
}

// TestCredentialContext covers nil and cancelled contexts on every method. | TestCredentialContext
// 覆盖每个方法的 nil 与取消上下文。
func TestCredentialContext(t *testing.T) {
	store := newStoreOn(t, miniredis.RunT(t), "")
	credential := sampleCredential(t, "cred-ctx", "alice", time.Now())
	var nilContext context.Context
	if err := store.Save(nilContext, credential); !errors.Is(err, authwebauthn.ErrInvalidRequest) {
		t.Fatalf("nil save = %v | nil 上下文保存错误不符", err)
	}
	if _, err := store.GetByCredentialID(nilContext, credential.ID); !errors.Is(err, authwebauthn.ErrInvalidRequest) {
		t.Fatalf("nil get = %v | nil 上下文读取错误不符", err)
	}
	if err := store.UpdateSignCount(nilContext, credential.ID, 1); !errors.Is(err, authwebauthn.ErrInvalidRequest) {
		t.Fatalf("nil sign count = %v | nil 上下文计数器错误不符", err)
	}
	if err := store.UpdateBackupState(nilContext, credential.ID, true); !errors.Is(err, authwebauthn.ErrInvalidRequest) {
		t.Fatalf("nil backup state = %v | nil 上下文备份状态错误不符", err)
	}
	if _, err := store.ListByUser(nilContext, "alice"); !errors.Is(err, authwebauthn.ErrInvalidRequest) {
		t.Fatalf("nil list = %v | nil 上下文列表错误不符", err)
	}
	cancelled, cancel := context.WithCancel(testContext)
	cancel()
	if err := store.Save(cancelled, credential); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled save = %v | 取消上下文保存错误不符", err)
	}
	if _, err := store.GetByCredentialID(cancelled, credential.ID); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled get = %v | 取消上下文读取错误不符", err)
	}
	if err := store.UpdateSignCount(cancelled, credential.ID, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled sign count = %v | 取消上下文计数器错误不符", err)
	}
	if err := store.UpdateBackupState(cancelled, credential.ID, true); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled backup state = %v | 取消上下文备份状态错误不符", err)
	}
	if _, err := store.ListByUser(cancelled, "alice"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled list = %v | 取消上下文列表错误不符", err)
	}
}

// TestCredentialConcurrentSaveExactlyOnce models many instances creating one credential ID.
// | TestCredentialConcurrentSaveExactlyOnce 模拟多实例创建同一个凭据 ID。
func TestCredentialConcurrentSaveExactlyOnce(t *testing.T) {
	first, second := newPair(t)
	credential := sampleCredential(t, "cred-create-race", "alice", time.Now())
	var successes atomic.Int64
	var exists atomic.Int64
	var failures atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		store := first
		if i%2 == 1 {
			store = second
		}
		wg.Add(1)
		go func(store *webauthnstore.Store) {
			defer wg.Done()
			err := store.Save(testContext, credential)
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, authwebauthn.ErrCredentialExists):
				exists.Add(1)
			default:
				failures.Add(1)
			}
		}(store)
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("save failures = %d | 保存失败次数非零", failures.Load())
	}
	if successes.Load() != 1 {
		t.Fatalf("save successes = %d, want 1 | 成功保存次数不为 1", successes.Load())
	}
	if exists.Load() != 63 {
		t.Fatalf("exists = %d, want 63 | 已存在次数不为 63", exists.Load())
	}
}

// TestCredentialConcurrentUpdates verifies that atomic counter and backup-state updates do not lose
// the credential record. | TestCredentialConcurrentUpdates 验证原子计数器与备份状态更新不会丢失凭据
// 记录。
func TestCredentialConcurrentUpdates(t *testing.T) {
	first, second := newPair(t)
	credential := sampleCredential(t, "cred-update-race", "alice", time.Now())
	if err := first.Save(testContext, credential); err != nil {
		t.Fatalf("save: %v | 保存失败", err)
	}
	var wg sync.WaitGroup
	var failures atomic.Int64
	for i := 0; i < 64; i++ {
		store := first
		if i%2 == 1 {
			store = second
		}
		count := uint32(i + 1)
		wantBackup := i%2 == 0
		wg.Add(1)
		go func(store *webauthnstore.Store, count uint32, wantBackup bool) {
			defer wg.Done()
			if err := store.UpdateSignCount(testContext, credential.ID, count); err != nil {
				failures.Add(1)
			}
			if err := store.UpdateBackupState(testContext, credential.ID, wantBackup); err != nil {
				failures.Add(1)
			}
		}(store, count, wantBackup)
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("update failures = %d | 更新失败次数非零", failures.Load())
	}
	got, err := first.GetByCredentialID(testContext, credential.ID)
	if err != nil {
		t.Fatalf("get: %v | 读取失败", err)
	}
	if got.SignCount < 1 || got.SignCount > 64 {
		t.Fatalf("sign count = %d | 计数器不是并发写入之一", got.SignCount)
	}
}

// credentialIDs returns the raw credential IDs of a list for failure messages. | credentialIDs 返回
// 列表的原始凭据 ID，用于失败信息。
func credentialIDs(credentials []*authwebauthn.Credential) []string {
	out := make([]string, 0, len(credentials))
	for _, credential := range credentials {
		out = append(out, string(credential.ID))
	}
	return out
}
