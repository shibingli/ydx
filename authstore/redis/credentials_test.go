package redis_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
)

// sampleCredential returns a fully populated authentication factor. | sampleCredential 返回字段完整的认证因素。
func sampleCredential(id, userID string, typ auth.CredentialType, created time.Time) *auth.Credential {
	return &auth.Credential{
		ID:         id,
		UserID:     userID,
		Type:       typ,
		Name:       "factor-" + id,
		Secret:     "secret-" + id,
		Data:       map[string]string{"algorithm": "test"},
		Disabled:   false,
		CreatedAt:  created,
		UpdatedAt:  created,
		LastUsedAt: created.Add(time.Minute),
	}
}

// TestCredentialCreateAndGet covers creation, lookups, duplicates and validation.
// | TestCredentialCreateAndGet 覆盖创建、查找、重复与校验。
func TestCredentialCreateAndGet(t *testing.T) {
	first, second := newPair(t)
	created := testTime(2026, time.September, 1, 0, 0, 0)
	credential := sampleCredential("c1", "u1", auth.CredentialTOTP, created)
	if err := first.Credentials.CreateCredential(testContext, credential); err != nil {
		t.Fatalf("create: %v | 创建失败", err)
	}
	got, err := second.Credentials.GetCredential(testContext, "c1")
	if err != nil {
		t.Fatalf("cross-instance get: %v | 跨实例读取失败", err)
	}
	if got.Secret != "secret-c1" || got.Data["algorithm"] != "test" || got.Type != auth.CredentialTOTP {
		t.Fatalf("credential fields lost: %#v | 凭据字段丢失", got)
	}
	if err := second.Credentials.CreateCredential(testContext, sampleCredential("c1", "u2", auth.CredentialPassword, created)); !errors.Is(err, auth.ErrCredentialExists) {
		t.Fatalf("duplicate error = %v, want ErrCredentialExists | 重复凭据错误不符", err)
	}
	for _, bad := range []*auth.Credential{
		nil,
		{},
		{ID: "c2"},
		{UserID: "u1"},
	} {
		if err := first.Credentials.CreateCredential(testContext, bad); !errors.Is(err, auth.ErrInvalidRequest) {
			t.Fatalf("invalid credential %#v error = %v | 非法凭据错误不符", bad, err)
		}
	}
	if _, err := first.Credentials.GetCredential(testContext, "missing"); !errors.Is(err, auth.ErrCredentialNotFound) {
		t.Fatalf("missing error = %v | 不存在凭据错误不符", err)
	}
	if list, err := first.Credentials.ListCredentialsByUser(testContext, "nobody"); err != nil || list == nil || len(list) != 0 {
		t.Fatalf("empty list = %#v, %v | 空凭据列表应为非 nil 空切片", list, err)
	}
	if list, err := first.Credentials.ListCredentialsByUserType(testContext, "nobody", auth.CredentialTOTP); err != nil || len(list) != 0 {
		t.Fatalf("empty typed list = %v, %v | 空类型列表不符", list, err)
	}
}

// TestCredentialList covers ordering and type filtering.
// | TestCredentialList 覆盖排序与类型过滤。
func TestCredentialList(t *testing.T) {
	stores := newStores(t, "")
	base := testTime(2026, time.September, 2, 0, 0, 0)
	credentials := []*auth.Credential{
		sampleCredential("c2", "u1", auth.CredentialWebAuthn, base.Add(2*time.Hour)),
		sampleCredential("c1", "u1", auth.CredentialTOTP, base.Add(1*time.Hour)),
		sampleCredential("c3", "u1", auth.CredentialTOTP, base.Add(1*time.Hour)),
		sampleCredential("c4", "u2", auth.CredentialPassword, base.Add(3*time.Hour)),
	}
	for _, credential := range credentials {
		if err := stores.Credentials.CreateCredential(testContext, credential); err != nil {
			t.Fatalf("create %s: %v | 创建凭据失败", credential.ID, err)
		}
	}
	all, err := stores.Credentials.ListCredentialsByUser(testContext, "u1")
	if err != nil {
		t.Fatalf("list all: %v | 列表失败", err)
	}
	wantAll := []string{"c1", "c3", "c2"}
	if len(all) != len(wantAll) {
		t.Fatalf("all len = %d | 凭据数量不符", len(all))
	}
	for i, id := range wantAll {
		if all[i].ID != id {
			t.Fatalf("all[%d] = %q, want %q | 凭据排序不符", i, all[i].ID, id)
		}
	}
	totp, err := stores.Credentials.ListCredentialsByUserType(testContext, "u1", auth.CredentialTOTP)
	if err != nil || len(totp) != 2 || totp[0].ID != "c1" || totp[1].ID != "c3" {
		t.Fatalf("totp list = %v, %v | 类型过滤不符", totp, err)
	}
	none, err := stores.Credentials.ListCredentialsByUserType(testContext, "u1", auth.CredentialPassword)
	if err != nil || len(none) != 0 {
		t.Fatalf("password list = %v, %v | 无匹配类型列表不符", none, err)
	}
}

// TestCredentialUpdateReindexes covers owner migration and not-found reporting.
// | TestCredentialUpdateReindexes 覆盖属主迁移与不存在报告。
func TestCredentialUpdateReindexes(t *testing.T) {
	first, second := newPair(t)
	created := testTime(2026, time.September, 3, 0, 0, 0)
	if err := first.Credentials.CreateCredential(testContext, sampleCredential("c1", "u1", auth.CredentialTOTP, created)); err != nil {
		t.Fatalf("create: %v | 创建失败", err)
	}
	moved := sampleCredential("c1", "u2", auth.CredentialRecoveryCode, created)
	moved.Secret = "new-secret"
	moved.Data = map[string]string{"algorithm": "rotated"}
	moved.Disabled = true
	moved.UpdatedAt = created.Add(time.Hour)
	if err := second.Credentials.UpdateCredential(testContext, moved); err != nil {
		t.Fatalf("update: %v | 更新失败", err)
	}
	if list, err := first.Credentials.ListCredentialsByUser(testContext, "u1"); err != nil || len(list) != 0 {
		t.Fatalf("old owner list = %v, %v | 旧属主列表未清空", list, err)
	}
	list, err := first.Credentials.ListCredentialsByUser(testContext, "u2")
	if err != nil || len(list) != 1 {
		t.Fatalf("new owner list = %v, %v | 新属主列表不符", list, err)
	}
	if got := list[0]; got.Secret != "new-secret" || got.Data["algorithm"] != "rotated" || !got.Disabled ||
		got.Type != auth.CredentialRecoveryCode {
		t.Fatalf("updated credential = %#v | 更新结果不符", got)
	}
	if err := first.Credentials.UpdateCredential(testContext, sampleCredential("missing", "u1", auth.CredentialTOTP, created)); !errors.Is(err, auth.ErrCredentialNotFound) {
		t.Fatalf("update missing error = %v | 更新不存在凭据错误不符", err)
	}
	if err := first.Credentials.UpdateCredential(testContext, nil); !errors.Is(err, auth.ErrInvalidRequest) {
		t.Fatalf("update nil error = %v | 更新 nil 错误不符", err)
	}
	if err := first.Credentials.UpdateCredential(testContext, &auth.Credential{}); !errors.Is(err, auth.ErrInvalidRequest) {
		t.Fatalf("update empty id error = %v | 更新空 ID 错误不符", err)
	}
}

// TestCredentialDelete covers deletion, index release and not-found reporting.
// | TestCredentialDelete 覆盖删除、索引释放与不存在报告。
func TestCredentialDelete(t *testing.T) {
	first, second := newPair(t)
	created := testTime(2026, time.September, 4, 0, 0, 0)
	if err := first.Credentials.CreateCredential(testContext, sampleCredential("c1", "u1", auth.CredentialTOTP, created)); err != nil {
		t.Fatalf("create: %v | 创建失败", err)
	}
	if err := second.Credentials.DeleteCredential(testContext, "c1"); err != nil {
		t.Fatalf("cross-instance delete: %v | 跨实例删除失败", err)
	}
	if _, err := first.Credentials.GetCredential(testContext, "c1"); !errors.Is(err, auth.ErrCredentialNotFound) {
		t.Fatalf("get deleted: %v | 删除后读取错误不符", err)
	}
	if list, err := first.Credentials.ListCredentialsByUser(testContext, "u1"); err != nil || len(list) != 0 {
		t.Fatalf("list after delete = %v, %v | 删除后列表不符", list, err)
	}
	if err := first.Credentials.DeleteCredential(testContext, "c1"); !errors.Is(err, auth.ErrCredentialNotFound) {
		t.Fatalf("delete missing error = %v | 删除不存在凭据错误不符", err)
	}
	if err := first.Credentials.CreateCredential(testContext, sampleCredential("c1", "u2", auth.CredentialPassword, created)); err != nil {
		t.Fatalf("recreate: %v | 重建凭据失败", err)
	}
}

// TestCredentialDeepCopy verifies secret/data isolation and UTC normalization.
// | TestCredentialDeepCopy 验证密钥/数据隔离与 UTC 规范化。
func TestCredentialDeepCopy(t *testing.T) {
	stores := newStores(t, "")
	zone := time.FixedZone("UTC+9", 9*3600)
	created := time.Date(2026, time.September, 5, 15, 0, 0, 0, zone)
	credential := sampleCredential("c1", "u1", auth.CredentialWebAuthn, created)
	if err := stores.Credentials.CreateCredential(testContext, credential); err != nil {
		t.Fatalf("create: %v | 创建失败", err)
	}
	credential.Data["algorithm"] = "mutated"
	credential.Secret = "mutated"
	credential.Name = "mutated"
	got, err := stores.Credentials.GetCredential(testContext, "c1")
	if err != nil {
		t.Fatalf("get: %v | 读取失败", err)
	}
	if got.Data["algorithm"] != "test" || got.Secret != "secret-c1" || got.Name != "factor-c1" {
		t.Fatalf("input mutation leaked: %#v | 输入修改泄露到存储", got)
	}
	if got.CreatedAt.Location() != time.UTC || !got.CreatedAt.Equal(created) {
		t.Fatalf("createdAt = %v | 创建时间未规范化为 UTC", got.CreatedAt)
	}
	got.Data["algorithm"] = "returned-mutation"
	again, err := stores.Credentials.GetCredential(testContext, "c1")
	if err != nil || again.Data["algorithm"] != "test" {
		t.Fatalf("returned mutation persisted: %v, %v | 返回值修改影响了存储", again, err)
	}
}

// TestCredentialConcurrentCreate verifies atomic uniqueness across instances.
// | TestCredentialConcurrentCreate 验证跨实例的原子唯一性。
func TestCredentialConcurrentCreate(t *testing.T) {
	first, second := newPair(t)
	const workers = 10
	created := testTime(2026, time.September, 6, 0, 0, 0)
	errsCh := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			stores := first
			if i%2 == 1 {
				stores = second
			}
			errsCh <- stores.Credentials.CreateCredential(testContext,
				sampleCredential("shared", fmt.Sprintf("u%d", i), auth.CredentialRecoveryCode, created))
		}(i)
	}
	wg.Wait()
	close(errsCh)
	successes := 0
	duplicates := 0
	for err := range errsCh {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, auth.ErrCredentialExists):
			duplicates++
		default:
			t.Fatalf("unexpected error: %v | 意外错误", err)
		}
	}
	if successes != 1 || duplicates != workers-1 {
		t.Fatalf("successes=%d duplicates=%d | 并发凭据创建结果不符", successes, duplicates)
	}
}
