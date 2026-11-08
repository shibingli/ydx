package redis_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
)

// sampleIdentity returns a fully populated identity link. | sampleIdentity 返回字段完整的身份关联。
func sampleIdentity(provider, subject, userID string, created time.Time) *auth.Identity {
	return &auth.Identity{
		Provider:      provider,
		Subject:       subject,
		UserID:        userID,
		Email:         subject + "@example.com",
		EmailVerified: true,
		Username:      subject,
		Name:          "Name " + subject,
		AvatarURL:     "https://example.com/" + subject + ".png",
		Raw:           map[string]string{"tier": "gold"},
		CreatedAt:     created,
		UpdatedAt:     created,
	}
}

// TestIdentityCreateAndGet covers creation, lookups, duplicates and validation.
// | TestIdentityCreateAndGet 覆盖创建、查找、重复与校验。
func TestIdentityCreateAndGet(t *testing.T) {
	first, second := newPair(t)
	created := testTime(2026, time.August, 1, 1, 2, 3)
	identity := sampleIdentity("google", "sub-1", "u1", created)
	if err := first.Identities.CreateIdentity(testContext, identity); err != nil {
		t.Fatalf("create: %v | 创建失败", err)
	}
	got, err := second.Identities.GetIdentity(testContext, "google", "sub-1")
	if err != nil {
		t.Fatalf("cross-instance get: %v | 跨实例读取失败", err)
	}
	if got.Raw["tier"] != "gold" || got.Email != "sub-1@example.com" || !got.EmailVerified {
		t.Fatalf("identity fields lost: %#v | 身份字段丢失", got)
	}
	if err := second.Identities.CreateIdentity(testContext, sampleIdentity("google", "sub-1", "u2", created)); !errors.Is(err, auth.ErrIdentityExists) {
		t.Fatalf("duplicate error = %v, want ErrIdentityExists | 重复身份错误不符", err)
	}
	for _, bad := range []*auth.Identity{
		nil,
		{},
		{Provider: "google", UserID: "u1"},
		{Subject: "sub", UserID: "u1"},
		{Provider: "google", Subject: "sub"},
	} {
		if err := first.Identities.CreateIdentity(testContext, bad); !errors.Is(err, auth.ErrInvalidRequest) {
			t.Fatalf("invalid identity %#v error = %v | 非法身份错误不符", bad, err)
		}
	}
	if _, err := first.Identities.GetIdentity(testContext, "google", "missing"); !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("missing error = %v | 不存在身份错误不符", err)
	}
	if err := first.Identities.CreateIdentity(testContext, sampleIdentity("google", "sub-2", "u1", created)); err != nil {
		t.Fatalf("second identity: %v | 创建第二个身份失败", err)
	}
	if err := first.Identities.CreateIdentity(testContext, sampleIdentity("azuread", "sub-1", "u1", created)); err != nil {
		t.Fatalf("third identity: %v | 创建第三个身份失败", err)
	}
	if err := first.Identities.CreateIdentity(testContext, sampleIdentity("a", "bc", "u3", created)); err != nil {
		t.Fatalf("injective a/bc: %v | 创建 a/bc 失败", err)
	}
	if err := first.Identities.CreateIdentity(testContext, sampleIdentity("ab", "c", "u4", created)); err != nil {
		t.Fatalf("injective ab/c: %v | 创建 ab/c 失败", err)
	}
}

// TestIdentityListOrder covers provider/subject ordering and per-user isolation.
// | TestIdentityListOrder 覆盖 provider/subject 排序与用户隔离。
func TestIdentityListOrder(t *testing.T) {
	stores := newStores(t, "")
	created := testTime(2026, time.August, 2, 0, 0, 0)
	links := []*auth.Identity{
		sampleIdentity("google", "z", "u1", created),
		sampleIdentity("azuread", "b", "u1", created),
		sampleIdentity("google", "a", "u1", created),
		sampleIdentity("azuread", "a", "u2", created),
	}
	for _, link := range links {
		if err := stores.Identities.CreateIdentity(testContext, link); err != nil {
			t.Fatalf("create %s/%s: %v | 创建身份失败", link.Provider, link.Subject, err)
		}
	}
	list, err := stores.Identities.ListIdentitiesByUser(testContext, "u1")
	if err != nil {
		t.Fatalf("list: %v | 列表失败", err)
	}
	want := [][2]string{{"azuread", "b"}, {"google", "a"}, {"google", "z"}}
	if len(list) != len(want) {
		t.Fatalf("len = %d | 身份数量不符", len(list))
	}
	for i, pair := range want {
		if list[i].Provider != pair[0] || list[i].Subject != pair[1] {
			t.Fatalf("order[%d] = %s/%s, want %s/%s | 身份排序不符",
				i, list[i].Provider, list[i].Subject, pair[0], pair[1])
		}
	}
	empty, err := stores.Identities.ListIdentitiesByUser(testContext, "nobody")
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("empty list = %#v, %v | 空身份列表应为非 nil 空切片", empty, err)
	}
}

// TestIdentityUpdateReindexes covers owner migration and not-found reporting.
// | TestIdentityUpdateReindexes 覆盖属主迁移与不存在报告。
func TestIdentityUpdateReindexes(t *testing.T) {
	first, second := newPair(t)
	created := testTime(2026, time.August, 3, 0, 0, 0)
	if err := first.Identities.CreateIdentity(testContext, sampleIdentity("google", "sub", "u1", created)); err != nil {
		t.Fatalf("create: %v | 创建失败", err)
	}
	moved := sampleIdentity("google", "sub", "u2", created)
	moved.Email = "moved@example.com"
	moved.Raw = map[string]string{"tier": "platinum"}
	moved.UpdatedAt = created.Add(time.Hour)
	if err := second.Identities.UpdateIdentity(testContext, moved); err != nil {
		t.Fatalf("update: %v | 更新失败", err)
	}
	if list, err := first.Identities.ListIdentitiesByUser(testContext, "u1"); err != nil || len(list) != 0 {
		t.Fatalf("old owner list = %v, %v | 旧属主列表未清空", list, err)
	}
	list, err := first.Identities.ListIdentitiesByUser(testContext, "u2")
	if err != nil || len(list) != 1 || list[0].Email != "moved@example.com" || list[0].Raw["tier"] != "platinum" {
		t.Fatalf("new owner list = %v, %v | 新属主列表不符", list, err)
	}
	if err := first.Identities.UpdateIdentity(testContext, sampleIdentity("google", "missing", "u1", created)); !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("update missing error = %v | 更新不存在身份错误不符", err)
	}
	for _, bad := range []*auth.Identity{nil, {}, {Provider: "google"}} {
		if err := first.Identities.UpdateIdentity(testContext, bad); !errors.Is(err, auth.ErrInvalidRequest) {
			t.Fatalf("invalid update %#v error = %v | 非法更新错误不符", bad, err)
		}
	}
}

// TestIdentityDelete covers deletion, release and not-found reporting.
// | TestIdentityDelete 覆盖删除、释放与不存在报告。
func TestIdentityDelete(t *testing.T) {
	first, second := newPair(t)
	created := testTime(2026, time.August, 4, 0, 0, 0)
	if err := first.Identities.CreateIdentity(testContext, sampleIdentity("google", "sub", "u1", created)); err != nil {
		t.Fatalf("create: %v | 创建失败", err)
	}
	if err := second.Identities.DeleteIdentity(testContext, "google", "sub"); err != nil {
		t.Fatalf("cross-instance delete: %v | 跨实例删除失败", err)
	}
	if _, err := first.Identities.GetIdentity(testContext, "google", "sub"); !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("get deleted: %v | 删除后读取错误不符", err)
	}
	if list, err := first.Identities.ListIdentitiesByUser(testContext, "u1"); err != nil || len(list) != 0 {
		t.Fatalf("list after delete = %v, %v | 删除后列表不符", list, err)
	}
	if err := first.Identities.DeleteIdentity(testContext, "google", "sub"); !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("delete missing error = %v | 删除不存在身份错误不符", err)
	}
	if err := first.Identities.CreateIdentity(testContext, sampleIdentity("google", "sub", "u2", created)); err != nil {
		t.Fatalf("recreate: %v | 重建身份失败", err)
	}
}

// TestIdentityDeepCopy verifies map isolation and UTC normalization.
// | TestIdentityDeepCopy 验证映射隔离与 UTC 规范化。
func TestIdentityDeepCopy(t *testing.T) {
	stores := newStores(t, "")
	zone := time.FixedZone("UTC+8", 8*3600)
	created := time.Date(2026, time.August, 5, 12, 0, 0, 0, zone)
	identity := sampleIdentity("google", "sub", "u1", created)
	if err := stores.Identities.CreateIdentity(testContext, identity); err != nil {
		t.Fatalf("create: %v | 创建失败", err)
	}
	identity.Raw["tier"] = "mutated"
	identity.Name = "mutated"
	got, err := stores.Identities.GetIdentity(testContext, "google", "sub")
	if err != nil {
		t.Fatalf("get: %v | 读取失败", err)
	}
	if got.Raw["tier"] != "gold" || got.Name != "Name sub" {
		t.Fatalf("input mutation leaked: %#v | 输入修改泄露到存储", got)
	}
	if got.CreatedAt.Location() != time.UTC || !got.CreatedAt.Equal(created) {
		t.Fatalf("createdAt = %v | 创建时间未规范化为 UTC", got.CreatedAt)
	}
	got.Raw["tier"] = "returned-mutation"
	again, err := stores.Identities.GetIdentity(testContext, "google", "sub")
	if err != nil || again.Raw["tier"] != "gold" {
		t.Fatalf("returned mutation persisted: %v, %v | 返回值修改影响了存储", again, err)
	}
}

// TestIdentityConcurrentCreate verifies atomic uniqueness across instances.
// | TestIdentityConcurrentCreate 验证跨实例的原子唯一性。
func TestIdentityConcurrentCreate(t *testing.T) {
	first, second := newPair(t)
	const workers = 10
	created := testTime(2026, time.August, 6, 0, 0, 0)
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
			errsCh <- stores.Identities.CreateIdentity(testContext,
				sampleIdentity("google", "shared", fmt.Sprintf("u%d", i), created))
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
		case errors.Is(err, auth.ErrIdentityExists):
			duplicates++
		default:
			t.Fatalf("unexpected error: %v | 意外错误", err)
		}
	}
	if successes != 1 || duplicates != workers-1 {
		t.Fatalf("successes=%d duplicates=%d | 并发身份创建结果不符", successes, duplicates)
	}
}
