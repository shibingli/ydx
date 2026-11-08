package oauth2_test

import (
	"errors"
	"testing"
	"time"

	authoauth2 "github.com/shibingli/ydx/auth/protocol/oauth2"
	oauth2store "github.com/shibingli/ydx/authstore/oauth2"
)

// TestClients covers registration CRUD, ordering, deep copies and errors.
// | TestClients 覆盖注册增删改查、排序、深拷贝与错误。
func TestClients(t *testing.T) {
	first, second := newPair(t, oauth2store.Options{})
	list, err := first.Clients.ListClients(testContext)
	if err != nil || len(list) != 0 {
		t.Fatalf("empty list = %v, %v | 空列表不符", list, err)
	}
	if err := first.Clients.CreateClient(testContext, nil); !errors.Is(err, authoauth2.ErrInvalidClient) {
		t.Fatalf("nil create error = %v, want ErrInvalidClient | nil 创建错误不符", err)
	}
	if err := first.Clients.CreateClient(testContext, &authoauth2.Client{}); !errors.Is(err, authoauth2.ErrInvalidClient) {
		t.Fatalf("empty create error = %v, want ErrInvalidClient | 空客户端创建错误不符", err)
	}
	for _, id := range []string{"charlie", "alpha", "bravo"} {
		if err := first.Clients.CreateClient(testContext, sampleClient(id)); err != nil {
			t.Fatalf("create %s: %v | 创建客户端失败", id, err)
		}
	}
	if err := second.Clients.CreateClient(testContext, sampleClient("alpha")); !errors.Is(err, authoauth2.ErrInvalidClient) {
		t.Fatalf("duplicate create error = %v, want ErrInvalidClient | 重复创建错误不符", err)
	}
	got, err := second.Clients.GetClient(testContext, "alpha")
	if err != nil {
		t.Fatalf("get: %v | 读取失败", err)
	}
	if got.Name != "Client alpha" || got.SecretHash != "secret-alpha" ||
		got.AccessTokenTTL != 15*time.Minute || got.RefreshTokenTTL != 24*time.Hour ||
		got.AuthorizationCodeTTL != 5*time.Minute || got.RegistrationAccessTokenHash != "registration-alpha" ||
		got.RegistrationClientURI != "https://issuer.example/register/alpha" {
		t.Fatalf("client hidden fields were lost: %+v | 客户端隐藏字段丢失", got)
	}
	if len(got.JWKS) != len(`{"keys":[]}`) || got.Metadata["tenant"] != "t1" {
		t.Fatalf("client nested data was lost: %+v | 客户端嵌套数据丢失", got)
	}
	if _, err := first.Clients.GetClient(testContext, "missing"); !errors.Is(err, authoauth2.ErrInvalidClient) {
		t.Fatalf("unknown get error = %v, want ErrInvalidClient | 未知客户端错误不符", err)
	}
	list, err = first.Clients.ListClients(testContext)
	if err != nil {
		t.Fatalf("list: %v | 列表失败", err)
	}
	if len(list) != 3 || list[0].ID != "alpha" || list[1].ID != "bravo" || list[2].ID != "charlie" {
		t.Fatalf("list order = %v | 列表顺序不符", list)
	}
	got.Name = "Alpha Updated"
	got.Scopes = []string{"email"}
	if err := second.Clients.UpdateClient(testContext, got); err != nil {
		t.Fatalf("update: %v | 更新失败", err)
	}
	updated, err := first.Clients.GetClient(testContext, "alpha")
	if err != nil || updated.Name != "Alpha Updated" || len(updated.Scopes) != 1 || updated.Scopes[0] != "email" {
		t.Fatalf("updated client = %+v, %v | 更新后客户端不符", updated, err)
	}
	if err := first.Clients.UpdateClient(testContext, nil); !errors.Is(err, authoauth2.ErrInvalidClient) {
		t.Fatalf("nil update error = %v, want ErrInvalidClient | nil 更新错误不符", err)
	}
	if err := first.Clients.UpdateClient(testContext, sampleClient("missing")); !errors.Is(err, authoauth2.ErrInvalidClient) {
		t.Fatalf("unknown update error = %v, want ErrInvalidClient | 未知客户端更新错误不符", err)
	}
	if err := second.Clients.DeleteClient(testContext, "bravo"); err != nil {
		t.Fatalf("delete: %v | 删除失败", err)
	}
	if _, err := first.Clients.GetClient(testContext, "bravo"); !errors.Is(err, authoauth2.ErrInvalidClient) {
		t.Fatalf("deleted client still exists: %v | 已删除客户端仍存在", err)
	}
	if err := first.Clients.DeleteClient(testContext, "bravo"); !errors.Is(err, authoauth2.ErrInvalidClient) {
		t.Fatalf("second delete error = %v, want ErrInvalidClient | 二次删除错误不符", err)
	}
	list, err = second.Clients.ListClients(testContext)
	if err != nil || len(list) != 2 || list[0].ID != "alpha" || list[1].ID != "charlie" {
		t.Fatalf("list after delete = %v, %v | 删除后列表不符", list, err)
	}
}

// TestClientsPagination covers cursor pagination, default limits and clamping.
// | TestClientsPagination 覆盖游标分页、默认上限与钳制。
func TestClientsPagination(t *testing.T) {
	first, second := newPair(t, oauth2store.Options{})
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		if err := first.Clients.CreateClient(testContext, sampleClient(id)); err != nil {
			t.Fatalf("create %s: %v | 创建客户端失败", id, err)
		}
	}
	page, next, err := second.Clients.ListClientsPage(testContext, "", 2)
	if err != nil || len(page) != 2 || page[0].ID != "a" || page[1].ID != "b" || next != "b" {
		t.Fatalf("page 1 = %v, %q, %v | 第一页不符", page, next, err)
	}
	page, next, err = first.Clients.ListClientsPage(testContext, next, 2)
	if err != nil || len(page) != 2 || page[0].ID != "c" || page[1].ID != "d" || next != "d" {
		t.Fatalf("page 2 = %v, %q, %v | 第二页不符", page, next, err)
	}
	page, next, err = second.Clients.ListClientsPage(testContext, next, 2)
	if err != nil || len(page) != 1 || page[0].ID != "e" || next != "" {
		t.Fatalf("page 3 = %v, %q, %v | 第三页不符", page, next, err)
	}
	page, next, err = first.Clients.ListClientsPage(testContext, "", 0)
	if err != nil || len(page) != 5 || next != "" {
		t.Fatalf("default limit = %v, %q, %v | 默认上限不符", page, next, err)
	}
	page, next, err = first.Clients.ListClientsPage(testContext, "", 10000)
	if err != nil || len(page) != 5 || next != "" {
		t.Fatalf("clamped limit = %v, %q, %v | 钳制上限不符", page, next, err)
	}
	page, next, err = first.Clients.ListClientsPage(testContext, "zzz", 2)
	if err != nil || len(page) != 0 || next != "" {
		t.Fatalf("past-end page = %v, %q, %v | 越界页不符", page, next, err)
	}
}
