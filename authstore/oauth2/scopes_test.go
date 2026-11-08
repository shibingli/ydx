package oauth2_test

import (
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	authoauth2 "github.com/shibingli/ydx/auth/protocol/oauth2"
	oauth2store "github.com/shibingli/ydx/authstore/oauth2"
)

// TestScopes covers registration, replacement, deletion and validation.
// | TestScopes 覆盖注册、替换、删除与校验。
func TestScopes(t *testing.T) {
	stores := newStoresOn(t, miniredis.RunT(t), oauth2store.Options{})
	if got := stores.Scopes.List(); len(got) != 0 {
		t.Fatalf("initial list = %v | 初始列表非空", got)
	}
	if stores.Scopes.Exists("openid") {
		t.Fatal("initial registry contains openid | 初始注册表包含 openid")
	}
	added, err := stores.Scopes.RegisterScopes(testContext,
		authoauth2.Scope{Name: "openid", Description: "OpenID", Claims: []string{"sub"}},
		authoauth2.Scope{Name: "profile", Description: "Profile"},
		authoauth2.Scope{Name: ""},
		authoauth2.Scope{Name: "openid", Description: "duplicate"},
	)
	if err != nil || added != 2 {
		t.Fatalf("register = %d, %v; want 2 | 注册数量不符", added, err)
	}
	if added, err := stores.Scopes.RegisterScopes(testContext, authoauth2.Scope{Name: "openid"}); err != nil || added != 0 {
		t.Fatalf("duplicate register = %d, %v; want 0 | 重复注册数量不符", added, err)
	}
	if got := stores.Scopes.List(); len(got) != 2 || got[0] != "openid" || got[1] != "profile" {
		t.Fatalf("list = %v | 作用域列表不符", got)
	}
	if got := stores.Scopes.SortedScopes(); len(got) != 2 || got[0] != "openid" || got[1] != "profile" {
		t.Fatalf("sorted = %v | 排序作用域不符", got)
	}
	scope, ok := stores.Scopes.Get("openid")
	if !ok || scope.Description != "OpenID" || len(scope.Claims) != 1 {
		t.Fatalf("get = %+v, %v | 作用域定义不符", scope, ok)
	}
	scope.Claims[0] = "mutated"
	again, _ := stores.Scopes.Get("openid")
	if again.Claims[0] != "sub" {
		t.Fatalf("Get exposed internal claims: %v | Get 暴露了内部声明切片", again.Claims)
	}
	if _, ok := stores.Scopes.Get("missing"); ok {
		t.Fatal("missing scope reported present | 缺失作用域被报告为存在")
	}

	granted, err := stores.Scopes.Validate([]string{" openid ", "openid", ""}, nil)
	if err != nil || len(granted) != 1 || granted[0] != "openid" {
		t.Fatalf("validate = %v, %v | 校验结果不符", granted, err)
	}
	if granted, err := stores.Scopes.Validate(nil, nil); err != nil || len(granted) != 0 {
		t.Fatalf("empty validate = %v, %v | 空校验结果不符", granted, err)
	}
	if _, err := stores.Scopes.Validate([]string{" unknown "}, nil); !errors.Is(err, authoauth2.ErrInvalidScope) {
		t.Fatalf("unknown validate error = %v, want ErrInvalidScope | 未知作用域错误不符", err)
	}
	if _, err := stores.Scopes.Validate([]string{""}, nil); !errors.Is(err, authoauth2.ErrInvalidScope) {
		t.Fatalf("blank validate error = %v, want ErrInvalidScope | 空白作用域错误不符", err)
	}
	client := &authoauth2.Client{ID: "c1", Scopes: []string{"openid"}}
	if _, err := stores.Scopes.Validate([]string{"profile"}, client); !errors.Is(err, authoauth2.ErrInvalidScope) {
		t.Fatalf("disallowed validate error = %v, want ErrInvalidScope | 客户端未授权作用域错误不符", err)
	}
	if granted, err := stores.Scopes.Validate([]string{"openid"}, client); err != nil || len(granted) != 1 {
		t.Fatalf("allowed validate = %v, %v | 客户端授权作用域校验失败", granted, err)
	}

	deleted, err := stores.Scopes.DeleteScope(testContext, "profile")
	if err != nil || !deleted {
		t.Fatalf("delete = %v, %v | 删除作用域失败", deleted, err)
	}
	if stores.Scopes.Exists("profile") {
		t.Fatal("deleted scope still exists | 已删除作用域仍存在")
	}
	if deleted, err := stores.Scopes.DeleteScope(testContext, "missing"); err != nil || deleted {
		t.Fatalf("missing delete = %v, %v | 缺失作用域删除结果不符", deleted, err)
	}
	replaced, err := stores.Scopes.ReplaceScopes(testContext,
		authoauth2.Scope{Name: "email", Description: "Email"},
		authoauth2.Scope{Name: "openid", Description: "Replaced"},
	)
	if err != nil || replaced != 2 {
		t.Fatalf("replace = %d, %v | 替换作用域失败", replaced, err)
	}
	if got := stores.Scopes.List(); len(got) != 2 || got[0] != "email" || got[1] != "openid" {
		t.Fatalf("list after replace = %v | 替换后列表不符", got)
	}
	if scope, ok := stores.Scopes.Get("openid"); !ok || scope.Description != "Replaced" {
		t.Fatalf("replace kept old definition: %+v, %v | 替换未更新定义", scope, ok)
	}
}

// TestScopesCrossInstance verifies explicit reload and lazy snapshot refresh.
// | TestScopesCrossInstance 验证显式重载与惰性快照刷新。
func TestScopesCrossInstance(t *testing.T) {
	first, second := newPair(t, oauth2store.Options{ScopeCacheTTL: -1})
	if added, err := first.Scopes.RegisterScopes(testContext, authoauth2.Scope{Name: "openid"}); err != nil || added != 1 {
		t.Fatalf("register = %d, %v | 注册失败", added, err)
	}
	if second.Scopes.Exists("openid") {
		t.Fatal("lazy-disabled instance refreshed without Reload | 关闭惰性刷新后不应自动刷新")
	}
	if err := second.Scopes.Reload(testContext); err != nil {
		t.Fatalf("reload: %v | 重载失败", err)
	}
	if !second.Scopes.Exists("openid") {
		t.Fatal("Reload did not load the scope | Reload 未加载作用域")
	}
	if added, err := second.Scopes.RegisterScopes(testContext, authoauth2.Scope{Name: "openid", Description: "second"}); err != nil || added != 0 {
		t.Fatalf("duplicate cross-instance register = %d, %v | 跨实例重复注册不符", added, err)
	}
	if scope, _ := first.Scopes.Get("openid"); scope.Description != "" {
		t.Fatalf("duplicate registration overwrote the first definition: %+v | 重复注册覆盖了首个定义", scope)
	}

	server := miniredis.RunT(t)
	fastFirst := newStoresOn(t, server, oauth2store.Options{ScopeCacheTTL: 30 * time.Millisecond})
	fastSecond := newStoresOn(t, server, oauth2store.Options{ScopeCacheTTL: 30 * time.Millisecond})
	if fastSecond.Scopes.Exists("profile") {
		t.Fatal("second instance saw an unwritten scope | 第二实例看到了未写入作用域")
	}
	if added, err := fastFirst.Scopes.RegisterScopes(testContext, authoauth2.Scope{Name: "profile"}); err != nil || added != 1 {
		t.Fatalf("fast register = %d, %v | 快速注册失败", added, err)
	}
	if fastSecond.Scopes.Exists("profile") {
		t.Fatal("snapshot refreshed before ttl | 快照在 ttl 前刷新")
	}
	time.Sleep(60 * time.Millisecond)
	if !fastSecond.Scopes.Exists("profile") {
		t.Fatal("snapshot did not refresh after ttl | 快照在 ttl 后未刷新")
	}
}
