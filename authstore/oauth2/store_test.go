package oauth2_test

import (
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	authoauth2 "github.com/shibingli/ydx/auth/protocol/oauth2"
	oauth2store "github.com/shibingli/ydx/authstore/oauth2"
)

// TestAuthorizationCodes covers save, single-use consumption, expiry and cleanup.
// | TestAuthorizationCodes 覆盖保存、单次使用消费、过期与清理。
func TestAuthorizationCodes(t *testing.T) {
	first, second := newPair(t, oauth2store.Options{})
	base := testTime(2026, time.January, 10, 10, 0, 0)
	code := sampleCode("code-1", base.Add(time.Hour))
	if err := first.Store.SaveAuthorizationCode(testContext, code); err != nil {
		t.Fatalf("save: %v | 保存失败", err)
	}
	if err := first.Store.SaveAuthorizationCode(testContext, code); !errors.Is(err, authoauth2.ErrServerError) {
		t.Fatalf("duplicate error = %v, want ErrServerError | 重复保存错误不符", err)
	}
	if err := first.Store.SaveAuthorizationCode(testContext, nil); !errors.Is(err, authoauth2.ErrInvalidRequest) {
		t.Fatalf("nil error = %v, want ErrInvalidRequest | nil 错误不符", err)
	}
	if err := first.Store.SaveAuthorizationCode(testContext, &authoauth2.AuthorizationCode{}); !errors.Is(err, authoauth2.ErrInvalidRequest) {
		t.Fatalf("empty error = %v, want ErrInvalidRequest | 空授权码错误不符", err)
	}
	got, err := second.Store.ConsumeAuthorizationCode(testContext, "code-1", base)
	if err != nil {
		t.Fatalf("consume: %v | 消费失败", err)
	}
	if !got.Used || got.ClientID != "client-1" || len(got.Scopes) != 2 {
		t.Fatalf("consumed code = %+v | 已消费授权码不符", got)
	}
	if _, err := first.Store.ConsumeAuthorizationCode(testContext, "code-1", base); !errors.Is(err, authoauth2.ErrInvalidGrant) {
		t.Fatalf("second consume error = %v, want ErrInvalidGrant | 二次消费错误不符", err)
	}
	if _, err := first.Store.ConsumeAuthorizationCode(testContext, "missing", base); !errors.Is(err, authoauth2.ErrInvalidGrant) {
		t.Fatalf("unknown consume error = %v, want ErrInvalidGrant | 未知授权码错误不符", err)
	}
	expired := sampleCode("expired", base)
	if err := first.Store.SaveAuthorizationCode(testContext, expired); err != nil {
		t.Fatalf("save expired: %v | 保存过期授权码失败", err)
	}
	if _, err := first.Store.ConsumeAuthorizationCode(testContext, "expired", base); !errors.Is(err, authoauth2.ErrInvalidGrant) {
		t.Fatalf("expired consume error = %v, want ErrInvalidGrant | 过期授权码错误不符", err)
	}
	presetUsed := sampleCode("preset-used", base.Add(time.Hour))
	presetUsed.Used = true
	if err := first.Store.SaveAuthorizationCode(testContext, presetUsed); err != nil {
		t.Fatalf("save preset-used: %v | 保存已用授权码失败", err)
	}
	if _, err := first.Store.ConsumeAuthorizationCode(testContext, presetUsed.CodeHash, base); !errors.Is(err, authoauth2.ErrInvalidGrant) {
		t.Fatalf("preset-used consume error = %v, want ErrInvalidGrant | 预置已用授权码错误不符", err)
	}
	if err := first.Store.Cleanup(testContext, base.Add(2*time.Hour)); err != nil {
		t.Fatalf("cleanup: %v | 清理失败", err)
	}
	if _, err := first.Store.ConsumeAuthorizationCode(testContext, "expired", base); !errors.Is(err, authoauth2.ErrInvalidGrant) {
		t.Fatalf("code survived cleanup: %v | 授权码未在清理后删除", err)
	}
}

// TestRefreshTokens covers storage, rotation, family and subject revocation, collisions and
// cleanup. | TestRefreshTokens 覆盖存储、轮换、家族与主体撤销、碰撞与清理。
func TestRefreshTokens(t *testing.T) {
	first, second := newPair(t, oauth2store.Options{})
	base := testTime(2026, time.February, 10, 10, 0, 0)
	token := sampleRefresh("refresh-1", "family-1", base.Add(time.Hour))
	if err := first.Store.SaveRefreshToken(testContext, token); err != nil {
		t.Fatalf("save: %v | 保存失败", err)
	}
	if err := first.Store.SaveRefreshToken(testContext, token); !errors.Is(err, authoauth2.ErrServerError) {
		t.Fatalf("duplicate error = %v, want ErrServerError | 重复保存错误不符", err)
	}
	if err := first.Store.SaveRefreshToken(testContext, nil); !errors.Is(err, authoauth2.ErrInvalidRequest) {
		t.Fatalf("nil error = %v, want ErrInvalidRequest | nil 错误不符", err)
	}
	got, err := second.Store.GetRefreshToken(testContext, "refresh-1")
	if err != nil {
		t.Fatalf("get: %v | 读取失败", err)
	}
	if got.FamilyID != "family-1" || got.Principal == nil || got.Principal.Subject != "subject-1" {
		t.Fatalf("token = %+v | 刷新令牌不符", got)
	}
	if _, err := first.Store.GetRefreshToken(testContext, "missing"); !errors.Is(err, authoauth2.ErrInvalidGrant) {
		t.Fatalf("unknown get error = %v, want ErrInvalidGrant | 未知令牌错误不符", err)
	}
	if _, err := first.Store.RotateRefreshToken(testContext, "refresh-1", nil, base); !errors.Is(err, authoauth2.ErrInvalidRequest) {
		t.Fatalf("nil replacement error = %v, want ErrInvalidRequest | 空替换令牌错误不符", err)
	}
	if _, err := first.Store.RotateRefreshToken(testContext, "refresh-1", &authoauth2.RefreshToken{}, base); !errors.Is(err, authoauth2.ErrInvalidRequest) {
		t.Fatalf("empty replacement error = %v, want ErrInvalidRequest | 空替换令牌错误不符", err)
	}
	child := sampleRefresh("refresh-2", "family-1", base.Add(2*time.Hour))
	ok, err := second.Store.RotateRefreshToken(testContext, "refresh-1", child, base)
	if err != nil || !ok {
		t.Fatalf("rotate = %v, %v | 轮换失败", ok, err)
	}
	old, err := first.Store.GetRefreshToken(testContext, "refresh-1")
	if err != nil || !old.Used {
		t.Fatalf("old token = %+v, %v; want used | 旧令牌未标记已用", old, err)
	}
	if ok, err := first.Store.RotateRefreshToken(testContext, "refresh-1", sampleRefresh("refresh-3", "family-1", base.Add(3*time.Hour)), base); err != nil || ok {
		t.Fatalf("second rotate = %v, %v; want false | 二次轮换应失败", ok, err)
	}
	if ok, err := first.Store.RotateRefreshToken(testContext, "missing", sampleRefresh("refresh-x", "family-1", base.Add(time.Hour)), base); err != nil || ok {
		t.Fatalf("unknown rotate = %v, %v; want false | 未知令牌轮换应失败", ok, err)
	}
	expired := sampleRefresh("refresh-expired", "family-expired", base)
	if err := first.Store.SaveRefreshToken(testContext, expired); err != nil {
		t.Fatalf("save expired: %v | 保存过期令牌失败", err)
	}
	if ok, err := first.Store.RotateRefreshToken(testContext, "refresh-expired", sampleRefresh("refresh-expired-child", "family-expired", base.Add(time.Hour)), base); err != nil || ok {
		t.Fatalf("expired rotate = %v, %v; want false | 过期令牌轮换应失败", ok, err)
	}
	if err := first.Store.SaveRefreshToken(testContext, sampleRefresh("collision", "family-2", base.Add(time.Hour))); err != nil {
		t.Fatalf("save collision: %v | 保存碰撞令牌失败", err)
	}
	if ok, err := first.Store.RotateRefreshToken(testContext, "refresh-2", sampleRefresh("collision", "family-1", base.Add(time.Hour)), base); !errors.Is(err, authoauth2.ErrServerError) || ok {
		t.Fatalf("collision rotate = %v, %v; want ErrServerError | 碰撞轮换错误不符", ok, err)
	}
	childAfter, err := first.Store.GetRefreshToken(testContext, "refresh-2")
	if err != nil || childAfter.Used {
		t.Fatalf("collision consumed the old token: %+v, %v | 碰撞仍消费了旧令牌", childAfter, err)
	}

	familyA := sampleRefresh("family-a", "revoke-family", base.Add(time.Hour))
	familyB := sampleRefresh("family-b", "revoke-family", base.Add(time.Hour))
	familyC := sampleRefresh("family-c", "other-family", base.Add(time.Hour))
	for _, item := range []*authoauth2.RefreshToken{familyA, familyB, familyC} {
		if err := first.Store.SaveRefreshToken(testContext, item); err != nil {
			t.Fatalf("save family: %v | 保存家族令牌失败", err)
		}
	}
	if err := second.Store.RevokeRefreshToken(testContext, "family-a", true); err != nil {
		t.Fatalf("revoke family: %v | 撤销家族失败", err)
	}
	for _, hash := range []string{"family-a", "family-b"} {
		item, err := first.Store.GetRefreshToken(testContext, hash)
		if err != nil || !item.Revoked {
			t.Fatalf("%s not revoked: %+v, %v | 家族令牌未撤销", hash, item, err)
		}
	}
	if item, err := first.Store.GetRefreshToken(testContext, "family-c"); err != nil || item.Revoked {
		t.Fatalf("other family revoked: %+v, %v | 其他家族被误撤销", item, err)
	}
	if err := first.Store.RevokeRefreshToken(testContext, "missing", false); !errors.Is(err, authoauth2.ErrInvalidGrant) {
		t.Fatalf("unknown revoke error = %v, want ErrInvalidGrant | 未知撤销错误不符", err)
	}
	if err := first.Store.RevokeRefreshToken(testContext, "family-c", false); err != nil {
		t.Fatalf("revoke single: %v | 单令牌撤销失败", err)
	}
	if item, err := first.Store.GetRefreshToken(testContext, "family-c"); err != nil || !item.Revoked {
		t.Fatalf("single token not revoked: %+v, %v | 单令牌未撤销", item, err)
	}

	subjectA := sampleRefresh("subject-a", "subject-family", base.Add(time.Hour))
	subjectA.ClientID, subjectA.Subject = "subject-client", "subject-target"
	subjectB := sampleRefresh("subject-b", "subject-family", base.Add(time.Hour))
	subjectB.ClientID, subjectB.Subject = "subject-client", "subject-target"
	for _, item := range []*authoauth2.RefreshToken{subjectA, subjectB} {
		if err := first.Store.SaveRefreshToken(testContext, item); err != nil {
			t.Fatalf("save subject: %v | 保存主体令牌失败", err)
		}
	}
	other := sampleRefresh("subject-other", "subject-family-2", base.Add(time.Hour))
	other.ClientID, other.Subject = "client-2", "subject-target"
	if err := first.Store.SaveRefreshToken(testContext, other); err != nil {
		t.Fatalf("save other subject: %v | 保存其他主体令牌失败", err)
	}
	count, err := second.Store.RevokeRefreshTokensForSubject(testContext, "subject-client", "subject-target")
	if err != nil || count != 2 {
		t.Fatalf("revoke subject count = %d, %v; want 2 | 主体撤销数量不符", count, err)
	}
	if count, err := second.Store.RevokeRefreshTokensForSubject(testContext, "subject-client", "subject-target"); err != nil || count != 0 {
		t.Fatalf("repeat revoke count = %d, %v; want 0 | 重复主体撤销数量不符", count, err)
	}
	if count, err := second.Store.RevokeRefreshTokensForSubject(testContext, "client-2", "subject-target"); err != nil || count != 1 {
		t.Fatalf("other client count = %d, %v; want 1 | 其他客户端撤销数量不符", count, err)
	}

	if err := first.Store.Cleanup(testContext, base.Add(3*time.Hour)); err != nil {
		t.Fatalf("cleanup: %v | 清理失败", err)
	}
	if _, err := first.Store.GetRefreshToken(testContext, "refresh-expired"); !errors.Is(err, authoauth2.ErrInvalidGrant) {
		t.Fatalf("expired token survived cleanup: %v | 过期令牌未在清理后删除", err)
	}
}

// TestAccessTokens covers save, get, revocation and cleanup. | TestAccessTokens 覆盖保存、读取、撤销与清理。
func TestAccessTokens(t *testing.T) {
	first, second := newPair(t, oauth2store.Options{})
	base := testTime(2026, time.March, 10, 10, 0, 0)
	token := sampleAccess("access-1", base.Add(time.Hour))
	if err := first.Store.SaveAccessToken(testContext, token); err != nil {
		t.Fatalf("save: %v | 保存失败", err)
	}
	if err := first.Store.SaveAccessToken(testContext, token); !errors.Is(err, authoauth2.ErrServerError) {
		t.Fatalf("duplicate error = %v, want ErrServerError | 重复保存错误不符", err)
	}
	if err := first.Store.SaveAccessToken(testContext, nil); !errors.Is(err, authoauth2.ErrInvalidRequest) {
		t.Fatalf("nil error = %v, want ErrInvalidRequest | nil 错误不符", err)
	}
	got, err := second.Store.GetAccessToken(testContext, "access-1")
	if err != nil || got.Subject != "subject-1" || got.JTI != "jti-access-1" || got.Revoked {
		t.Fatalf("get = %+v, %v | 读取访问令牌不符", got, err)
	}
	if _, err := first.Store.GetAccessToken(testContext, "missing"); !errors.Is(err, authoauth2.ErrInvalidGrant) {
		t.Fatalf("unknown get error = %v, want ErrInvalidGrant | 未知访问令牌错误不符", err)
	}
	if err := first.Store.RevokeAccessToken(testContext, "missing"); !errors.Is(err, authoauth2.ErrInvalidGrant) {
		t.Fatalf("unknown revoke error = %v, want ErrInvalidGrant | 未知撤销错误不符", err)
	}
	if err := second.Store.RevokeAccessToken(testContext, "access-1"); err != nil {
		t.Fatalf("revoke: %v | 撤销失败", err)
	}
	if got, err := first.Store.GetAccessToken(testContext, "access-1"); err != nil || !got.Revoked {
		t.Fatalf("token not revoked: %+v, %v | 令牌未撤销", got, err)
	}
	expired := sampleAccess("access-expired", base)
	if err := first.Store.SaveAccessToken(testContext, expired); err != nil {
		t.Fatalf("save expired: %v | 保存过期令牌失败", err)
	}
	if err := first.Store.Cleanup(testContext, base.Add(2*time.Hour)); err != nil {
		t.Fatalf("cleanup: %v | 清理失败", err)
	}
	if _, err := first.Store.GetAccessToken(testContext, "access-expired"); !errors.Is(err, authoauth2.ErrInvalidGrant) {
		t.Fatalf("expired token survived cleanup: %v | 过期令牌未在清理后删除", err)
	}
}

// TestDeviceCodes covers storage, indexes, updates, approval, polling, expiry and cleanup.
// | TestDeviceCodes 覆盖存储、索引、更新、批准、轮询、过期与清理。
func TestDeviceCodes(t *testing.T) {
	first, second := newPair(t, oauth2store.Options{})
	base := testTime(2026, time.April, 10, 10, 0, 0)
	device := sampleDevice("device-1", "user-1", "client-1", base.Add(time.Hour))
	if err := first.Store.SaveDeviceCode(testContext, device); err != nil {
		t.Fatalf("save: %v | 保存失败", err)
	}
	if err := first.Store.SaveDeviceCode(testContext, device); !errors.Is(err, authoauth2.ErrServerError) {
		t.Fatalf("duplicate error = %v, want ErrServerError | 重复设备码错误不符", err)
	}
	other := sampleDevice("device-2", "user-1", "client-1", base.Add(time.Hour))
	if err := first.Store.SaveDeviceCode(testContext, other); !errors.Is(err, authoauth2.ErrServerError) {
		t.Fatalf("user code collision error = %v, want ErrServerError | 用户码碰撞错误不符", err)
	}
	if err := first.Store.SaveDeviceCode(testContext, nil); !errors.Is(err, authoauth2.ErrInvalidRequest) {
		t.Fatalf("nil error = %v, want ErrInvalidRequest | nil 错误不符", err)
	}
	if err := first.Store.SaveDeviceCode(testContext, &authoauth2.DeviceCode{DeviceCodeHash: "x"}); !errors.Is(err, authoauth2.ErrInvalidRequest) {
		t.Fatalf("empty user code error = %v, want ErrInvalidRequest | 空用户码错误不符", err)
	}
	byUser, err := second.Store.GetDeviceCodeByUserCode(testContext, "user-1")
	if err != nil || byUser.DeviceCodeHash != "device-1" || byUser.Status != authoauth2.DevicePending {
		t.Fatalf("get by user = %+v, %v | 按用户码读取不符", byUser, err)
	}
	byHash, err := first.Store.GetDeviceCode(testContext, "device-1")
	if err != nil || byHash.UserCode != "user-1" {
		t.Fatalf("get by hash = %+v, %v | 按哈希读取不符", byHash, err)
	}
	if _, err := first.Store.GetDeviceCodeByUserCode(testContext, "missing"); !errors.Is(err, authoauth2.ErrInvalidGrant) {
		t.Fatalf("unknown user error = %v, want ErrInvalidGrant | 未知用户码错误不符", err)
	}
	if _, err := first.Store.GetDeviceCode(testContext, "missing"); !errors.Is(err, authoauth2.ErrInvalidGrant) {
		t.Fatalf("unknown device error = %v, want ErrInvalidGrant | 未知设备码错误不符", err)
	}
	if err := first.Store.UpdateDeviceCode(testContext, nil); !errors.Is(err, authoauth2.ErrInvalidRequest) {
		t.Fatalf("nil update error = %v, want ErrInvalidRequest | nil 更新错误不符", err)
	}
	if err := first.Store.UpdateDeviceCode(testContext, sampleDevice("missing", "user-missing", "client-1", base.Add(time.Hour))); !errors.Is(err, authoauth2.ErrInvalidGrant) {
		t.Fatalf("unknown update error = %v, want ErrInvalidGrant | 未知设备码更新错误不符", err)
	}
	updated := byHash
	updated.UserCode = "user-changed"
	updated.Scopes = []string{"email"}
	if err := second.Store.UpdateDeviceCode(testContext, updated); err != nil {
		t.Fatalf("update: %v | 更新失败", err)
	}
	oldIndex, err := first.Store.GetDeviceCodeByUserCode(testContext, "user-1")
	if err != nil || oldIndex.UserCode != "user-changed" || len(oldIndex.Scopes) != 1 {
		t.Fatalf("old user index = %+v, %v | 旧用户码索引未保留", oldIndex, err)
	}
	if _, err := first.Store.GetDeviceCodeByUserCode(testContext, "user-changed"); !errors.Is(err, authoauth2.ErrInvalidGrant) {
		t.Fatalf("new user index unexpectedly exists: %v | 新用户码索引不应存在", err)
	}

	principal := samplePrincipal("subject-9")
	approved, err := second.Store.SetDeviceCodeStatus(testContext, "user-1", authoauth2.DeviceApproved, base, principal)
	if err != nil {
		t.Fatalf("approve: %v | 批准失败", err)
	}
	if approved.Status != authoauth2.DeviceApproved || approved.UserID != "subject-9" ||
		approved.Subject != "subject-9" || approved.DPoPJKT != "thumbprint-1" || approved.Principal == nil {
		t.Fatalf("approved device = %+v | 已批准设备不符", approved)
	}
	if approved.Principal.AuthTime.Location() != time.UTC {
		t.Fatalf("principal time is not UTC: %v | 主体时间未规范化为 UTC", approved.Principal.AuthTime.Location())
	}
	if _, err := first.Store.SetDeviceCodeStatus(testContext, "user-1", authoauth2.DeviceApproved, base, principal); !errors.Is(err, authoauth2.ErrInvalidGrant) {
		t.Fatalf("second approve error = %v, want ErrInvalidGrant | 二次批准错误不符", err)
	}
	if _, err := first.Store.SetDeviceCodeStatus(testContext, "missing", authoauth2.DeviceDenied, base, nil); !errors.Is(err, authoauth2.ErrInvalidGrant) {
		t.Fatalf("unknown status error = %v, want ErrInvalidGrant | 未知用户码状态错误不符", err)
	}
	if _, err := first.Store.SetDeviceCodeStatus(testContext, "user-1", "bogus", base, nil); !errors.Is(err, authoauth2.ErrInvalidRequest) {
		t.Fatalf("unsupported status error = %v, want ErrInvalidRequest | 不支持状态错误不符", err)
	}
	if _, err := first.Store.SetDeviceCodeStatus(testContext, "user-1", authoauth2.DeviceApproved, base, nil); !errors.Is(err, authoauth2.ErrAccessDenied) {
		t.Fatalf("nil principal error = %v, want ErrAccessDenied | nil 主体错误不符", err)
	}
	preserved := sampleDevice("device-preserved", "user-preserved", "client-1", base.Add(time.Hour))
	preserved.DPoPJKT = "preset-thumbprint"
	if err := first.Store.SaveDeviceCode(testContext, preserved); err != nil {
		t.Fatalf("save preserved: %v | 保存保留指纹设备失败", err)
	}
	noAttrs := samplePrincipal("subject-preserved")
	noAttrs.Attributes = nil
	preservedApproved, err := second.Store.SetDeviceCodeStatus(testContext, "user-preserved", authoauth2.DeviceApproved, base, noAttrs)
	if err != nil || preservedApproved.DPoPJKT != "preset-thumbprint" {
		t.Fatalf("preserved approval = %+v, %v | 主体无属性时的指纹保留不符", preservedApproved, err)
	}
	polled, accepted, err := first.Store.PollDeviceCode(testContext, "device-1", "client-1", base)
	if err != nil || !accepted || polled.Status != authoauth2.DeviceApproved {
		t.Fatalf("first poll = %+v, %v, %v; want approved | 首次轮询状态不符", polled, accepted, err)
	}
	used, accepted, err := second.Store.PollDeviceCode(testContext, "device-1", "client-1", base)
	if err != nil || !accepted || used.Status != authoauth2.DeviceUsed {
		t.Fatalf("second poll = %+v, %v, %v; want used | 二次轮询状态不符", used, accepted, err)
	}

	pending := sampleDevice("device-3", "user-3", "client-1", base.Add(time.Hour))
	if err := first.Store.SaveDeviceCode(testContext, pending); err != nil {
		t.Fatalf("save pending: %v | 保存等待设备失败", err)
	}
	if _, _, err := first.Store.PollDeviceCode(testContext, "device-3", "client-2", base); !errors.Is(err, authoauth2.ErrInvalidGrant) {
		t.Fatalf("foreign client poll error = %v, want ErrInvalidGrant | 其他客户端轮询错误不符", err)
	}
	if _, _, err := first.Store.PollDeviceCode(testContext, "missing", "client-1", base); !errors.Is(err, authoauth2.ErrInvalidGrant) {
		t.Fatalf("unknown poll error = %v, want ErrInvalidGrant | 未知设备轮询错误不符", err)
	}
	firstPoll, accepted, err := first.Store.PollDeviceCode(testContext, "device-3", "client-1", base)
	if err != nil || !accepted || !firstPoll.LastPolledAt.Equal(base) {
		t.Fatalf("pending first poll = %+v, %v, %v | 等待设备首次轮询不符", firstPoll, accepted, err)
	}
	slow, accepted, err := second.Store.PollDeviceCode(testContext, "device-3", "client-1", base.Add(time.Second))
	if err != nil || accepted || slow.Interval != 10*time.Second || !slow.LastPolledAt.Equal(base) {
		t.Fatalf("slow poll = %+v, %v, %v | 过快轮询不符", slow, accepted, err)
	}
	next, accepted, err := first.Store.PollDeviceCode(testContext, "device-3", "client-1", base.Add(10*time.Second))
	if err != nil || !accepted || !next.LastPolledAt.Equal(base.Add(10*time.Second)) || next.Interval != 10*time.Second {
		t.Fatalf("next poll = %+v, %v, %v | 下一轮轮询不符", next, accepted, err)
	}

	expired := sampleDevice("device-expired", "user-expired", "client-1", base)
	if err := first.Store.SaveDeviceCode(testContext, expired); err != nil {
		t.Fatalf("save expired: %v | 保存过期设备失败", err)
	}
	expiredPoll, accepted, err := first.Store.PollDeviceCode(testContext, "device-expired", "client-1", base)
	if err != nil || accepted || expiredPoll.Status != authoauth2.DeviceExpired {
		t.Fatalf("expired poll = %+v, %v, %v | 过期设备轮询不符", expiredPoll, accepted, err)
	}
	statusExpired := sampleDevice("device-status-expired", "user-status-expired", "client-1", base)
	if err := first.Store.SaveDeviceCode(testContext, statusExpired); err != nil {
		t.Fatalf("save status expired: %v | 保存状态过期设备失败", err)
	}
	if _, err := first.Store.SetDeviceCodeStatus(testContext, "user-status-expired", authoauth2.DeviceDenied, base, nil); !errors.Is(err, authoauth2.ErrInvalidGrant) {
		t.Fatalf("expired status error = %v, want ErrInvalidGrant | 过期设备状态错误不符", err)
	}
	if got, err := first.Store.GetDeviceCode(testContext, "device-status-expired"); err != nil || got.Status != authoauth2.DeviceExpired {
		t.Fatalf("expired status = %+v, %v | 过期状态未持久化", got, err)
	}

	denied := sampleDevice("device-denied", "user-denied", "client-1", base.Add(time.Hour))
	if err := first.Store.SaveDeviceCode(testContext, denied); err != nil {
		t.Fatalf("save denied: %v | 保存拒绝设备失败", err)
	}
	if got, err := first.Store.SetDeviceCodeStatus(testContext, "user-denied", authoauth2.DeviceDenied, base, nil); err != nil || got.Status != authoauth2.DeviceDenied {
		t.Fatalf("deny = %+v, %v | 拒绝设备失败", got, err)
	}

	if err := first.Store.Cleanup(testContext, base.Add(2*time.Hour)); err != nil {
		t.Fatalf("cleanup: %v | 清理失败", err)
	}
	if _, err := first.Store.GetDeviceCode(testContext, "device-expired"); !errors.Is(err, authoauth2.ErrInvalidGrant) {
		t.Fatalf("expired device survived cleanup: %v | 过期设备未在清理后删除", err)
	}
	if _, err := first.Store.GetDeviceCodeByUserCode(testContext, "user-expired"); !errors.Is(err, authoauth2.ErrInvalidGrant) {
		t.Fatalf("expired user index survived cleanup: %v | 过期用户码索引未在清理后删除", err)
	}
}

// TestPARRequests covers save, single-use consumption, expiry and cleanup.
// | TestPARRequests 覆盖保存、单次使用消费、过期与清理。
func TestPARRequests(t *testing.T) {
	first, second := newPair(t, oauth2store.Options{})
	base := testTime(2026, time.May, 10, 10, 0, 0)
	request := samplePAR("urn:ietf:params:oauth:request_uri:one", base.Add(time.Hour))
	if err := first.Store.SavePAR(testContext, request); err != nil {
		t.Fatalf("save: %v | 保存失败", err)
	}
	if err := first.Store.SavePAR(testContext, request); !errors.Is(err, authoauth2.ErrServerError) {
		t.Fatalf("duplicate error = %v, want ErrServerError | 重复保存错误不符", err)
	}
	if err := first.Store.SavePAR(testContext, nil); !errors.Is(err, authoauth2.ErrInvalidRequest) {
		t.Fatalf("nil error = %v, want ErrInvalidRequest | nil 错误不符", err)
	}
	if err := first.Store.SavePAR(testContext, &authoauth2.PARRequest{}); !errors.Is(err, authoauth2.ErrInvalidRequest) {
		t.Fatalf("empty error = %v, want ErrInvalidRequest | 空请求错误不符", err)
	}
	got, err := second.Store.ConsumePAR(testContext, request.RequestURI, base)
	if err != nil || !got.Used || got.ClientID != "client-1" || len(got.Params["scope"]) != 2 {
		t.Fatalf("consume = %+v, %v | 消费请求不符", got, err)
	}
	if _, err := first.Store.ConsumePAR(testContext, request.RequestURI, base); !errors.Is(err, authoauth2.ErrInvalidRequest) {
		t.Fatalf("second consume error = %v, want ErrInvalidRequest | 二次消费错误不符", err)
	}
	if _, err := first.Store.ConsumePAR(testContext, "urn:missing", base); !errors.Is(err, authoauth2.ErrInvalidRequest) {
		t.Fatalf("unknown consume error = %v, want ErrInvalidRequest | 未知请求错误不符", err)
	}
	expired := samplePAR("urn:ietf:params:oauth:request_uri:expired", base)
	if err := first.Store.SavePAR(testContext, expired); err != nil {
		t.Fatalf("save expired: %v | 保存过期请求失败", err)
	}
	if _, err := first.Store.ConsumePAR(testContext, expired.RequestURI, base); !errors.Is(err, authoauth2.ErrInvalidRequest) {
		t.Fatalf("expired consume error = %v, want ErrInvalidRequest | 过期请求错误不符", err)
	}
	presetUsed := samplePAR("urn:preset-used", base.Add(time.Hour))
	presetUsed.Used = true
	if err := first.Store.SavePAR(testContext, presetUsed); err != nil {
		t.Fatalf("save preset-used: %v | 保存已用请求失败", err)
	}
	if _, err := first.Store.ConsumePAR(testContext, presetUsed.RequestURI, base); !errors.Is(err, authoauth2.ErrInvalidRequest) {
		t.Fatalf("preset-used consume error = %v, want ErrInvalidRequest | 预置已用请求错误不符", err)
	}
	if err := first.Store.Cleanup(testContext, base.Add(2*time.Hour)); err != nil {
		t.Fatalf("cleanup: %v | 清理失败", err)
	}
	if _, err := first.Store.ConsumePAR(testContext, expired.RequestURI, base); !errors.Is(err, authoauth2.ErrInvalidRequest) {
		t.Fatalf("expired request survived cleanup: %v | 过期请求未在清理后删除", err)
	}
}

// TestCleanupKeepsLiveRecords verifies that cleanup does not delete live records.
// | TestCleanupKeepsLiveRecords 验证清理不会删除有效记录。
func TestCleanupKeepsLiveRecords(t *testing.T) {
	stores := newStoresOn(t, miniredis.RunT(t), oauth2store.Options{})
	base := testTime(2026, time.June, 10, 10, 0, 0)
	liveExpiry := base.Add(24 * time.Hour)
	if err := stores.Store.SaveAuthorizationCode(testContext, sampleCode("live-code", liveExpiry)); err != nil {
		t.Fatalf("save code: %v | 保存授权码失败", err)
	}
	if err := stores.Store.SaveRefreshToken(testContext, sampleRefresh("live-refresh", "live-family", liveExpiry)); err != nil {
		t.Fatalf("save refresh: %v | 保存刷新令牌失败", err)
	}
	if err := stores.Store.SaveAccessToken(testContext, sampleAccess("live-access", liveExpiry)); err != nil {
		t.Fatalf("save access: %v | 保存访问令牌失败", err)
	}
	if err := stores.Store.SaveDeviceCode(testContext, sampleDevice("live-device", "live-user", "client-1", liveExpiry)); err != nil {
		t.Fatalf("save device: %v | 保存设备码失败", err)
	}
	if err := stores.Store.SavePAR(testContext, samplePAR("urn:live", liveExpiry)); err != nil {
		t.Fatalf("save par: %v | 保存推送请求失败", err)
	}
	if err := stores.Store.Cleanup(testContext, base); err != nil {
		t.Fatalf("cleanup: %v | 清理失败", err)
	}
	if _, err := stores.Store.ConsumeAuthorizationCode(testContext, "live-code", base); err != nil {
		t.Fatalf("live code deleted: %v | 有效授权码被删除", err)
	}
	if _, err := stores.Store.GetRefreshToken(testContext, "live-refresh"); err != nil {
		t.Fatalf("live refresh deleted: %v | 有效刷新令牌被删除", err)
	}
	if _, err := stores.Store.GetAccessToken(testContext, "live-access"); err != nil {
		t.Fatalf("live access deleted: %v | 有效访问令牌被删除", err)
	}
	if _, err := stores.Store.GetDeviceCodeByUserCode(testContext, "live-user"); err != nil {
		t.Fatalf("live device deleted: %v | 有效设备码被删除", err)
	}
	if _, err := stores.Store.ConsumePAR(testContext, "urn:live", base); err != nil {
		t.Fatalf("live par deleted: %v | 有效推送请求被删除", err)
	}
}
