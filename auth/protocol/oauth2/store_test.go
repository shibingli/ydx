package oauth2

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
)

func storeTestPrincipal() *auth.Principal {
	return &auth.Principal{
		Subject:    "user-1",
		AuthTime:   time.Unix(100, 0).UTC(),
		ACR:        "urn:acr:1",
		AMR:        []string{"pwd"},
		SessionID:  "session-1",
		Attributes: map[string]string{"dpop_jkt": "thumb"},
	}
}

func TestMemoryStoreAuthorizationCodes(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	now := time.Unix(1000, 0)

	if err := store.SaveAuthorizationCode(ctx, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil code = %v", err)
	}
	if err := store.SaveAuthorizationCode(ctx, &AuthorizationCode{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty code = %v", err)
	}
	code := &AuthorizationCode{
		CodeHash:  "hash-1",
		ClientID:  "client",
		Scopes:    []string{"openid"},
		AMR:       []string{"pwd"},
		Resource:  []string{"https://api.example"},
		Principal: storeTestPrincipal(),
		ExpiresAt: now.Add(time.Minute),
		CreatedAt: now,
	}
	if err := store.SaveAuthorizationCode(ctx, code); err != nil {
		t.Fatalf("save code: %v", err)
	}
	// Mutating the caller copy must not affect the stored value. | 修改调用方副本不得影响已存值。
	code.Scopes[0] = "mutated"
	code.Principal.Subject = "mutated"
	if err := store.SaveAuthorizationCode(ctx, &AuthorizationCode{CodeHash: "hash-1"}); !errors.Is(err, ErrServerError) {
		t.Fatalf("collision = %v", err)
	}
	if _, err := store.ConsumeAuthorizationCode(ctx, "unknown", now); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("unknown code = %v", err)
	}
	got, err := store.ConsumeAuthorizationCode(ctx, "hash-1", now)
	if err != nil || got.Scopes[0] != "openid" || got.Principal.Subject != "user-1" {
		t.Fatalf("consume = %+v err=%v", got, err)
	}
	if _, err := store.ConsumeAuthorizationCode(ctx, "hash-1", now); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("used code = %v", err)
	}
	if err := store.SaveAuthorizationCode(ctx, &AuthorizationCode{CodeHash: "expired", ExpiresAt: now}); err != nil {
		t.Fatalf("save expired: %v", err)
	}
	if _, err := store.ConsumeAuthorizationCode(ctx, "expired", now); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expired code = %v", err)
	}
	if (*AuthorizationCode)(nil).Clone() != nil || (*RefreshToken)(nil).Clone() != nil ||
		(*AccessToken)(nil).Clone() != nil || (*DeviceCode)(nil).Clone() != nil ||
		(*PARRequest)(nil).Clone() != nil || (*Client)(nil).clone() != nil {
		t.Fatal("nil clone")
	}
}

func TestMemoryStoreRefreshTokens(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	now := time.Unix(1000, 0)

	if err := store.SaveRefreshToken(ctx, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil refresh = %v", err)
	}
	token := &RefreshToken{
		TokenHash: "rt-1",
		FamilyID:  "family-1",
		ClientID:  "client",
		Subject:   "user",
		Principal: storeTestPrincipal(),
		Scopes:    []string{"openid"},
		Audience:  []string{"https://api.example"},
		AMR:       []string{"pwd"},
		ExpiresAt: now.Add(time.Hour),
	}
	if err := store.SaveRefreshToken(ctx, token); err != nil {
		t.Fatalf("save refresh: %v", err)
	}
	token.Scopes[0] = "mutated"
	if err := store.SaveRefreshToken(ctx, &RefreshToken{TokenHash: "rt-1"}); !errors.Is(err, ErrServerError) {
		t.Fatalf("refresh collision = %v", err)
	}
	if _, err := store.GetRefreshToken(ctx, "missing"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("unknown refresh = %v", err)
	}
	got, err := store.GetRefreshToken(ctx, "rt-1")
	if err != nil || got.Scopes[0] != "openid" || got.Principal.Subject != "user-1" {
		t.Fatalf("get refresh = %+v err=%v", got, err)
	}
	got.Scopes[0] = "mutated-again"
	got, _ = store.GetRefreshToken(ctx, "rt-1")
	if got.Scopes[0] != "openid" {
		t.Fatal("stored refresh was mutated through a clone")
	}

	replacement := &RefreshToken{TokenHash: "rt-2", FamilyID: "family-1", ClientID: "client", Subject: "user"}
	if ok, err := store.RotateRefreshToken(ctx, "rt-1", replacement, now); err != nil || !ok {
		t.Fatalf("rotate = %v err=%v", ok, err)
	}
	if ok, _ := store.RotateRefreshToken(ctx, "rt-1", &RefreshToken{TokenHash: "rt-3"}, now); ok {
		t.Fatal("rotated token accepted twice")
	}
	old, _ := store.GetRefreshToken(ctx, "rt-1")
	if old != nil && !old.Used {
		t.Fatal("rotated token is not marked used")
	}
	if _, err := store.GetRefreshToken(ctx, "rt-2"); err != nil {
		t.Fatalf("replacement missing: %v", err)
	}
	if ok, err := store.RotateRefreshToken(ctx, "missing", &RefreshToken{TokenHash: "rt-x"}, now); err != nil || ok {
		t.Fatalf("unknown rotate = %v err=%v", ok, err)
	}
	if _, err := store.RotateRefreshToken(ctx, "rt-2", nil, now); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil replacement = %v", err)
	}
	if _, err := store.RotateRefreshToken(ctx, "rt-2", &RefreshToken{TokenHash: "rt-3"}, now); err != nil {
		t.Fatalf("second rotation = %v", err)
	}
	if _, err := store.RotateRefreshToken(ctx, "rt-1", &RefreshToken{TokenHash: "rt-9"}, now); err != nil {
		t.Fatalf("used rotate error = %v", err)
	}
	if ok, err := store.RotateRefreshToken(ctx, "rt-3", &RefreshToken{TokenHash: "rt-2"}, now); ok || !errors.Is(err, ErrServerError) {
		t.Fatalf("replacement collision = %v err=%v", ok, err)
	}

	expired := &RefreshToken{TokenHash: "rt-expired", ExpiresAt: now}
	if err := store.SaveRefreshToken(ctx, expired); err != nil {
		t.Fatalf("save expired refresh: %v", err)
	}
	if ok, _ := store.RotateRefreshToken(ctx, "rt-expired", &RefreshToken{TokenHash: "rt-child"}, now); ok {
		t.Fatal("expired refresh rotated")
	}
	if err := store.SaveRefreshToken(ctx, &RefreshToken{TokenHash: "rt-revoked", Revoked: true}); err != nil {
		t.Fatalf("save revoked: %v", err)
	}
	if ok, _ := store.RotateRefreshToken(ctx, "rt-revoked", &RefreshToken{TokenHash: "rt-child-2"}, now); ok {
		t.Fatal("revoked refresh rotated")
	}

	if err := store.RevokeRefreshToken(ctx, "missing", false); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("revoke unknown = %v", err)
	}
	if err := store.RevokeRefreshToken(ctx, "rt-2", false); err != nil {
		t.Fatalf("revoke one: %v", err)
	}
	revoked, _ := store.GetRefreshToken(ctx, "rt-2")
	if revoked == nil || !revoked.Revoked {
		t.Fatal("token not revoked")
	}
	// Family revocation marks every token in the family. | 家族撤销标记家族内所有令牌。
	if err := store.RevokeRefreshToken(ctx, "rt-3", true); err != nil {
		t.Fatalf("revoke family: %v", err)
	}
	family, _ := store.GetRefreshToken(ctx, "rt-3")
	if family == nil || !family.Revoked {
		t.Fatal("family token not revoked")
	}

	for i, hash := range []string{"subject-a", "subject-b", "subject-c"} {
		if err := store.SaveRefreshToken(ctx, &RefreshToken{
			TokenHash: hash,
			ClientID:  "client-" + string(rune('a'+i%2)),
			Subject:   "user",
		}); err != nil {
			t.Fatalf("save subject token: %v", err)
		}
	}
	// "subject-a" and "subject-c" belong to client-a; only live tokens count. | "subject-a" 与
	// "subject-c" 属于 client-a；只统计未撤销令牌。
	n, err := store.RevokeRefreshTokensForSubject(ctx, "client-a", "user")
	if err != nil || n != 2 {
		t.Fatalf("revoke subject = %d err=%v", n, err)
	}
	n, _ = store.RevokeRefreshTokensForSubject(ctx, "client-a", "user")
	if n != 0 {
		t.Fatalf("second subject revoke = %d", n)
	}
}

func TestMemoryStoreAccessTokens(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	now := time.Unix(1000, 0)

	if err := store.SaveAccessToken(ctx, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil access = %v", err)
	}
	token := &AccessToken{
		TokenHash: "at-1",
		ClientID:  "client",
		Subject:   "user",
		Principal: storeTestPrincipal(),
		Scopes:    []string{"api:read"},
		Audience:  []string{"https://api.example"},
		AMR:       []string{"pwd"},
		ExpiresAt: now.Add(time.Hour),
	}
	if err := store.SaveAccessToken(ctx, token); err != nil {
		t.Fatalf("save access: %v", err)
	}
	token.Scopes[0] = "mutated"
	if err := store.SaveAccessToken(ctx, &AccessToken{TokenHash: "at-1"}); !errors.Is(err, ErrServerError) {
		t.Fatalf("access collision = %v", err)
	}
	if _, err := store.GetAccessToken(ctx, "missing"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("unknown access = %v", err)
	}
	got, err := store.GetAccessToken(ctx, "at-1")
	if err != nil || got.Scopes[0] != "api:read" || got.Principal.Subject != "user-1" {
		t.Fatalf("get access = %+v err=%v", got, err)
	}
	if err := store.RevokeAccessToken(ctx, "missing"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("revoke unknown access = %v", err)
	}
	if err := store.RevokeAccessToken(ctx, "at-1"); err != nil {
		t.Fatalf("revoke access: %v", err)
	}
	got, _ = store.GetAccessToken(ctx, "at-1")
	if got == nil || !got.Revoked {
		t.Fatal("access token not revoked")
	}
}

func TestMemoryStoreDeviceCodes(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	now := time.Unix(1000, 0)

	bad := []*DeviceCode{nil, {}, {DeviceCodeHash: "hash"}, {UserCode: "UC"}}
	for _, code := range bad {
		if err := store.SaveDeviceCode(ctx, code); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("bad device code %+v = %v", code, err)
		}
	}
	code := &DeviceCode{
		DeviceCodeHash: "device-1",
		UserCode:       "ABCD-EFGH",
		ClientID:       "client",
		Scopes:         []string{"openid"},
		Audience:       []string{"https://api.example"},
		Status:         DevicePending,
		Interval:       10 * time.Second,
		ExpiresAt:      now.Add(time.Hour),
	}
	if err := store.SaveDeviceCode(ctx, code); err != nil {
		t.Fatalf("save device: %v", err)
	}
	code.Scopes[0] = "mutated"
	if err := store.SaveDeviceCode(ctx, &DeviceCode{DeviceCodeHash: "device-1", UserCode: "OTHER"}); !errors.Is(err, ErrServerError) {
		t.Fatalf("device collision = %v", err)
	}
	if err := store.SaveDeviceCode(ctx, &DeviceCode{DeviceCodeHash: "device-2", UserCode: "ABCD-EFGH"}); !errors.Is(err, ErrServerError) {
		t.Fatalf("user code collision = %v", err)
	}
	if _, err := store.GetDeviceCodeByUserCode(ctx, "missing"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("unknown user code = %v", err)
	}
	got, err := store.GetDeviceCodeByUserCode(ctx, "ABCD-EFGH")
	if err != nil || got.Scopes[0] != "openid" {
		t.Fatalf("get by user code = %+v err=%v", got, err)
	}
	if _, err := store.GetDeviceCode(ctx, "missing"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("unknown device = %v", err)
	}
	if _, err := store.GetDeviceCode(ctx, "device-1"); err != nil {
		t.Fatalf("get device: %v", err)
	}
	if err := store.UpdateDeviceCode(ctx, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil update = %v", err)
	}
	if err := store.UpdateDeviceCode(ctx, &DeviceCode{DeviceCodeHash: "missing"}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("missing update = %v", err)
	}
	updated := &DeviceCode{DeviceCodeHash: "device-1", UserCode: "ABCD-EFGH", ClientID: "client", Status: DevicePending, ExpiresAt: now.Add(time.Hour)}
	updated.Scopes = []string{"profile"}
	if err := store.UpdateDeviceCode(ctx, updated); err != nil {
		t.Fatalf("update device: %v", err)
	}
	got, _ = store.GetDeviceCode(ctx, "device-1")
	if got.Scopes[0] != "profile" {
		t.Fatalf("update not applied: %+v", got)
	}

	if _, _, err := store.PollDeviceCode(ctx, "missing", "client", now); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("poll missing = %v", err)
	}
	if _, _, err := store.PollDeviceCode(ctx, "device-1", "other", now); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("poll wrong client = %v", err)
	}
	polled, accepted, err := store.PollDeviceCode(ctx, "device-1", "client", now)
	if err != nil || !accepted || polled.Status != DevicePending {
		t.Fatalf("first poll = %+v accepted=%v err=%v", polled, accepted, err)
	}
	polled, accepted, err = store.PollDeviceCode(ctx, "device-1", "client", now.Add(time.Second))
	if err != nil || accepted || polled.Interval != 10*time.Second {
		t.Fatalf("slow poll = %+v accepted=%v err=%v", polled, accepted, err)
	}
	polled, accepted, err = store.PollDeviceCode(ctx, "device-1", "client", now.Add(16*time.Second))
	if err != nil || !accepted {
		t.Fatalf("poll after interval = %+v accepted=%v err=%v", polled, accepted, err)
	}

	// Approved grants transition to used exactly once. | 已批准许可恰好转为已用一次。
	approved := &DeviceCode{DeviceCodeHash: "device-2", UserCode: "IJKL-MNOP", ClientID: "client", Status: DeviceApproved, Interval: time.Second, ExpiresAt: now.Add(time.Hour)}
	if err := store.SaveDeviceCode(ctx, approved); err != nil {
		t.Fatalf("save approved: %v", err)
	}
	polled, accepted, err = store.PollDeviceCode(ctx, "device-2", "client", now)
	if err != nil || !accepted || polled.Status != DeviceApproved {
		t.Fatalf("approved poll = %+v accepted=%v err=%v", polled, accepted, err)
	}
	stored, _ := store.GetDeviceCode(ctx, "device-2")
	if stored.Status != DeviceUsed {
		t.Fatalf("approved grant status = %q", stored.Status)
	}
	polled, accepted, _ = store.PollDeviceCode(ctx, "device-2", "client", now)
	if !accepted || polled.Status != DeviceUsed {
		t.Fatalf("used poll = %+v accepted=%v", polled, accepted)
	}
	denied := &DeviceCode{DeviceCodeHash: "device-3", UserCode: "QRST-UVWX", ClientID: "client", Status: DeviceDenied, ExpiresAt: now.Add(time.Hour)}
	if err := store.SaveDeviceCode(ctx, denied); err != nil {
		t.Fatalf("save denied: %v", err)
	}
	polled, accepted, _ = store.PollDeviceCode(ctx, "device-3", "client", now)
	if !accepted || polled.Status != DeviceDenied {
		t.Fatalf("denied poll = %+v accepted=%v", polled, accepted)
	}
	expired := &DeviceCode{DeviceCodeHash: "device-4", UserCode: "YZAB-CDEF", ClientID: "client", Status: DevicePending, ExpiresAt: now}
	if err := store.SaveDeviceCode(ctx, expired); err != nil {
		t.Fatalf("save expired device: %v", err)
	}
	polled, accepted, _ = store.PollDeviceCode(ctx, "device-4", "client", now)
	if accepted || polled.Status != DeviceExpired {
		t.Fatalf("expired poll = %+v accepted=%v", polled, accepted)
	}
}

func TestMemoryStoreDeviceStatus(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	now := time.Unix(1000, 0)
	device := &DeviceCode{
		DeviceCodeHash: "device-1",
		UserCode:       "ABCD-EFGH",
		ClientID:       "client",
		Status:         DevicePending,
		ExpiresAt:      now.Add(time.Hour),
	}
	if err := store.SaveDeviceCode(ctx, device); err != nil {
		t.Fatalf("save device: %v", err)
	}
	if _, err := store.SetDeviceCodeStatus(ctx, "ABCD-EFGH", DevicePending, now, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unsupported status = %v", err)
	}
	if _, err := store.SetDeviceCodeStatus(ctx, "ABCD-EFGH", DeviceApproved, now, nil); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("approval without principal = %v", err)
	}
	if _, err := store.SetDeviceCodeStatus(ctx, "MISSING", DeviceApproved, now, storeTestPrincipal()); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("unknown user code = %v", err)
	}
	principal := storeTestPrincipal()
	approved, err := store.SetDeviceCodeStatus(ctx, "ABCD-EFGH", DeviceApproved, now, principal)
	if err != nil || approved.Status != DeviceApproved ||
		approved.Subject != "user-1" || approved.UserID != "user-1" ||
		approved.Principal == nil || approved.Principal.Subject != "user-1" ||
		approved.DPoPJKT != "thumb" {
		t.Fatalf("approve = %+v err=%v", approved, err)
	}
	if _, err := store.SetDeviceCodeStatus(ctx, "ABCD-EFGH", DeviceDenied, now, principal); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("re-approve = %v", err)
	}

	expired := &DeviceCode{DeviceCodeHash: "device-2", UserCode: "IJKL-MNOP", ClientID: "client", Status: DevicePending, ExpiresAt: now}
	if err := store.SaveDeviceCode(ctx, expired); err != nil {
		t.Fatalf("save expired: %v", err)
	}
	if _, err := store.SetDeviceCodeStatus(ctx, "IJKL-MNOP", DeviceDenied, now, nil); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expired status = %v", err)
	}
	// Denial needs no principal. | 拒绝无需主体。
	denied := &DeviceCode{DeviceCodeHash: "device-3", UserCode: "QRST-UVWX", ClientID: "client", Status: DevicePending, ExpiresAt: now.Add(time.Hour)}
	if err := store.SaveDeviceCode(ctx, denied); err != nil {
		t.Fatalf("save denied candidate: %v", err)
	}
	result, err := store.SetDeviceCodeStatus(ctx, "QRST-UVWX", DeviceDenied, now, nil)
	if err != nil || result.Status != DeviceDenied {
		t.Fatalf("deny = %+v err=%v", result, err)
	}
}

func TestMemoryStorePAR(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	now := time.Unix(1000, 0)

	if err := store.SavePAR(ctx, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil PAR = %v", err)
	}
	request := &PARRequest{
		RequestURI: "urn:ietf:params:oauth:request_uri:abc",
		ClientID:   "client",
		Params:     url.Values{"scope": {"openid"}},
		ExpiresAt:  now.Add(time.Minute),
	}
	if err := store.SavePAR(ctx, request); err != nil {
		t.Fatalf("save PAR: %v", err)
	}
	request.Params.Set("scope", "mutated")
	if err := store.SavePAR(ctx, &PARRequest{RequestURI: request.RequestURI}); !errors.Is(err, ErrServerError) {
		t.Fatalf("PAR collision = %v", err)
	}
	if _, err := store.ConsumePAR(ctx, "missing", now); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unknown PAR = %v", err)
	}
	got, err := store.ConsumePAR(ctx, request.RequestURI, now)
	if err != nil || got.Params.Get("scope") != "openid" || got.ClientID != "client" {
		t.Fatalf("consume PAR = %+v err=%v", got, err)
	}
	if _, err := store.ConsumePAR(ctx, request.RequestURI, now); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("used PAR = %v", err)
	}
	expired := &PARRequest{RequestURI: "urn:expired", ClientID: "client", ExpiresAt: now}
	if err := store.SavePAR(ctx, expired); err != nil {
		t.Fatalf("save expired PAR: %v", err)
	}
	if _, err := store.ConsumePAR(ctx, "urn:expired", now); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expired PAR = %v", err)
	}
}

func TestMemoryStoreCleanup(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	now := time.Unix(1000, 0)
	past := now.Add(-time.Minute)
	future := now.Add(time.Hour)

	if err := store.SaveAuthorizationCode(ctx, &AuthorizationCode{CodeHash: "expired-code", ExpiresAt: past}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAuthorizationCode(ctx, &AuthorizationCode{CodeHash: "live-code", ExpiresAt: future}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAuthorizationCode(ctx, &AuthorizationCode{CodeHash: "forever-code"}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRefreshToken(ctx, &RefreshToken{TokenHash: "expired-refresh", ExpiresAt: past}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRefreshToken(ctx, &RefreshToken{TokenHash: "live-refresh", ExpiresAt: future}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAccessToken(ctx, &AccessToken{TokenHash: "expired-access", ExpiresAt: past}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAccessToken(ctx, &AccessToken{TokenHash: "live-access", ExpiresAt: future}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveDeviceCode(ctx, &DeviceCode{DeviceCodeHash: "expired-device", UserCode: "EXPIRED", ExpiresAt: past}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveDeviceCode(ctx, &DeviceCode{DeviceCodeHash: "live-device", UserCode: "LIVE", ExpiresAt: future}); err != nil {
		t.Fatal(err)
	}
	if err := store.SavePAR(ctx, &PARRequest{RequestURI: "expired-par", ExpiresAt: past}); err != nil {
		t.Fatal(err)
	}
	if err := store.SavePAR(ctx, &PARRequest{RequestURI: "live-par", ExpiresAt: future}); err != nil {
		t.Fatal(err)
	}
	if err := store.Cleanup(ctx, now); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := store.ConsumeAuthorizationCode(ctx, "expired-code", now); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expired code survived: %v", err)
	}
	if _, err := store.ConsumeAuthorizationCode(ctx, "live-code", now); err != nil {
		t.Fatalf("live code removed: %v", err)
	}
	if _, err := store.GetRefreshToken(ctx, "expired-refresh"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expired refresh survived: %v", err)
	}
	if _, err := store.GetAccessToken(ctx, "expired-access"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expired access survived: %v", err)
	}
	if _, err := store.GetDeviceCodeByUserCode(ctx, "EXPIRED"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expired user code survived: %v", err)
	}
	if _, err := store.GetDeviceCodeByUserCode(ctx, "LIVE"); err != nil {
		t.Fatalf("live user code removed: %v", err)
	}
	if _, err := store.ConsumePAR(ctx, "expired-par", now); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expired PAR survived: %v", err)
	}
	if _, err := store.ConsumePAR(ctx, "live-par", now); err != nil {
		t.Fatalf("live PAR removed: %v", err)
	}
}

func TestMemoryClientStore(t *testing.T) {
	ctx := context.Background()
	client := &Client{
		ID:                     "client-1",
		RedirectURIs:           []string{"https://rp.example/cb"},
		GrantTypes:             []string{GrantAuthorizationCode},
		ResponseTypes:          []string{ResponseCode},
		Scopes:                 []string{"openid"},
		TLSClientAuthSANs:      []string{"rp.example"},
		JWKS:                   []byte("{}"),
		PostLogoutRedirectURIs: []string{"https://rp.example/logout"},
		Contacts:               []string{"admin@rp.example"},
		Metadata:               map[string]string{"owner": "team"},
	}
	store := NewMemoryClientStore(nil, &Client{}, client)
	client.Scopes[0] = "mutated"
	client.Metadata["owner"] = "mutated"

	if err := store.CreateClient(ctx, nil); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("nil create = %v", err)
	}
	if err := store.CreateClient(ctx, &Client{}); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("empty create = %v", err)
	}
	if err := store.CreateClient(ctx, &Client{ID: "client-1"}); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("duplicate create = %v", err)
	}
	if _, err := store.GetClient(ctx, "missing"); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("unknown get = %v", err)
	}
	got, err := store.GetClient(ctx, "client-1")
	if err != nil || got.Scopes[0] != "openid" || got.Metadata["owner"] != "team" {
		t.Fatalf("get client = %+v err=%v", got, err)
	}
	got.Scopes[0] = "changed"
	got.Metadata["owner"] = "changed"
	again, _ := store.GetClient(ctx, "client-1")
	if again.Scopes[0] != "openid" || again.Metadata["owner"] != "team" {
		t.Fatal("client store leaked a mutable reference")
	}
	if err := store.CreateClient(ctx, &Client{ID: "client-2"}); err != nil {
		t.Fatalf("create client-2: %v", err)
	}
	if err := store.UpdateClient(ctx, nil); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("nil update = %v", err)
	}
	if err := store.UpdateClient(ctx, &Client{ID: "missing"}); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("unknown update = %v", err)
	}
	if err := store.UpdateClient(ctx, &Client{ID: "client-2", RedirectURIs: []string{"https://new.example/cb"}}); err != nil {
		t.Fatalf("update client: %v", err)
	}
	updated, _ := store.GetClient(ctx, "client-2")
	if len(updated.RedirectURIs) != 1 || updated.RedirectURIs[0] != "https://new.example/cb" {
		t.Fatalf("update not applied: %+v", updated)
	}
	listed, err := store.ListClients(ctx)
	if err != nil || len(listed) != 2 || listed[0].ID != "client-1" || listed[1].ID != "client-2" {
		t.Fatalf("list clients = %+v err=%v", listed, err)
	}
	if err := store.DeleteClient(ctx, "missing"); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("unknown delete = %v", err)
	}
	if err := store.DeleteClient(ctx, "client-2"); err != nil {
		t.Fatalf("delete client: %v", err)
	}
	if _, err := store.GetClient(ctx, "client-2"); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("deleted client still present: %v", err)
	}
}
