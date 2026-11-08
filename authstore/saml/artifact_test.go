package saml_test

import (
	"errors"
	"testing"
	"time"

	samlapi "github.com/shibingli/ydx/auth/protocol/saml"
)

// TestArtifactLifecycle covers cross-instance save, single consumption, replay and the
// endpoint-index-free lookup key. | TestArtifactLifecycle 覆盖跨实例保存、单次消费、重放以及不含
// 端点索引的查找键。
func TestArtifactLifecycle(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.January, 15, 0, 0, 0)
	expires := base.Add(time.Hour)
	artifact := sampleArtifact(1, 0)
	record := sampleRecord(artifact, "payload", base, expires)
	if err := first.SaveArtifact(testContext, record, base); err != nil {
		t.Fatalf("save artifact: %v | 保存工件失败", err)
	}
	// Mutating the caller record after the save must not change the stored bytes.
	record.Message = []byte("mutated")
	record.SPEntityID = "mutated"
	duplicate := sampleRecord(sampleArtifact(1, 7), "other", base, expires)
	if err := second.SaveArtifact(testContext, duplicate, base); !errors.Is(err, samlapi.ErrReplay) {
		t.Fatalf("duplicate artifact error = %v, want ErrReplay | 重复工件错误不符", err)
	}
	// The endpoint index is not part of the lookup key, so another index still resolves it.
	taken, err := second.TakeArtifact(testContext, sampleArtifact(1, 9), base)
	if err != nil {
		t.Fatalf("take artifact: %v | 消费工件失败", err)
	}
	if !taken.Used {
		t.Fatal("taken artifact is not marked used | 已消费工件未标记已用")
	}
	if string(taken.Message) != "payload" {
		t.Fatalf("message = %q, want payload | 消息内容不符", taken.Message)
	}
	if taken.SPEntityID != "https://sp.example.com/saml/metadata" {
		t.Fatalf("stored artifact was not a deep copy: %q | 存储工件不是深拷贝", taken.SPEntityID)
	}
	if _, err := first.TakeArtifact(testContext, artifact, base); !errors.Is(err, samlapi.ErrReplay) {
		t.Fatalf("second take error = %v, want ErrReplay | 二次消费错误不符", err)
	}
	if _, err := second.TakeArtifact(testContext, sampleArtifact(2, 0), base); !errors.Is(err, samlapi.ErrArtifactInvalid) {
		t.Fatalf("unknown artifact error = %v, want ErrArtifactInvalid | 未知工件错误不符", err)
	}
	other := sampleArtifact(2, 0)
	if err := second.SaveArtifact(testContext, sampleRecord(other, "second", base, expires), base); err != nil {
		t.Fatalf("save second artifact: %v | 保存第二个工件失败", err)
	}
	secondTaken, err := first.TakeArtifact(testContext, other, base)
	if err != nil {
		t.Fatalf("take second artifact: %v | 消费第二个工件失败", err)
	}
	if string(secondTaken.Message) != "second" {
		t.Fatalf("second artifact message = %q | 第二个工件内容不符", secondTaken.Message)
	}
}

// TestArtifactValidation covers nil, empty, wrong-type and already-expired records.
// | TestArtifactValidation 覆盖空记录、空消息、错误类型与已过期记录。
func TestArtifactValidation(t *testing.T) {
	stores := newStore(t, "")
	base := testTime(2026, time.February, 15, 0, 0, 0)
	expires := base.Add(time.Hour)
	artifact := sampleArtifact(1, 0)
	if err := stores.SaveArtifact(testContext, nil, base); !errors.Is(err, samlapi.ErrArtifactInvalid) {
		t.Fatalf("nil record error = %v, want ErrArtifactInvalid | 空记录错误不符", err)
	}
	if err := stores.SaveArtifact(testContext, sampleRecord(artifact, "", base, expires), base); !errors.Is(err, samlapi.ErrArtifactInvalid) {
		t.Fatalf("empty message error = %v, want ErrArtifactInvalid | 空消息错误不符", err)
	}
	wrongType := sampleRecord(artifact, "payload", base, expires)
	wrongType.Artifact.Type = 0x0002
	if err := stores.SaveArtifact(testContext, wrongType, base); !errors.Is(err, samlapi.ErrArtifactInvalid) {
		t.Fatalf("wrong type error = %v, want ErrArtifactInvalid | 错误类型错误不符", err)
	}
	if err := stores.SaveArtifact(testContext, sampleRecord(artifact, "payload", base, base), base); !errors.Is(err, samlapi.ErrResponseExpired) {
		t.Fatalf("expired input error = %v, want ErrResponseExpired | 过期输入错误不符", err)
	}
	if _, err := stores.TakeArtifact(testContext, artifact, base); !errors.Is(err, samlapi.ErrArtifactInvalid) {
		t.Fatalf("take after rejected saves error = %v, want ErrArtifactInvalid | 被拒保存后不应存在工件", err)
	}
}

// TestArtifactExpiry covers expiry on take, deletion on discovery, replacement of an expired
// record and cleanup of stale records. | TestArtifactExpiry 覆盖消费时过期、发现即删除、过期记录替换
// 与陈旧记录清理。
func TestArtifactExpiry(t *testing.T) {
	stores := newStore(t, "")
	base := testTime(2026, time.March, 15, 0, 0, 0)
	expires := base.Add(time.Hour)
	first := sampleArtifact(1, 0)
	if err := stores.SaveArtifact(testContext, sampleRecord(first, "first", base, expires), base); err != nil {
		t.Fatalf("save first artifact: %v | 保存第一个工件失败", err)
	}
	if _, err := stores.TakeArtifact(testContext, first, expires); !errors.Is(err, samlapi.ErrResponseExpired) {
		t.Fatalf("take at expiry error = %v, want ErrResponseExpired | 到期消费错误不符", err)
	}
	if _, err := stores.TakeArtifact(testContext, first, base); !errors.Is(err, samlapi.ErrArtifactInvalid) {
		t.Fatalf("take after expiry deletion error = %v, want ErrArtifactInvalid | 过期记录未删除", err)
	}

	second := sampleArtifact(2, 0)
	if err := stores.SaveArtifact(testContext, sampleRecord(second, "stale", base, expires), base); err != nil {
		t.Fatalf("save second artifact: %v | 保存第二个工件失败", err)
	}
	replacement := sampleRecord(second, "replacement", expires, expires.Add(time.Hour))
	if err := stores.SaveArtifact(testContext, replacement, expires); err != nil {
		t.Fatalf("replace expired artifact: %v | 替换过期工件失败", err)
	}
	taken, err := stores.TakeArtifact(testContext, second, expires)
	if err != nil {
		t.Fatalf("take replacement: %v | 消费替换工件失败", err)
	}
	if string(taken.Message) != "replacement" || !taken.Used {
		t.Fatalf("replacement = %q, used=%v | 替换工件内容不符", taken.Message, taken.Used)
	}

	stale := sampleArtifact(3, 0)
	if err := stores.SaveArtifact(testContext, sampleRecord(stale, "stale", base, expires), base); err != nil {
		t.Fatalf("save stale artifact: %v | 保存陈旧工件失败", err)
	}
	if err := stores.Cleanup(testContext, expires); err != nil {
		t.Fatalf("cleanup: %v | 清理失败", err)
	}
	if _, err := stores.TakeArtifact(testContext, stale, expires); !errors.Is(err, samlapi.ErrArtifactInvalid) {
		t.Fatalf("take after cleanup error = %v, want ErrArtifactInvalid | 清理后工件仍存在", err)
	}
}

// TestArtifactZeroExpiry verifies that an artifact without expiry is never cleaned up.
// | TestArtifactZeroExpiry 验证无到期时间的工件永不清理。
func TestArtifactZeroExpiry(t *testing.T) {
	stores := newStore(t, "")
	base := testTime(2026, time.April, 15, 0, 0, 0)
	artifact := sampleArtifact(1, 0)
	if err := stores.SaveArtifact(testContext, sampleRecord(artifact, "eternal", base, time.Time{}), base); err != nil {
		t.Fatalf("save artifact: %v | 保存工件失败", err)
	}
	later := base.Add(10000 * time.Hour)
	if err := stores.Cleanup(testContext, later); err != nil {
		t.Fatalf("cleanup: %v | 清理失败", err)
	}
	taken, err := stores.TakeArtifact(testContext, artifact, later)
	if err != nil {
		t.Fatalf("take zero-expiry artifact: %v | 消费零期限工件失败", err)
	}
	if string(taken.Message) != "eternal" {
		t.Fatalf("zero-expiry artifact message = %q | 零期限工件内容不符", taken.Message)
	}
}

// TestArtifactDueAtBoundarySecond verifies callback-free cleanup of an artifact expiring during the
// boundary second. | TestArtifactDueAtBoundarySecond 验证恰在边界秒到期的工件会被清理。
func TestArtifactDueAtBoundarySecond(t *testing.T) {
	stores := newStore(t, "")
	base := testTime(2026, time.May, 15, 0, 0, 0)
	artifact := sampleArtifact(1, 0)
	if err := stores.SaveArtifact(testContext, sampleRecord(artifact, "boundary", base.Add(-time.Hour), base), base.Add(-time.Hour)); err != nil {
		t.Fatalf("save artifact: %v | 保存工件失败", err)
	}
	if err := stores.Cleanup(testContext, base); err != nil {
		t.Fatalf("cleanup: %v | 清理失败", err)
	}
	if _, err := stores.TakeArtifact(testContext, artifact, base); !errors.Is(err, samlapi.ErrArtifactInvalid) {
		t.Fatalf("boundary artifact error = %v, want ErrArtifactInvalid | 边界工件未删除", err)
	}
}
