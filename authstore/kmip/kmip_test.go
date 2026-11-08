package kmip

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	kmipcore "github.com/shibingli/ydx/auth/keymgmt/kmip"
)

// testEnv bundles one miniredis server with two independent clients that act as two application
// instances. | testEnv 把一个 miniredis 服务器与两个独立客户端打包在一起，模拟两个应用实例。
type testEnv struct {
	// mr is the shared miniredis server. | mr 是共享的 miniredis 服务器。
	mr *miniredis.Miniredis
	// clientA is the first client. | clientA 是第一个客户端。
	clientA *goredis.Client
	// clientB is the second client. | clientB 是第二个客户端。
	clientB *goredis.Client
	// storeA is the store backed by clientA. | storeA 是由 clientA 支持的存储。
	storeA *Store
	// storeB is the store backed by clientB. | storeB 是由 clientB 支持的存储。
	storeB *Store
}

// newTestServer starts a miniredis server owned by the test. | newTestServer 启动由测试拥有的 miniredis 服务器。
func newTestServer(t *testing.T) *miniredis.Miniredis {
	t.Helper()
	server := miniredis.RunT(t)
	return server
}

// newTestClient opens a go-redis client against server and closes it at test cleanup; retries are
// disabled so backend-failure tests fail fast. | newTestClient 打开指向 server 的 go-redis 客户端并在
// 测试清理时关闭；重试被禁用，使后端故障测试快速失败。
func newTestClient(t *testing.T, server *miniredis.Miniredis) *goredis.Client {
	t.Helper()
	client := goredis.NewClient(&goredis.Options{
		Addr:       server.Addr(),
		MaxRetries: -1,
	})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// newTestEnv returns two stores that share one Redis deployment. | newTestEnv 返回共享同一 Redis
// 部署的两个存储。
func newTestEnv(t *testing.T, prefix string) *testEnv {
	t.Helper()
	server := newTestServer(t)
	clientA := newTestClient(t, server)
	clientB := newTestClient(t, server)
	storeA, err := New(clientA, Options{KeyPrefix: prefix})
	if err != nil {
		t.Fatalf("New store A: %v", err)
	}
	storeB, err := New(clientB, Options{KeyPrefix: prefix})
	if err != nil {
		t.Fatalf("New store B: %v", err)
	}
	return &testEnv{mr: server, clientA: clientA, clientB: clientB, storeA: storeA, storeB: storeB}
}

// testRecord builds a fully populated record whose times use a non-UTC fixed zone so tests can
// verify UTC normalization. | testRecord 构造字段完整的记录，其时间使用非 UTC 固定时区，以便
// 测试验证 UTC 规范化。
func testRecord(uniqueIdentifier string) kmipcore.ObjectRecord {
	base := time.Date(2026, time.November, 8, 10, 30, 45, 123456789, time.FixedZone("CST", 8*60*60))
	return kmipcore.ObjectRecord{
		UniqueIdentifier: uniqueIdentifier,
		ObjectType:       kmipcore.ObjectTypeSymmetricKey,
		Object: &kmipcore.Object{
			Type: kmipcore.ObjectTypeSymmetricKey,
			SymmetricKey: &kmipcore.SymmetricKeyObject{
				KeyBlock: kmipcore.KeyBlock{
					Format: kmipcore.KeyFormatRaw,
					Value: kmipcore.KeyValue{
						Material: kmipcore.NewByteString(kmipcore.TagKeyMaterial, []byte("0123456789abcdef")),
						Attributes: kmipcore.AttributeList{
							kmipcore.NewEnumerationAttribute(kmipcore.AttributeCryptographicAlgorithm, uint32(kmipcore.AlgorithmAES)),
						},
					},
					Algorithm: kmipcore.AlgorithmAES,
					Length:    128,
				},
			},
		},
		State: kmipcore.StatePreActive,
		Names: []kmipcore.Name{
			kmipcore.NewName("alpha"),
			{Value: "https://example.test/key", Type: kmipcore.NameTypeURI},
		},
		ObjectGroups: []string{"group-a", "group-b"},
		Attributes: kmipcore.AttributeList{
			kmipcore.NewTextAttribute("x-custom", "custom-value"),
			{
				Name: kmipcore.AttributeApplicationSpecificInformation,
				Value: kmipcore.NewStructure(kmipcore.TagApplicationSpecificInformation,
					kmipcore.NewTextString(kmipcore.TagApplicationNamespace, "demo"),
					kmipcore.NewByteString(kmipcore.TagApplicationData, []byte{0x01, 0x02, 0x03, 0x04}),
				),
			},
		},
		Owner:                    "owner-1",
		UsageMask:                kmipcore.UsageMaskEncrypt | kmipcore.UsageMaskDecrypt,
		Sensitive:                true,
		Extractable:              true,
		Fresh:                    false,
		InitialDate:              base,
		OriginalCreationDate:     base.Add(-24 * time.Hour),
		ActivationDate:           base.Add(time.Hour),
		DeactivationDate:         time.Time{},
		CompromiseDate:           time.Time{},
		CompromiseOccurrenceDate: time.Time{},
		DestroyDate:              time.Time{},
		ArchiveDate:              time.Time{},
		LastChangeDate:           base.Add(2 * time.Hour),
		RevocationReason: kmipcore.RevocationReason{
			Code:    kmipcore.RevocationKeyCompromise,
			Message: "test revocation reason",
		},
	}
}

// normalizedRecord returns record with every non-zero time in UTC. | normalizedRecord 返回所有非零
// 时间均为 UTC 的记录。
func normalizedRecord(record kmipcore.ObjectRecord) kmipcore.ObjectRecord {
	normalizeRecordTimes(&record)
	return record
}

// requireRecordEqual fails unless want and got are deeply equal after UTC normalization.
// | requireRecordEqual 在 want 与 got 经 UTC 规范化后不深度相等时失败。
func requireRecordEqual(t *testing.T, want, got kmipcore.ObjectRecord) {
	t.Helper()
	want = normalizedRecord(want)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("record mismatch\nwant: %#v\ngot:  %#v", want, got)
	}
}

// requireErrorIs fails unless err matches target. | requireErrorIs 在 err 不匹配 target 时失败。
func requireErrorIs(t *testing.T, err, target error, context string) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("%s: got %v, want errors.Is(_, %v)", context, err, target)
	}
}

// TestNewRejectsInvalidConfig verifies client and prefix validation. | TestNewRejectsInvalidConfig
// 验证客户端与前缀校验。
func TestNewRejectsInvalidConfig(t *testing.T) {
	server := newTestServer(t)
	client := newTestClient(t, server)
	if _, err := New(nil, Options{}); err == nil {
		t.Fatal("New(nil) accepted a nil client")
	} else {
		requireErrorIs(t, err, kmipcore.ErrInvalidRequest, "New(nil)")
	}
	for _, prefix := range []string{"{", "}", "a{b}", "a}b"} {
		if _, err := New(client, Options{KeyPrefix: prefix}); err == nil {
			t.Fatalf("New accepted prefix %q", prefix)
		} else {
			requireErrorIs(t, err, kmipcore.ErrInvalidRequest, "New(prefix "+prefix+")")
		}
	}
	for _, prefix := range []string{"", "myapp:kmip:", "ydx:custom:"} {
		if _, err := New(client, Options{KeyPrefix: prefix}); err != nil {
			t.Fatalf("New rejected valid prefix %q: %v", prefix, err)
		}
	}
}

// TestNilStoreFailsClosed verifies that a nil receiver returns an error instead of panicking.
// | TestNilStoreFailsClosed 验证 nil 接收者返回错误而不是 panic。
func TestNilStoreFailsClosed(t *testing.T) {
	var store *Store
	requireErrorIs(t, store.Create(context.Background(), testRecord("x")), kmipcore.ErrInvalidRequest, "nil Create")
	_, err := store.Get(context.Background(), "x")
	requireErrorIs(t, err, kmipcore.ErrInvalidRequest, "nil Get")
	requireErrorIs(t, store.Update(context.Background(), testRecord("x")), kmipcore.ErrInvalidRequest, "nil Update")
	requireErrorIs(t, store.Delete(context.Background(), "x"), kmipcore.ErrInvalidRequest, "nil Delete")
	list, err := store.List(context.Background())
	if list != nil {
		t.Fatalf("nil List returned records: %v", list)
	}
	requireErrorIs(t, err, kmipcore.ErrInvalidRequest, "nil List")
	requireErrorIs(t, store.Reset(context.Background()), kmipcore.ErrInvalidRequest, "nil Reset")
}

// TestContextErrors verifies that a pre-canceled or expired context is returned unchanged by every
// method. | TestContextErrors 验证每个方法原样返回已取消或已超时的上下文错误。
func TestContextErrors(t *testing.T) {
	env := newTestEnv(t, "")
	record := testRecord("ctx-object")
	if err := env.storeA.Create(context.Background(), record); err != nil {
		t.Fatalf("Create: %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()

	methods := []struct {
		name string
		call func(ctx context.Context) error
	}{
		{"Create", func(ctx context.Context) error { return env.storeA.Create(ctx, testRecord("ctx-new")) }},
		{"Get", func(ctx context.Context) error { _, err := env.storeA.Get(ctx, "ctx-object"); return err }},
		{"Update", func(ctx context.Context) error { return env.storeA.Update(ctx, record) }},
		{"Delete", func(ctx context.Context) error { return env.storeA.Delete(ctx, "ctx-object") }},
		{"List", func(ctx context.Context) error { _, err := env.storeA.List(ctx); return err }},
		{"Reset", func(ctx context.Context) error { return env.storeA.Reset(ctx) }},
	}
	for _, method := range methods {
		if err := method.call(canceled); !errors.Is(err, context.Canceled) {
			t.Fatalf("%s with canceled context: got %v, want context.Canceled", method.name, err)
		}
		if err := method.call(expired); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("%s with expired context: got %v, want context.DeadlineExceeded", method.name, err)
		}
	}
}

// TestBackendFailuresAreSanitized verifies that a closed backend maps to ErrStoreUnavailable and
// that the error text leaks neither the server address nor key material.
// | TestBackendFailuresAreSanitized 验证关闭的后端映射为 ErrStoreUnavailable，且错误文本既不泄露
// 服务器地址也不泄露密钥材料。
func TestBackendFailuresAreSanitized(t *testing.T) {
	env := newTestEnv(t, "")
	secret := []byte("SUPER-SECRET-KEY-MATERIAL")
	record := testRecord("backend-object")
	record.Object.SymmetricKey.KeyBlock.Value.Material = kmipcore.NewByteString(kmipcore.TagKeyMaterial, secret)
	if err := env.storeA.Create(context.Background(), record); err != nil {
		t.Fatalf("Create: %v", err)
	}
	address := env.mr.Addr()
	env.mr.Close()

	calls := []struct {
		name string
		call func() error
	}{
		{"Create", func() error { return env.storeB.Create(context.Background(), testRecord("backend-new")) }},
		{"Get", func() error { _, err := env.storeB.Get(context.Background(), "backend-object"); return err }},
		{"Update", func() error { return env.storeB.Update(context.Background(), record) }},
		{"Delete", func() error { return env.storeB.Delete(context.Background(), "backend-object") }},
		{"List", func() error { _, err := env.storeB.List(context.Background()); return err }},
		{"Reset", func() error { return env.storeB.Reset(context.Background()) }},
	}
	for _, item := range calls {
		err := item.call()
		requireErrorIs(t, err, ErrStoreUnavailable, item.name)
		text := err.Error()
		if strings.Contains(text, address) {
			t.Fatalf("%s leaked the server address: %q", item.name, text)
		}
		if strings.Contains(text, string(secret)) {
			t.Fatalf("%s leaked key material: %q", item.name, text)
		}
	}
}
