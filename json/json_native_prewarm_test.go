//go:build !jsonx_std

package json

import (
	"reflect"
	"testing"
	"time"
)

type prewarmAddress struct {
	City string `json:"city"`
	Zip  int    `json:"zip"`
}

type prewarmProfile struct {
	Name      string            `json:"name"`
	Address   prewarmAddress    `json:"address"`
	Addresses []prewarmAddress  `json:"addresses"`
	Meta      map[string]string `json:"meta"`
}

// TestPrewarmInstallsPlans verifies that Prewarm compiles the encoder and decoder plans for the
// sample's type and for every type reachable from its fields, so the first real call finds them
// in the caches instead of paying plan construction. |
// TestPrewarmInstallsPlans 验证 Prewarm 会为样本类型及其字段可达的所有类型编译编解码计划，
// 使首次真实调用直接命中缓存，而不必承担计划构建成本。
func TestPrewarmInstallsPlans(t *testing.T) {
	profile := reflect.TypeOf(prewarmProfile{})
	address := reflect.TypeOf(prewarmAddress{})
	addresses := reflect.TypeOf([]prewarmAddress{})
	meta := reflect.TypeOf(map[string]string{})

	Prewarm(prewarmProfile{}, (*prewarmProfile)(nil))
	Prewarm(prewarmProfile{}, (*prewarmProfile)(nil))

	for _, typ := range []reflect.Type{profile, address, addresses, meta} {
		if _, ok := encodeCache.Load(typ); !ok {
			t.Errorf("encoder plan for %s was not installed | 未安装 %s 的编码计划", typ, typ)
		}
		if _, ok := decodeCache.Load(typ); !ok {
			t.Errorf("decoder plan for %s was not installed | 未安装 %s 的解码计划", typ, typ)
		}
	}
	// A struct containing a map has no all-fast direct-memory plan; the nested scalar-only
	// struct does, and Prewarm must install it. | 含映射的结构体没有全快速的按内存计划；仅含
	// 标量的嵌套结构体有，Prewarm 必须安装它。
	if _, ok := fastStructCache.Load(address); !ok {
		t.Errorf("fast struct encoder for %s was not installed | 未安装 %s 的快速结构体编码器", address, address)
	}
	if _, ok := fastStructDecCache.Load(address); !ok {
		t.Errorf("fast struct decoder for %s was not installed | 未安装 %s 的快速结构体解码器", address, address)
	}
}

// TestPrewarmIgnoresNil verifies that nil and scalar samples are accepted. |
// TestPrewarmIgnoresNil 验证 nil 与标量样本可被接受。
func TestPrewarmIgnoresNil(t *testing.T) {
	Prewarm(nil)
	Prewarm(42, "text", true, 3.5)
}

type prewarmNode struct {
	Name string       `json:"name"`
	Next *prewarmNode `json:"next"`
}

type prewarmTime struct {
	At time.Time `json:"at"`
}

// TestPrewarmRecursiveAndCustom verifies that recursive types terminate and types with their own
// codec methods are warmed without walking into their fields. |
// TestPrewarmRecursiveAndCustom 验证递归类型能够终止，并且自带编解码方法的类型只预热自身方法而
// 不遍历其字段。
func TestPrewarmRecursiveAndCustom(t *testing.T) {
	Prewarm(prewarmNode{}, (*prewarmNode)(nil))
	Prewarm(prewarmTime{}, (*prewarmTime)(nil))

	node := reflect.TypeOf(prewarmNode{})
	if _, ok := encodeCache.Load(node); !ok {
		t.Fatalf("recursive encoder plan was not installed | 未安装递归类型编码计划")
	}
	if _, ok := decodeCache.Load(node); !ok {
		t.Fatalf("recursive decoder plan was not installed | 未安装递归类型解码计划")
	}
	// time.Time encodes through its Marshaler method; its unexported fields must not be walked
	// into a plan. | time.Time 通过 Marshaler 方法编码，其未导出字段不应被构建计划。
	at := reflect.TypeOf(prewarmTime{}).Field(0).Type
	if _, ok := encodeCache.Load(at); !ok {
		t.Fatalf("custom-marshaler encoder plan was not installed | 未安装自定义编码方法的计划")
	}
}
