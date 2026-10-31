package waf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/shibingli/ydx/log"
)

// appendU32 appends a LEB128 unsigned integer. | appendU32 追加一个 LEB128 无符号整数。
func appendU32(dst []byte, value uint32) []byte {
	for {
		b := byte(value & 0x7f)
		value >>= 7
		if value != 0 {
			b |= 0x80
		}
		dst = append(dst, b)
		if value == 0 {
			return dst
		}
	}
}

// wasmSection wraps section content. | wasmSection 包装段内容。
func wasmSection(id byte, content []byte) []byte {
	out := []byte{id}
	out = appendU32(out, uint32(len(content)))
	return append(out, content...)
}

// wasmVec encodes a vector of byte slices. | wasmVec 编码字节切片向量。
func wasmVec(items ...[]byte) []byte {
	out := appendU32(nil, uint32(len(items)))
	for _, item := range items {
		out = append(out, item...)
	}
	return out
}

// wasmName encodes a length-prefixed name. | wasmName 编码长度前缀名称。
func wasmName(value string) []byte {
	out := appendU32(nil, uint32(len(value)))
	return append(out, value...)
}

// wasmExport encodes one export entry. | wasmExport 编码一个导出项。
func wasmExport(name string, kind byte, index uint32) []byte {
	out := wasmName(name)
	out = append(out, kind)
	return appendU32(out, index)
}

// wasmBody encodes one function body. | wasmBody 编码一个函数体。
func wasmBody(code ...byte) []byte {
	body := []byte{0x00}
	body = append(body, code...)
	body = append(body, 0x0b)
	out := appendU32(nil, uint32(len(body)))
	return append(out, body...)
}

// minimalWASM builds a plugin module with the ydx WAF ABI. version is the ABI version returned,
// verdict is returned from on_hook, and trap makes on_hook execute unreachable.
// | minimalWASM 构建实现 ydx WAF ABI 的插件模块。version 是返回的 ABI 版本，verdict 是 on_hook
// 的返回值，trap 让 on_hook 执行 unreachable。
func minimalWASM(version, verdict uint32, trap bool) []byte {
	module := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	types := wasmVec(
		[]byte{0x60, 0x00, 0x01, 0x7f},
		[]byte{0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f},
		[]byte{0x60, 0x01, 0x7f, 0x01, 0x7f},
		[]byte{0x60, 0x01, 0x7f, 0x00},
	)
	functions := wasmVec([]byte{0x00}, []byte{0x01}, []byte{0x01}, []byte{0x02}, []byte{0x03})
	memory := wasmVec([]byte{0x00, 0x01})
	exports := wasmVec(
		wasmExport("ydx_waf_abi_version", 0x00, 0),
		wasmExport("ydx_waf_init", 0x00, 1),
		wasmExport("ydx_waf_on_hook", 0x00, 2),
		wasmExport("ydx_waf_alloc", 0x00, 3),
		wasmExport("ydx_waf_free", 0x00, 4),
		wasmExport("memory", 0x02, 0),
	)
	hookCode := []byte{0x41, byte(verdict & 0x7f)}
	if trap {
		hookCode = []byte{0x00}
	}
	code := wasmVec(
		wasmBody(0x41, byte(version&0x7f)),
		wasmBody(0x41, 0x00),
		wasmBody(hookCode...),
		wasmBody(0x41, 0x80, 0x08),
		wasmBody(),
	)
	module = append(module, wasmSection(1, types)...)
	module = append(module, wasmSection(3, functions)...)
	module = append(module, wasmSection(5, memory)...)
	module = append(module, wasmSection(7, exports)...)
	module = append(module, wasmSection(10, code)...)
	return module
}

// newWASMTestWAF builds an instance with one WASM plugin. | newWASMTestWAF 构建带一个 WASM 插件的实例。
func newWASMTestWAF(t *testing.T, config WASMPluginConfig) *WAF {
	t.Helper()
	instance, err := New(Options{
		Directives: []string{`SecRule REQUEST_URI "@contains x" "id:1,phase:1,pass,nolog"`},
		Logger:     log.New(log.Options{Writer: io.Discard, Level: log.ErrorLevel}),
		WASMPlugins: []WASMPluginConfig{
			config,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	return instance
}

func TestWASMPluginDeny(t *testing.T) {
	instance := newWASMTestWAF(t, WASMPluginConfig{
		Name:   "deny",
		Bytes:  minimalWASM(wasmABIVersion, 1, false),
		Points: []HookPoint{HookAfterPhase},
	})
	response := serveTest(t, instance, httptestNewRequest("/x"))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

func TestWASMPluginAllow(t *testing.T) {
	instance := newWASMTestWAF(t, WASMPluginConfig{
		Name:   "allow",
		Bytes:  minimalWASM(wasmABIVersion, 0, false),
		Points: []HookPoint{HookAfterPhase},
	})
	response := serveTest(t, instance, httptestNewRequest("/x"))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
}

func TestWASMPluginFailClosedOnTrap(t *testing.T) {
	instance := newWASMTestWAF(t, WASMPluginConfig{
		Name:       "trap",
		Bytes:      minimalWASM(wasmABIVersion, 0, true),
		Points:     []HookPoint{HookAfterPhase},
		FailClosed: true,
	})
	response := serveTest(t, instance, httptestNewRequest("/x"))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", response.Code)
	}
}

func TestWASMPluginFailOpenOnTrap(t *testing.T) {
	instance := newWASMTestWAF(t, WASMPluginConfig{
		Name:   "trap-open",
		Bytes:  minimalWASM(wasmABIVersion, 0, true),
		Points: []HookPoint{HookAfterPhase},
	})
	response := serveTest(t, instance, httptestNewRequest("/x"))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
}

func TestWASMPluginRejectsWrongABI(t *testing.T) {
	_, err := New(Options{
		Directives: []string{`SecRule REQUEST_URI "@contains x" "id:1,phase:1,pass,nolog"`},
		WASMPlugins: []WASMPluginConfig{{
			Name:  "wrong-abi",
			Bytes: minimalWASM(wasmABIVersion+1, 0, false),
		}},
	})
	if err == nil {
		t.Fatal("wrong ABI version accepted")
	}
}

func TestWASMPluginConcurrent(t *testing.T) {
	instance := newWASMTestWAF(t, WASMPluginConfig{
		Name:   "concurrent",
		Bytes:  minimalWASM(wasmABIVersion, 0, false),
		Points: []HookPoint{HookBeforePhase},
	})
	var wait sync.WaitGroup
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			recorder := httptest.NewRecorder()
			instance.HTTPMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				rw.WriteHeader(http.StatusOK)
			})).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/x", nil))
			if recorder.Code != http.StatusOK {
				t.Errorf("status = %d", recorder.Code)
			}
		}()
	}
	wait.Wait()
}
