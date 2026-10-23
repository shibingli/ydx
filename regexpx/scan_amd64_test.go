//go:build amd64

package regexpx

import (
	"reflect"
	"testing"
)

// funcPC returns the code pointer of a kernel so tests can prove which one was installed. |
// funcPC 返回内核的代码指针，供测试证明安装的是哪一个。
func funcPC(fn any) uintptr {
	return reflect.ValueOf(fn).Pointer()
}

// TestAMD64SIMDSelection proves that the widest detected instruction set is installed. |
// TestAMD64SIMDSelection 证明已安装检测到的最宽指令集。
func TestAMD64SIMDSelection(t *testing.T) {
	sse41, sse42, avx2, avx512 := detectScanCPU()
	if sse42 && !sse41 {
		t.Fatal("SSE4.2 reported without SSE4.1")
	}
	switch {
	case avx512:
		if indexByteBlock != 64 || indexByteSetBlock != 64 || indexFoldPairBlock != 64 {
			t.Fatalf("AVX-512 available but block = %d/%d/%d", indexByteBlock, indexByteSetBlock, indexFoldPairBlock)
		}
	case avx2:
		if indexByteBlock != 32 || indexByteSetBlock != 32 || indexFoldPairBlock != 32 {
			t.Fatalf("AVX2 available but block = %d/%d/%d", indexByteBlock, indexByteSetBlock, indexFoldPairBlock)
		}
	case sse42 || sse41:
		if indexByteBlock != 16 || indexByteSetBlock != 16 || indexFoldPairBlock != 16 {
			t.Fatalf("SSE4.x available but block = %d/%d/%d", indexByteBlock, indexByteSetBlock, indexFoldPairBlock)
		}
	default:
		if indexByteBlock != 1 || indexByteSetBlock != 1 || indexFoldPairBlock != 1 {
			t.Fatalf("no SIMD but block = %d/%d/%d", indexByteBlock, indexByteSetBlock, indexFoldPairBlock)
		}
	}
}

// TestInstallScanKernels proves the priority order and every block size without executing the
// kernels. | TestInstallScanKernels 在不执行内核的情况下证明优先级与每种块大小。
func TestInstallScanKernels(t *testing.T) {
	byteFn, byteBlock := indexByteFn, indexByteBlock
	setFn, setBlock := indexByteSetFn, indexByteSetBlock
	foldFn, foldBlock := indexFoldPairFn, indexFoldPairBlock
	defer func() {
		indexByteFn, indexByteBlock = byteFn, byteBlock
		indexByteSetFn, indexByteSetBlock = setFn, setBlock
		indexFoldPairFn, indexFoldPairBlock = foldFn, foldBlock
	}()
	cases := []struct {
		sse41, sse42, avx2, avx512 bool
		block                      int
		byteFn, setFn, foldFn      any
	}{
		{false, false, false, false, 1, indexByteScalar, indexByteSetScalar, indexFoldPairScalar},
		{true, false, false, false, 16, indexByteSSE41, indexByteSetSSE41, indexFoldPairSSE41},
		{true, true, false, false, 16, indexByteSSE42, indexByteSetSSE42, indexFoldPairSSE42},
		{true, true, true, false, 32, indexByteAVX2, indexByteSetAVX2, indexFoldPairAVX2},
		{true, true, true, true, 64, indexByteAVX512, indexByteSetAVX512, indexFoldPairAVX512},
		{false, false, true, true, 64, indexByteAVX512, indexByteSetAVX512, indexFoldPairAVX512},
	}
	for _, c := range cases {
		installScanKernels(c.sse41, c.sse42, c.avx2, c.avx512)
		if indexByteBlock != c.block || indexByteSetBlock != c.block || indexFoldPairBlock != c.block {
			t.Fatalf("install(%v,%v,%v,%v) block = %d/%d/%d, want %d",
				c.sse41, c.sse42, c.avx2, c.avx512,
				indexByteBlock, indexByteSetBlock, indexFoldPairBlock, c.block)
		}
		if funcPC(indexByteFn) != funcPC(c.byteFn) {
			t.Fatalf("install(%v,%v,%v,%v) byte kernel = %#x, want %#x",
				c.sse41, c.sse42, c.avx2, c.avx512, funcPC(indexByteFn), funcPC(c.byteFn))
		}
		if funcPC(indexByteSetFn) != funcPC(c.setFn) {
			t.Fatalf("install(%v,%v,%v,%v) set kernel = %#x, want %#x",
				c.sse41, c.sse42, c.avx2, c.avx512, funcPC(indexByteSetFn), funcPC(c.setFn))
		}
		if funcPC(indexFoldPairFn) != funcPC(c.foldFn) {
			t.Fatalf("install(%v,%v,%v,%v) fold kernel = %#x, want %#x",
				c.sse41, c.sse42, c.avx2, c.avx512, funcPC(indexFoldPairFn), funcPC(c.foldFn))
		}
	}
}

// TestSSEKernelIntegration installs the SSE4.1 and SSE4.2 kernels and reruns the full reference
// suites, so their 16-byte wrappers and scalar tails are compared at every offset. |
// TestSSEKernelIntegration 安装 SSE4.1 与 SSE4.2 内核并重跑完整参考测试，在每个偏移处对比 16 字节
// 包装与标量尾部。
func TestSSEKernelIntegration(t *testing.T) {
	sse41, sse42, _, _ := detectScanCPU()
	if !sse41 {
		t.Skip("SSE4.1 unavailable")
	}
	byteFn, byteBlock := indexByteFn, indexByteBlock
	setFn, setBlock := indexByteSetFn, indexByteSetBlock
	foldFn, foldBlock := indexFoldPairFn, indexFoldPairBlock
	defer func() {
		indexByteFn, indexByteBlock = byteFn, byteBlock
		indexByteSetFn, indexByteSetBlock = setFn, setBlock
		indexFoldPairFn, indexFoldPairBlock = foldFn, foldBlock
	}()
	installScanKernels(true, false, false, false)
	if indexByteBlock != 16 || indexByteSetBlock != 16 || indexFoldPairBlock != 16 {
		t.Fatalf("SSE4.1 block = %d/%d/%d, want 16", indexByteBlock, indexByteSetBlock, indexFoldPairBlock)
	}
	t.Run("SSE41/IndexByte", TestIndexByteMatchesReference)
	t.Run("SSE41/IndexByteSet", TestIndexByteSetMatchesReference)
	t.Run("SSE41/IndexLiteral", TestIndexLiteralMatchesReference)
	t.Run("SSE41/IndexFoldPair", TestIndexFoldPairMatchesReference)
	if !sse42 {
		return
	}
	installScanKernels(true, true, false, false)
	if indexByteBlock != 16 || indexByteSetBlock != 16 || indexFoldPairBlock != 16 {
		t.Fatalf("SSE4.2 block = %d/%d/%d, want 16", indexByteBlock, indexByteSetBlock, indexFoldPairBlock)
	}
	t.Run("SSE42/IndexByte", TestIndexByteMatchesReference)
	t.Run("SSE42/IndexByteSet", TestIndexByteSetMatchesReference)
	t.Run("SSE42/IndexLiteral", TestIndexLiteralMatchesReference)
	t.Run("SSE42/IndexFoldPair", TestIndexFoldPairMatchesReference)
}
