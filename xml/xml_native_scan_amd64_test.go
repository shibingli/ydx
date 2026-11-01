//go:build amd64 && !xml_std

package xml

import (
	"math/rand"
	"testing"
)

func TestScannerAMD64AgreesWithScalar(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	type byteFunc func([]byte, int, byte) int
	type any2Func func([]byte, int, byte, byte) int
	type any3Func func([]byte, int, byte, byte, byte) int
	type any4Func func([]byte, int, byte, byte, byte, byte) int

	modes := []struct {
		name      string
		indexByte byteFunc
		any2      any2Func
		any3      any3Func
		any4      any4Func
	}{
		{"SSE2", indexByteSSE2, indexAny2SSE2, indexAny3SSE2, indexAny4SSE2},
	}
	if useAVX2 {
		modes = append(modes, struct {
			name      string
			indexByte byteFunc
			any2      any2Func
			any3      any3Func
			any4      any4Func
		}{"AVX2", indexByteAVX2, indexAny2AVX2, indexAny3AVX2, indexAny4AVX2})
	}
	if useAVX512BW {
		modes = append(modes, struct {
			name      string
			indexByte byteFunc
			any2      any2Func
			any3      any3Func
			any4      any4Func
		}{"AVX512", indexByteAVX512, indexAny2AVX512, indexAny3AVX512, indexAny4AVX512})
	}

	for _, mode := range modes {
		for _, n := range []int{0, 1, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1024} {
			data := make([]byte, n)
			for i := range data {
				data[i] = byte(rng.Intn(6))
			}
			for start := 0; start <= n; start++ {
				for k := 0; k < 6; k++ {
					c1, c2, c3, c4 := byte(rng.Intn(8)), byte(rng.Intn(8)), byte(rng.Intn(8)), byte(rng.Intn(8))
					if got, want := mode.indexByte(data, start, c1), indexByteScalar(data, start, c1); got != want {
						t.Fatalf("%s indexByte n=%d start=%d c=%d: got %d want %d", mode.name, n, start, c1, got, want)
					}
					if got, want := mode.any2(data, start, c1, c2), indexAny2Scalar(data, start, c1, c2); got != want {
						t.Fatalf("%s indexAny2 n=%d start=%d: got %d want %d", mode.name, n, start, got, want)
					}
					if got, want := mode.any3(data, start, c1, c2, c3), indexAny3Scalar(data, start, c1, c2, c3); got != want {
						t.Fatalf("%s indexAny3 n=%d start=%d: got %d want %d", mode.name, n, start, got, want)
					}
					if got, want := mode.any4(data, start, c1, c2, c3, c4), indexAny4Scalar(data, start, c1, c2, c3, c4); got != want {
						t.Fatalf("%s indexAny4 n=%d start=%d: got %d want %d", mode.name, n, start, got, want)
					}
				}
			}
		}
	}
}
