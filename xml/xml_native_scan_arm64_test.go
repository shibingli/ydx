//go:build arm64 && !xml_std

package xml

import (
	"math/rand"
	"testing"
)

func TestScannerNEONAgreesWithScalar(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	for _, n := range []int{0, 1, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1024} {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(rng.Intn(6))
		}
		for start := 0; start <= n; start++ {
			for k := 0; k < 6; k++ {
				c1, c2, c3, c4 := byte(rng.Intn(8)), byte(rng.Intn(8)), byte(rng.Intn(8)), byte(rng.Intn(8))
				if got, want := indexByteNEON(data, start, c1), indexByteScalar(data, start, c1); got != want {
					t.Fatalf("indexByteNEON n=%d start=%d c=%d: got %d want %d", n, start, c1, got, want)
				}
				if got, want := indexAny2NEON(data, start, c1, c2), indexAny2Scalar(data, start, c1, c2); got != want {
					t.Fatalf("indexAny2NEON n=%d start=%d: got %d want %d", n, start, got, want)
				}
				if got, want := indexAny3NEON(data, start, c1, c2, c3), indexAny3Scalar(data, start, c1, c2, c3); got != want {
					t.Fatalf("indexAny3NEON n=%d start=%d: got %d want %d", n, start, got, want)
				}
				if got, want := indexAny4NEON(data, start, c1, c2, c3, c4), indexAny4Scalar(data, start, c1, c2, c3, c4); got != want {
					t.Fatalf("indexAny4NEON n=%d start=%d: got %d want %d", n, start, got, want)
				}
			}
		}
	}
}
