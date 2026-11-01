//go:build !xml_std

package xml

import (
	"math/rand"
	"testing"
)

func TestScannerSWARAgreesWithScalar(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, n := range []int{0, 1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257} {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(rng.Intn(6))
		}
		for start := 0; start <= n; start++ {
			for k := 0; k < 8; k++ {
				c1 := byte(rng.Intn(8))
				c2 := byte(rng.Intn(8))
				c3 := byte(rng.Intn(8))
				c4 := byte(rng.Intn(8))
				if got, want := indexByteSWAR(data, start, c1), indexByteScalar(data, start, c1); got != want {
					t.Fatalf("indexByteSWAR n=%d start=%d c=%d: got %d want %d", n, start, c1, got, want)
				}
				if got, want := indexAny2SWAR(data, start, c1, c2), indexAny2Scalar(data, start, c1, c2); got != want {
					t.Fatalf("indexAny2SWAR n=%d start=%d: got %d want %d", n, start, got, want)
				}
				if got, want := indexAny3SWAR(data, start, c1, c2, c3), indexAny3Scalar(data, start, c1, c2, c3); got != want {
					t.Fatalf("indexAny3SWAR n=%d start=%d: got %d want %d", n, start, got, want)
				}
				if got, want := indexAny4SWAR(data, start, c1, c2, c3, c4), indexAny4Scalar(data, start, c1, c2, c3, c4); got != want {
					t.Fatalf("indexAny4SWAR n=%d start=%d: got %d want %d", n, start, got, want)
				}
			}
		}
	}
}

func TestScannerDispatchIsInstalled(t *testing.T) {
	if scanIndexByte == nil || scanIndexAny2 == nil || scanIndexAny3 == nil || scanIndexAny4 == nil {
		t.Fatal("scanner dispatch function is nil")
	}
}
