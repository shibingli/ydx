package client

import (
	"bytes"
	"testing"
)

func FuzzEventReaderNoPanic(f *testing.F) {
	f.Add([]byte("data: hi\n\n"))
	f.Add([]byte(": ping\r\n\r\ndata: x\r\r"))
	f.Fuzz(func(t *testing.T, b []byte) {
		r := NewEventReader(bytes.NewReader(b))
		for i := 0; i < 100; i++ {
			if _, err := r.Next(); err != nil {
				return
			}
		}
	})
}
