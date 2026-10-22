package sse

import (
	"fmt"
	"strings"
	"testing"
	"time"

	sselib "github.com/gin-contrib/sse"

	. "github.com/shibingli/ydx/sse"
)

// BenchmarkWriteDataCompare compares a data-only event across the ydx writer, gin-contrib/sse
// and a hand-written fmt.Fprintf encoder. The latter is the common "no library" baseline. |
// BenchmarkWriteDataCompare 对比 ydx 写入器、gin-contrib/sse 与手写 fmt.Fprintf 编码器的纯 data
// 事件。后者是常见的「不用库」基线。
func BenchmarkWriteDataCompare(b *testing.B) {
	cases := []struct {
		name string
		data string
	}{
		{name: "small_32B", data: strings.Repeat("a", 32)},
		{name: "large_4KiB", data: strings.Repeat("a", 4<<10)},
	}
	for _, c := range cases {
		b.Run(c.name+"/ydx", func(b *testing.B) {
			w := benchSSEWriter(b, benchDefaultBufferSize)
			if err := w.WriteData(c.data); err != nil {
				b.Fatalf("warm-up WriteData failed | 预热 WriteData 失败: %v", err)
			}
			b.SetBytes(int64(len(c.data)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := w.WriteData(c.data); err != nil {
					b.Fatalf("WriteData failed | WriteData 失败: %v", err)
				}
			}
		})
		b.Run(c.name+"/gin-contrib", func(b *testing.B) {
			w := newBenchWriter()
			event := sselib.Event{Data: c.data}
			if err := sselib.Encode(w, event); err != nil {
				b.Fatalf("warm-up Encode failed | 预热 Encode 失败: %v", err)
			}
			b.SetBytes(int64(len(c.data)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := sselib.Encode(w, event); err != nil {
					b.Fatalf("Encode failed | Encode 失败: %v", err)
				}
			}
		})
		b.Run(c.name+"/manual", func(b *testing.B) {
			w := newBenchWriter()
			if _, err := fmt.Fprintf(w, "data: %s\n\n", c.data); err != nil {
				b.Fatalf("warm-up write failed | 预热写入失败: %v", err)
			}
			b.SetBytes(int64(len(c.data)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := fmt.Fprintf(w, "data: %s\n\n", c.data); err != nil {
					b.Fatalf("write failed | 写入失败: %v", err)
				}
			}
		})
	}
}

// BenchmarkWriteEventCompare compares a full event carrying id, name, retry and data. ydx also
// writes a comment; gin-contrib/sse has no comment field, and the manual encoder includes the
// same comment for a closer comparison. | BenchmarkWriteEventCompare 对比携带 id、name、retry 与
// data 的完整事件。ydx 还会写注释；gin-contrib/sse 没有注释字段，手写编码器为贴近对比也写入相同注释。
func BenchmarkWriteEventCompare(b *testing.B) {
	event := Event{
		ID:      "evt-12345",
		Name:    "message",
		Comment: "keep-alive",
		Data:    []byte(strings.Repeat("payload line\n", 16)),
		Retry:   3 * time.Second,
	}
	ginEvent := sselib.Event{
		Id:    event.ID,
		Event: event.Name,
		Retry: uint(event.Retry / time.Millisecond),
		Data:  string(event.Data),
	}

	b.Run("ydx", func(b *testing.B) {
		w := benchSSEWriter(b, benchDefaultBufferSize)
		if err := w.WriteEvent(event); err != nil {
			b.Fatalf("warm-up WriteEvent failed | 预热 WriteEvent 失败: %v", err)
		}
		b.SetBytes(int64(len(event.Data)))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := w.WriteEvent(event); err != nil {
				b.Fatalf("WriteEvent failed | WriteEvent 失败: %v", err)
			}
		}
	})
	b.Run("gin-contrib", func(b *testing.B) {
		w := newBenchWriter()
		if err := sselib.Encode(w, ginEvent); err != nil {
			b.Fatalf("warm-up Encode failed | 预热 Encode 失败: %v", err)
		}
		b.SetBytes(int64(len(event.Data)))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := sselib.Encode(w, ginEvent); err != nil {
				b.Fatalf("Encode failed | Encode 失败: %v", err)
			}
		}
	})
	b.Run("manual", func(b *testing.B) {
		w := newBenchWriter()
		data := string(event.Data)
		if _, err := fmt.Fprintf(w, ": %s\nid: %s\nevent: %s\nretry: %d\ndata: %s\n\n",
			event.Comment, event.ID, event.Name, event.Retry/time.Millisecond, data); err != nil {
			b.Fatalf("warm-up write failed | 预热写入失败: %v", err)
		}
		b.SetBytes(int64(len(event.Data)))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := fmt.Fprintf(w, ": %s\nid: %s\nevent: %s\nretry: %d\ndata: %s\n\n",
				event.Comment, event.ID, event.Name, event.Retry/time.Millisecond, data); err != nil {
				b.Fatalf("write failed | 写入失败: %v", err)
			}
		}
	})
}
