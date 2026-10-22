//go:build !jsonx_std

package json

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// TestDecoderArenaAppendOnly verifies that reusing one decoder never overwrites strings returned
// by earlier calls, including when the arena fills up and a new chunk starts. |
// TestDecoderArenaAppendOnly 验证复用同一个解码器不会覆盖更早调用返回的字符串，包括 arena 写满并
// 开启新块的情况。
func TestDecoderArenaAppendOnly(t *testing.T) {
	d := &decoder{}
	var got, want []string
	for i := 0; i < 2000; i++ {
		body := fmt.Sprintf("value-%04d-%s", i, strings.Repeat("x", i%40))
		want = append(want, body)
		d.data = []byte(`"` + body + `",padding`)
		d.pos = 0
		s, err := d.parseString()
		if err != nil {
			t.Fatalf("parseString %d failed | 失败: %v", i, err)
		}
		got = append(got, s)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("string %d = %q, want %q (an earlier arena chunk was overwritten)",
				i, got[i], want[i])
		}
	}
}

// TestUnmarshalArenaRetentionConcurrent keeps every decoded result alive while other goroutines
// reuse pooled decoders, so a prematurely reused arena would corrupt earlier strings. |
// TestUnmarshalArenaRetentionConcurrent 在其他 goroutine 复用池化解码器期间保留所有解码结果，若
// arena 被提前复用，早先的字符串就会被破坏。
func TestUnmarshalArenaRetentionConcurrent(t *testing.T) {
	type doc struct {
		Name  string   `json:"name"`
		Tags  []string `json:"tags"`
		ID    int64    `json:"id"`
		Score float64  `json:"score"`
		Good  bool     `json:"good"`
	}
	const goroutines, rounds = 4, 500
	results := make([][]doc, goroutines)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			out := make([]doc, 0, rounds)
			for i := 0; i < rounds; i++ {
				name := fmt.Sprintf("goroutine-%d-round-%d-%s", g, i, strings.Repeat("y", (g*i)%50))
				in := fmt.Sprintf(`{"name":%q,"tags":["alpha","beta","gamma"],"id":%d,"score":98.5,"good":true}`, name, i)
				var v doc
				if err := Unmarshal([]byte(in), &v); err != nil {
					t.Errorf("Unmarshal failed | 失败: %v", err)
					return
				}
				if v.Name != name {
					t.Errorf("goroutine %d round %d: name %q, want %q", g, i, v.Name, name)
					return
				}
				out = append(out, v)
			}
			results[g] = out
		}(g)
	}
	wg.Wait()
	if t.Failed() {
		return
	}
	// Every string must still hold its original value after all reuse. | 所有复用结束后，每个字符串
	// 必须仍是原值。
	for g := range results {
		for i, v := range results[g] {
			want := fmt.Sprintf("goroutine-%d-round-%d-%s", g, i, strings.Repeat("y", (g*i)%50))
			if v.Name != want {
				t.Fatalf("goroutine %d round %d: retained name %q, want %q", g, i, v.Name, want)
			}
			if len(v.Tags) != 3 || v.Tags[0] != "alpha" || v.Tags[1] != "beta" || v.Tags[2] != "gamma" {
				t.Fatalf("goroutine %d round %d: retained tags %#v", g, i, v.Tags)
			}
		}
	}
}

// TestUnmarshalLongCleanString covers clean strings larger than one arena chunk. |
// TestUnmarshalLongCleanString 覆盖超过单个 arena 块的干净字符串。
func TestUnmarshalLongCleanString(t *testing.T) {
	long := strings.Repeat("abcdefghij", 5000) // 50,000 bytes
	in := []byte(`{"name":"` + long + `"}`)
	var v struct {
		Name string `json:"name"`
	}
	if err := Unmarshal(in, &v); err != nil {
		t.Fatalf("Unmarshal failed | 失败: %v", err)
	}
	if v.Name != long {
		t.Fatalf("long string mismatch: got %d bytes, want %d", len(v.Name), len(long))
	}
}

// TestParseCleanString verifies the fused scan-and-copy fast path for clean ASCII strings across
// word boundaries and its fallback for escapes, control bytes, non-ASCII bytes and unterminated
// input. | TestParseCleanString 验证干净 ASCII 字符串的扫描复制融合快速路径（覆盖字边界），以及
// 对转义、控制字节、非 ASCII 字节和未终止输入的回退。
func TestParseCleanString(t *testing.T) {
	bodies := []string{
		"", "a", "ab", "abc", "abcd", "abcde", "abcdef", "abcdefg",
		"abcdefgh", "abcdefghi", "bench-user", strings.Repeat("x", 15),
		strings.Repeat("x", 16), strings.Repeat("x", 17), strings.Repeat("y", 40),
	}
	for _, body := range bodies {
		// Padding after the closing quote keeps at least one full word readable. | 结束引号后的填充
		// 保证至少有一个完整字可读。
		input := []byte(`"` + body + `",padding`)
		d := &decoder{data: input}
		s, ok := d.parseCleanString(1)
		if !ok {
			t.Fatalf("parseCleanString(%q) fell back | 回退", body)
		}
		if s != body {
			t.Fatalf("parseCleanString(%q) = %q", body, s)
		}
		if d.pos != len(body)+2 {
			t.Fatalf("parseCleanString(%q) left pos %d, want %d", body, d.pos, len(body)+2)
		}
	}

	// Sequential strings share one arena, including after growth. | 连续字符串共享同一 arena，包括
	// 扩容之后。
	d := &decoder{data: []byte(`"one","two","three","four","five","six","seven","eight"` +
		`,padding`)}
	var got []string
	for i := 0; i < 8; i++ {
		s, err := d.parseString()
		if err != nil {
			t.Fatalf("parseString %d failed | 失败: %v", i, err)
		}
		got = append(got, s)
		if d.pos < len(d.data) && d.data[d.pos] == ',' {
			d.pos++
		}
	}
	want := []string{"one", "two", "three", "four", "five", "six", "seven", "eight"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("string %d = %q, want %q", i, got[i], want[i])
		}
	}

	fallbacks := []string{`"a\"b",padding`, "\"h\xc3\xa9llo\",padding", "\"a\x01b\",padding", `"abc`}
	for _, input := range fallbacks {
		d := &decoder{data: []byte(input)}
		if s, ok := d.parseCleanString(1); ok {
			t.Fatalf("parseCleanString(%q) should fall back, got %q", input, s)
		}
		if d.pos != 0 {
			t.Fatalf("parseCleanString(%q) changed pos to %d", input, d.pos)
		}
	}
}
