package base64

import (
	"bytes"
	stdb64 "encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	b64x "github.com/shibingli/ydx/base64"
)

// compatAlphabet is a valid custom alphabet in a non-standard order. | compatAlphabet 是顺序非标准的
// 合法自定义字母表。
const compatAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/"

// TestEncodingOptionsMatchStdlib cross-checks the encoding/base64-compatible constructor and
// option APIs (NewEncoding, Strict, WithPadding, NoPadding) against the standard library. |
// TestEncodingOptionsMatchStdlib 与标准库对拍 encoding/base64 兼容的构造与选项 API
// （NewEncoding、Strict、WithPadding、NoPadding）。
func TestEncodingOptionsMatchStdlib(t *testing.T) {
	variants := []struct {
		name string
		ydx  *b64x.Encoding
		std  *stdb64.Encoding
	}{
		{"custom", b64x.NewEncoding(compatAlphabet), stdb64.NewEncoding(compatAlphabet)},
		{"no_padding", b64x.StdEncoding.WithPadding(b64x.NoPadding), stdb64.StdEncoding.WithPadding(stdb64.NoPadding)},
		{"hash_padding", b64x.StdEncoding.WithPadding('#'), stdb64.StdEncoding.WithPadding('#')},
		{"custom_hash", b64x.NewEncoding(compatAlphabet).WithPadding('#'), stdb64.NewEncoding(compatAlphabet).WithPadding('#')},
		{"strict", b64x.StdEncoding.Strict(), stdb64.StdEncoding.Strict()},
		{"raw_strict", b64x.RawStdEncoding.Strict(), stdb64.RawStdEncoding.Strict()},
	}
	for _, v := range variants {
		for size := 0; size <= 64; size++ {
			src := benchBuf(size)
			got, want := v.ydx.EncodeToString(src), v.std.EncodeToString(src)
			if got != want {
				t.Fatalf("%s size=%d: EncodeToString = %q want %q", v.name, size, got, want)
			}
			back, err := v.ydx.DecodeString(want)
			wantBack, wantErr := v.std.DecodeString(want)
			if (err == nil) != (wantErr == nil) || !bytes.Equal(back, wantBack) {
				t.Fatalf("%s size=%d: DecodeString = (%x, %v) want (%x, %v)", v.name, size, back, err, wantBack, wantErr)
			}
		}
	}
	// Invalid alphabets return nil instead of panicking (ydx no-panic policy). | 非法字母表返回 nil
	// 而不是 panic（ydx 禁止 panic 约束）。
	for _, alpha := range []string{"", "abc", strings.Repeat("A", 65), strings.Repeat("A", 64)} {
		if enc := b64x.NewEncoding(alpha); enc != nil {
			t.Fatalf("NewEncoding(%q) = %v want nil", alpha, enc)
		}
	}
	for _, pad := range []rune{'A', '\n', rune(0x100)} {
		if enc := b64x.StdEncoding.WithPadding(pad); enc != nil {
			t.Fatalf("WithPadding(%q) = %v want nil", pad, enc)
		}
	}
}

// TestStrictAndCorruptInputMatchStdlib verifies strict trailing-bit checks and corrupt-input
// offsets equal encoding/base64. | TestStrictAndCorruptInputMatchStdlib 验证 strict 尾部比特校验与
// 非法输入偏移都与 encoding/base64 一致。
func TestStrictAndCorruptInputMatchStdlib(t *testing.T) {
	variants := []struct {
		name string
		ydx  *b64x.Encoding
		std  *stdb64.Encoding
	}{
		{"std", b64x.StdEncoding, stdb64.StdEncoding},
		{"strict", b64x.StdEncoding.Strict(), stdb64.StdEncoding.Strict()},
		{"raw_strict", b64x.RawStdEncoding.Strict(), stdb64.RawStdEncoding.Strict()},
		{"url", b64x.URLEncoding, stdb64.URLEncoding},
	}
	inputs := []string{
		"", "A", "AA", "AAA", "AAAA", "AB==", "AAB=", "AB", "AAB",
		"AA==", "AAA=", "AAAAA", "AA=A", "A===", "====", "AA==AA==",
		"!!!!", "AA!A", "AAAA=", "AA==\nA", "AAAAA\nAA", "ABCD=", "ABCD==",
	}
	for _, v := range variants {
		for _, in := range inputs {
			got, gotErr := v.ydx.DecodeString(in)
			want, wantErr := v.std.DecodeString(in)
			if (gotErr == nil) != (wantErr == nil) || !bytes.Equal(got, want) {
				t.Fatalf("%s %q: DecodeString = (%x, %v) want (%x, %v)", v.name, in, got, gotErr, want, wantErr)
			}
			if gotErr == nil {
				continue
			}
			var ourCE b64x.CorruptInputError
			if !errors.As(gotErr, &ourCE) {
				t.Fatalf("%s %q: %v is not b64x.CorruptInputError", v.name, in, gotErr)
			}
			if !errors.Is(gotErr, b64x.ErrInvalidData) {
				t.Fatalf("%s %q: errors.Is(ErrInvalidData) = false", v.name, in)
			}
			var stdCE stdb64.CorruptInputError
			if !errors.As(wantErr, &stdCE) {
				t.Fatalf("%s %q: std error %v is not CorruptInputError", v.name, in, wantErr)
			}
			if int64(ourCE) != int64(stdCE) || ourCE.Error() != stdCE.Error() {
				t.Fatalf("%s %q: CorruptInputError = %v want %v", v.name, in, ourCE, stdCE)
			}
		}
	}
}

// TestPartialDecodeMatchesStdlib verifies Decode and DecodeString return the same partial
// output as encoding/base64 when input is malformed. | TestPartialDecodeMatchesStdlib 验证输入非法
// 时 Decode 与 DecodeString 返回与 encoding/base64 相同的部分输出。
func TestPartialDecodeMatchesStdlib(t *testing.T) {
	inputs := []string{"AAAAA", "AAAA=", "ABCDEFGH=JKLMNOP", "AQIDBA!=", "AAAA AA"}
	for _, in := range inputs {
		ydxOut := make([]byte, b64x.StdEncoding.DecodedLen(len(in)))
		stdOut := make([]byte, stdb64.StdEncoding.DecodedLen(len(in)))
		ydxN, ydxErr := b64x.StdEncoding.Decode(ydxOut, []byte(in))
		stdN, stdErr := stdb64.StdEncoding.Decode(stdOut, []byte(in))
		if (ydxErr == nil) != (stdErr == nil) || ydxN != stdN || !bytes.Equal(ydxOut[:ydxN], stdOut[:stdN]) {
			t.Fatalf("%q: Decode = (%x, %v) want (%x, %v)", in, ydxOut[:ydxN], ydxErr, stdOut[:stdN], stdErr)
		}
		ydxStr, ydxStrErr := b64x.StdEncoding.DecodeString(in)
		stdStr, stdStrErr := stdb64.StdEncoding.DecodeString(in)
		if (ydxStrErr == nil) != (stdStrErr == nil) || !bytes.Equal(ydxStr, stdStr) {
			t.Fatalf("%q: DecodeString = (%x, %v) want (%x, %v)", in, ydxStr, ydxStrErr, stdStr, stdStrErr)
		}
	}
}

// TestStreamingCodecMatchesStdlib cross-checks NewEncoder / NewDecoder, including CR/LF
// filtering and small write chunks. | TestStreamingCodecMatchesStdlib 对拍 NewEncoder /
// NewDecoder，含 CR/LF 过滤与小分块写入。
func TestStreamingCodecMatchesStdlib(t *testing.T) {
	variants := []struct {
		name string
		ydx  *b64x.Encoding
		std  *stdb64.Encoding
	}{
		{"std", b64x.StdEncoding, stdb64.StdEncoding},
		{"raw_url", b64x.RawURLEncoding, stdb64.RawURLEncoding},
		{"no_padding", b64x.StdEncoding.WithPadding(b64x.NoPadding), stdb64.StdEncoding.WithPadding(stdb64.NoPadding)},
		{"hash_padding", b64x.StdEncoding.WithPadding('#'), stdb64.StdEncoding.WithPadding('#')},
	}
	for _, v := range variants {
		for _, size := range []int{0, 1, 2, 3, 5, 31, 1024, 4097} {
			src := benchBuf(size)
			for _, chunk := range []int{1, 3, 7, 512} {
				var ydxOut, stdOut bytes.Buffer
				ydxEnc := b64x.NewEncoder(v.ydx, &ydxOut)
				stdEnc := stdb64.NewEncoder(v.std, &stdOut)
				for off := 0; off < len(src); off += chunk {
					end := off + chunk
					if end > len(src) {
						end = len(src)
					}
					if _, err := ydxEnc.Write(src[off:end]); err != nil {
						t.Fatalf("%s size=%d chunk=%d: ydx Write: %v", v.name, size, chunk, err)
					}
					if _, err := stdEnc.Write(src[off:end]); err != nil {
						t.Fatalf("%s size=%d chunk=%d: std Write: %v", v.name, size, chunk, err)
					}
				}
				if err := ydxEnc.Close(); err != nil {
					t.Fatalf("%s size=%d: ydx Close: %v", v.name, size, err)
				}
				if err := stdEnc.Close(); err != nil {
					t.Fatalf("%s size=%d: std Close: %v", v.name, size, err)
				}
				if ydxOut.String() != stdOut.String() {
					t.Fatalf("%s size=%d chunk=%d: stream output differs", v.name, size, chunk)
				}
			}
			encoded := v.std.EncodeToString(src)
			var wrapped strings.Builder
			for i := 0; i < len(encoded); i += 4 {
				end := i + 4
				if end > len(encoded) {
					end = len(encoded)
				}
				wrapped.WriteString(encoded[i:end])
				wrapped.WriteString("\r\n")
			}
			ydxDec := b64x.NewDecoder(v.ydx, strings.NewReader(wrapped.String()))
			stdDec := stdb64.NewDecoder(v.std, strings.NewReader(wrapped.String()))
			ydxBack, ydxErr := io.ReadAll(ydxDec)
			stdBack, stdErr := io.ReadAll(stdDec)
			if (ydxErr == nil) != (stdErr == nil) || !bytes.Equal(ydxBack, stdBack) {
				t.Fatalf("%s size=%d: stream decode = (%x, %v) want (%x, %v)", v.name, size, ydxBack, ydxErr, stdBack, stdErr)
			}
		}
	}
}

// compatUnicodeInputs covers CJK, emoji, RTL text, metacharacters, line separators and
// invalid UTF-8 bytes. | compatUnicodeInputs 覆盖 CJK、表情符号、RTL 文本、元字符、行分隔符与
// 非法 UTF-8 字节。
func compatUnicodeInputs() [][]byte {
	return [][]byte{
		{},
		[]byte("中文测试"),
		[]byte("😀🚀🎉👨‍👩‍👧‍👦"),
		[]byte("مرحبا"),
		[]byte(`<>"'&\/+`),
		[]byte("\u2028\u2029"),
		{0xff, 0xfe, 0x80},
		[]byte("mixed 中文😀 <&> end"),
	}
}

// TestUnicodePayloadsMatchStdlib cross-checks non-ASCII and special-byte payloads through all
// encoding variants, including the three padding residues. | TestUnicodePayloadsMatchStdlib 用
// 非 ASCII 与特殊字节载荷对拍全部编码变体，并覆盖三种填充余数。
func TestUnicodePayloadsMatchStdlib(t *testing.T) {
	variants := []struct {
		name string
		ydx  *b64x.Encoding
		std  *stdb64.Encoding
	}{
		{"std", b64x.StdEncoding, stdb64.StdEncoding},
		{"raw_std", b64x.RawStdEncoding, stdb64.RawStdEncoding},
		{"url", b64x.URLEncoding, stdb64.URLEncoding},
		{"raw_url", b64x.RawURLEncoding, stdb64.RawURLEncoding},
		{"no_padding", b64x.StdEncoding.WithPadding(b64x.NoPadding), stdb64.StdEncoding.WithPadding(stdb64.NoPadding)},
	}
	for _, v := range variants {
		for _, base := range compatUnicodeInputs() {
			for pad := 0; pad < 3; pad++ {
				src := append(append([]byte(nil), base...), bytes.Repeat([]byte{'x'}, pad)...)
				if got, want := v.ydx.EncodeToString(src), v.std.EncodeToString(src); got != want {
					t.Fatalf("%s len=%d: EncodeToString differs", v.name, len(src))
				}
				encoded := v.std.EncodeToString(src)
				got, err := v.ydx.DecodeString(encoded)
				want, wantErr := v.std.DecodeString(encoded)
				if (err == nil) != (wantErr == nil) || !bytes.Equal(got, want) {
					t.Fatalf("%s len=%d: DecodeString = (%q, %v) want (%q, %v)", v.name, len(src), got, err, want, wantErr)
				}
			}
		}
	}
}
