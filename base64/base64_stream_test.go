package base64

import (
	"bytes"
	stdb64 "encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
)

// testAlphabet is a valid 64-byte custom alphabet in a non-standard order. |
// testAlphabet 是顺序非标准的合法 64 字节自定义字母表。
const testAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/"

// TestNewEncodingRejectsInvalidAlphabet verifies invalid alphabets return nil instead of
// panicking. | TestNewEncodingRejectsInvalidAlphabet 验证非法字母表返回 nil 而不是 panic。
func TestNewEncodingRejectsInvalidAlphabet(t *testing.T) {
	cases := []string{
		"",
		"abc",
		strings.Repeat("A", 65),
		strings.Repeat("A", 64),
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+\n",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+\r",
	}
	for _, alpha := range cases {
		if enc := NewEncoding(alpha); enc != nil {
			t.Errorf("NewEncoding(%q) = %v want nil", alpha, enc)
		}
	}
	if enc := NewEncoding(testAlphabet); enc == nil {
		t.Fatal("NewEncoding(testAlphabet) = nil")
	}
}

// TestNewEncodingMatchesStdlib cross-checks a custom alphabet against encoding/base64. |
// TestNewEncodingMatchesStdlib 用自定义字母表与 encoding/base64 对拍。
func TestNewEncodingMatchesStdlib(t *testing.T) {
	ours, theirs := NewEncoding(testAlphabet), stdb64.NewEncoding(testAlphabet)
	for n := 0; n <= 64; n++ {
		src := randomBytes(n)
		if got, want := ours.EncodeToString(src), theirs.EncodeToString(src); got != want {
			t.Fatalf("n=%d EncodeToString = %q want %q", n, got, want)
		}
		text := theirs.EncodeToString(src)
		got, gotErr := ours.DecodeString(text)
		want, wantErr := theirs.DecodeString(text)
		if (gotErr == nil) != (wantErr == nil) || !bytes.Equal(got, want) {
			t.Fatalf("n=%d DecodeString = (%q, %v) want (%q, %v)", n, got, gotErr, want, wantErr)
		}
	}
}

// TestWithPaddingMatchesStdlib cross-checks NoPadding and a custom padding character. |
// TestWithPaddingMatchesStdlib 对 NoPadding 与自定义填充字符与标准库对拍。
func TestWithPaddingMatchesStdlib(t *testing.T) {
	oursNoPad := StdEncoding.WithPadding(NoPadding)
	theirsNoPad := stdb64.StdEncoding.WithPadding(stdb64.NoPadding)
	oursHash := NewEncoding(testAlphabet).WithPadding('#')
	theirsHash := stdb64.NewEncoding(testAlphabet).WithPadding('#')
	if !oursNoPad.isRaw() || oursHash.isRaw() {
		t.Fatalf("isRaw: noPad=%v hash=%v", oursNoPad.isRaw(), oursHash.isRaw())
	}
	if oursNoPad.isRaw() != RawStdEncoding.isRaw() {
		t.Fatalf("NoPadding-isRaw=%v RawStdEncoding-isRaw=%v", oursNoPad.isRaw(), RawStdEncoding.isRaw())
	}
	for n := 0; n <= 64; n++ {
		src := randomBytes(n)
		cases := []struct {
			name   string
			ours   *Encoding
			theirs *stdb64.Encoding
		}{
			{"NoPadding", oursNoPad, theirsNoPad},
			{"hashPad", oursHash, theirsHash},
		}
		for _, c := range cases {
			got, want := c.ours.EncodeToString(src), c.theirs.EncodeToString(src)
			if got != want {
				t.Fatalf("%s n=%d EncodeToString = %q want %q", c.name, n, got, want)
			}
			back, err := c.ours.DecodeString(want)
			wantBack, wantErr := c.theirs.DecodeString(want)
			if (err == nil) != (wantErr == nil) || !bytes.Equal(back, wantBack) {
				t.Fatalf("%s n=%d DecodeString = (%q, %v) want (%q, %v)", c.name, n, back, err, wantBack, wantErr)
			}
		}
	}
	// WithPadding can restore '=' padding on a raw encoding. |
	// WithPadding 可以把原始编码恢复为 '=' 填充。
	restored := RawStdEncoding.WithPadding(StdPadding)
	if restored.isRaw() || restored.EncodeToString([]byte("a")) != "YQ==" {
		t.Fatalf("restored raw encoding: raw=%v encoded=%q", restored.isRaw(), restored.EncodeToString([]byte("a")))
	}
}

// TestWithPaddingRejectsInvalid verifies invalid padding returns nil. | TestWithPaddingRejectsInvalid
// 验证非法填充返回 nil。
func TestWithPaddingRejectsInvalid(t *testing.T) {
	for _, p := range []rune{'A', '\n', '\r', rune(0x100), rune(-2)} {
		if enc := StdEncoding.WithPadding(p); enc != nil {
			t.Errorf("WithPadding(%q) = %v want nil", p, enc)
		}
	}
	if enc := StdEncoding.WithPadding(NoPadding); enc == nil || !enc.isRaw() {
		t.Fatalf("WithPadding(NoPadding) = %v", enc)
	}
}

// TestStrictMatchesStdlib verifies Strict rejects non-zero trailing bits at the same positions
// as encoding/base64. | TestStrictMatchesStdlib 验证 Strict 在与 encoding/base64 相同的位置拒绝
// 非零尾部填充位。
func TestStrictMatchesStdlib(t *testing.T) {
	padded := []string{"", "AA==", "AB==", "AAA=", "AAB=", "AAAA", "AQID", "AQI=", "AQ=="}
	raw := []string{"", "AA", "AB", "AAA", "AAB", "AAAA"}
	for _, in := range padded {
		got, gotErr := StdEncoding.Strict().DecodeString(in)
		want, wantErr := stdb64.StdEncoding.Strict().DecodeString(in)
		if (gotErr == nil) != (wantErr == nil) || !bytes.Equal(got, want) {
			t.Fatalf("padded %q = (%q, %v) want (%q, %v)", in, got, gotErr, want, wantErr)
		}
		if gotErr != nil {
			assertCorruptAt(t, gotErr, wantErr)
		}
	}
	for _, in := range raw {
		got, gotErr := RawStdEncoding.Strict().DecodeString(in)
		want, wantErr := stdb64.RawStdEncoding.Strict().DecodeString(in)
		if (gotErr == nil) != (wantErr == nil) || !bytes.Equal(got, want) {
			t.Fatalf("raw %q = (%q, %v) want (%q, %v)", in, got, gotErr, want, wantErr)
		}
		if gotErr != nil {
			assertCorruptAt(t, gotErr, wantErr)
		}
	}
	// Strict must not mutate the receiver. | Strict 不得修改接收者。
	if _, err := StdEncoding.DecodeString("AB=="); err != nil {
		t.Fatalf("non-strict decode after Strict: %v", err)
	}
	if _, err := RawStdEncoding.DecodeString("AB"); err != nil {
		t.Fatalf("non-strict raw decode after Strict: %v", err)
	}
}

// TestCorruptInputErrorPositions verifies invalid input reports the same byte offset as the
// standard library. | TestCorruptInputErrorPositions 验证非法输入报告与标准库相同的字节偏移。
func TestCorruptInputErrorPositions(t *testing.T) {
	encs := []struct {
		name   string
		ours   *Encoding
		theirs *stdb64.Encoding
	}{
		{"Std", StdEncoding, stdb64.StdEncoding},
		{"RawStd", RawStdEncoding, stdb64.RawStdEncoding},
		{"URL", URLEncoding, stdb64.URLEncoding},
		{"RawURL", RawURLEncoding, stdb64.RawURLEncoding},
	}
	inputs := []string{
		"A", "AA", "AAA", "AAAAA", "AA=A", "A===", "====", "AA==AA==", "!!!!", "AA!A",
		"AA=A", "AAAA=", "AA==\nA", "AAAAA\nAA", "AAA====",
	}
	for _, e := range encs {
		for _, in := range inputs {
			_, oursErr := e.ours.DecodeString(in)
			_, theirsErr := e.theirs.DecodeString(in)
			if (oursErr == nil) != (theirsErr == nil) {
				t.Fatalf("%s %q: ours=%v theirs=%v", e.name, in, oursErr, theirsErr)
			}
			if oursErr != nil {
				assertCorruptAt(t, oursErr, theirsErr)
			}
		}
	}
}

// assertCorruptAt verifies both errors are CorruptInputError with the same offset. |
// assertCorruptAt 验证两个错误都是 CorruptInputError 且偏移相同。
func assertCorruptAt(t *testing.T, ours, theirs error) {
	t.Helper()
	var got CorruptInputError
	if !errors.As(ours, &got) {
		t.Fatalf("errors.As(%v, CorruptInputError) = false", ours)
	}
	if !errors.Is(ours, ErrInvalidData) {
		t.Fatalf("errors.Is(%v, ErrInvalidData) = false", ours)
	}
	var want stdb64.CorruptInputError
	if !errors.As(theirs, &want) {
		t.Fatalf("errors.As(%v, std CorruptInputError) = false", theirs)
	}
	if int64(got) != int64(want) {
		t.Fatalf("CorruptInputError = %d want %d", int64(got), int64(want))
	}
	if got.Error() != want.Error() {
		t.Fatalf("Error() = %q want %q", got.Error(), want.Error())
	}
}

// TestStreamEncoderMatchesStdlib cross-checks the streaming encoder with several chunk sizes. |
// TestStreamEncoderMatchesStdlib 用多种分块大小与标准库对拍流式编码器。
func TestStreamEncoderMatchesStdlib(t *testing.T) {
	encs := []struct {
		name   string
		ours   *Encoding
		theirs *stdb64.Encoding
	}{
		{"Std", StdEncoding, stdb64.StdEncoding},
		{"RawStd", RawStdEncoding, stdb64.RawStdEncoding},
		{"URL", URLEncoding, stdb64.URLEncoding},
		{"RawURL", RawURLEncoding, stdb64.RawURLEncoding},
		{"NoPadding", StdEncoding.WithPadding(NoPadding), stdb64.StdEncoding.WithPadding(stdb64.NoPadding)},
		{"hashPad", StdEncoding.WithPadding('#'), stdb64.StdEncoding.WithPadding('#')},
	}
	for _, e := range encs {
		for _, n := range []int{0, 1, 2, 3, 4, 5, 31, 1024, 4097} {
			src := randomBytes(n)
			for _, chunk := range []int{1, 2, 3, 5, 7, 512, 4096} {
				var oursOut, theirsOut bytes.Buffer
				ours := NewEncoder(e.ours, &oursOut)
				theirs := stdb64.NewEncoder(e.theirs, &theirsOut)
				for off := 0; off < len(src); off += chunk {
					end := off + chunk
					if end > len(src) {
						end = len(src)
					}
					on, oerr := ours.Write(src[off:end])
					tn, terr := theirs.Write(src[off:end])
					if on != tn || (oerr == nil) != (terr == nil) {
						t.Fatalf("%s n=%d chunk=%d Write = (%d,%v) want (%d,%v)", e.name, n, chunk, on, oerr, tn, terr)
					}
				}
				if oerr, terr := ours.Close(), theirs.Close(); (oerr == nil) != (terr == nil) {
					t.Fatalf("%s n=%d chunk=%d Close = %v want %v", e.name, n, chunk, oerr, terr)
				}
				if oursOut.String() != theirsOut.String() {
					t.Fatalf("%s n=%d chunk=%d output = %q want %q", e.name, n, chunk, oursOut.String(), theirsOut.String())
				}
			}
		}
	}
}

// TestStreamEncoderWriteAfterClose verifies a closed encoder keeps returning the close result. |
// TestStreamEncoderWriteAfterClose 验证已关闭的编码器持续返回关闭结果。
func TestStreamEncoderWriteAfterClose(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(StdEncoding, &buf)
	if _, err := enc.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	want := stdb64.StdEncoding.EncodeToString([]byte("hello"))
	if buf.String() != want {
		t.Fatalf("output = %q want %q", buf.String(), want)
	}
}

// TestStreamDecoderMatchesStdlib cross-checks the streaming decoder, including CR/LF filtering. |
// TestStreamDecoderMatchesStdlib 与标准库对拍流式解码器，含 CR/LF 过滤。
func TestStreamDecoderMatchesStdlib(t *testing.T) {
	encs := []struct {
		name   string
		ours   *Encoding
		theirs *stdb64.Encoding
	}{
		{"Std", StdEncoding, stdb64.StdEncoding},
		{"RawStd", RawStdEncoding, stdb64.RawStdEncoding},
		{"URL", URLEncoding, stdb64.URLEncoding},
		{"RawURL", RawURLEncoding, stdb64.RawURLEncoding},
		{"NoPadding", StdEncoding.WithPadding(NoPadding), stdb64.StdEncoding.WithPadding(stdb64.NoPadding)},
		{"hashPad", StdEncoding.WithPadding('#'), stdb64.StdEncoding.WithPadding('#')},
	}
	for _, e := range encs {
		for _, n := range []int{0, 1, 2, 3, 4, 5, 6, 7, 100, 1024, 4097} {
			src := randomBytes(n)
			text := e.theirs.EncodeToString(src)
			// Insert CR/LF to exercise the newline filter. | 插入 CR/LF 以覆盖换行过滤。
			var b strings.Builder
			for i := 0; i < len(text); i += 4 {
				end := i + 4
				if end > len(text) {
					end = len(text)
				}
				b.WriteString(text[i:end])
				if i%8 == 0 {
					b.WriteString("\r\n")
				} else {
					b.WriteByte('\n')
				}
			}
			encoded := b.String()
			for _, chunk := range []int{1, 4, 5, 7, 1024} {
				got, gotErr := io.ReadAll(NewDecoder(e.ours, &chunkReader{s: encoded, chunk: chunk}))
				want, wantErr := io.ReadAll(stdb64.NewDecoder(e.theirs, &chunkReader{s: encoded, chunk: chunk}))
				if (gotErr == nil) != (wantErr == nil) || !bytes.Equal(got, want) {
					t.Fatalf("%s n=%d chunk=%d ReadAll = (%x, %v) want (%x, %v)", e.name, n, chunk, got, gotErr, want, wantErr)
				}
			}
		}
	}
}

// TestStreamDecoderInvalid verifies invalid stream input reports CorruptInputError. |
// TestStreamDecoderInvalid 验证非法流输入报告 CorruptInputError。
func TestStreamDecoderInvalid(t *testing.T) {
	for _, in := range []string{"!!!!", "AA!A", "ABCD=", "A"} {
		gotErr := readAllErr(NewDecoder(StdEncoding, strings.NewReader(in)))
		wantErr := readAllErr(stdb64.NewDecoder(stdb64.StdEncoding, strings.NewReader(in)))
		if (gotErr == nil) != (wantErr == nil) {
			t.Fatalf("%q: ours=%v theirs=%v", in, gotErr, wantErr)
		}
		if gotErr == nil {
			continue
		}
		var got CorruptInputError
		var want stdb64.CorruptInputError
		if !errors.As(wantErr, &want) {
			// The standard library reports truncated input as io.ErrUnexpectedEOF; the ydx
			// decoder must agree rather than invent a CorruptInputError. | 标准库把截断输入报告为
			// io.ErrUnexpectedEOF；ydx 解码器必须一致，不能自造 CorruptInputError。
			if errors.Is(wantErr, io.ErrUnexpectedEOF) {
				if !errors.Is(gotErr, io.ErrUnexpectedEOF) {
					t.Fatalf("%q: error = %v want io.ErrUnexpectedEOF", in, gotErr)
				}
				continue
			}
			t.Fatalf("%q: std error %v is not CorruptInputError", in, wantErr)
		}
		if !errors.As(gotErr, &got) {
			t.Fatalf("%q: %v is not CorruptInputError", in, gotErr)
		}
		if int64(got) != int64(want) {
			t.Fatalf("%q: position = %d want %d", in, int64(got), int64(want))
		}
	}
}

// readAllErr discards the payload and returns the read error. | readAllErr 丢弃数据并返回读取错误。
func readAllErr(r io.Reader) error {
	_, err := io.ReadAll(r)
	return err
}

// chunkReader returns data in fixed-size pieces, exercising the decoder's refill paths. |
// chunkReader 按固定大小分片返回数据，覆盖解码器的补充读取路径。
type chunkReader struct {
	s     string
	chunk int
	off   int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if r.off >= len(r.s) {
		return 0, io.EOF
	}
	n := r.chunk
	if n > len(p) {
		n = len(p)
	}
	if n > len(r.s)-r.off {
		n = len(r.s) - r.off
	}
	copy(p, r.s[r.off:r.off+n])
	r.off += n
	return n, nil
}
