package base64

import (
	"bytes"
	stdb64 "encoding/base64"
	"io"
	"strings"
	"testing"
)

// unicodeInputs covers CJK, emoji (including ZWJ sequences), RTL text, combining marks,
// metacharacters, line separators and invalid UTF-8 bytes. | unicodeInputs 覆盖 CJK、表情符号
// （含 ZWJ 组合）、RTL 文本、组合附加符、元字符、行分隔符与非法 UTF-8 字节。
func unicodeInputs() [][]byte {
	return [][]byte{
		{},
		[]byte("中文测试"),
		[]byte("日本語と韓国語"),
		[]byte("😀🚀🎉👨‍👩‍👧‍👦"),
		[]byte("مرحبا بالعالم"),
		[]byte("é"),
		[]byte(`<>"'&\\/+`),
		[]byte("  "),
		{0xff, 0xfe, 0x80, 0x00, 0x01},
		[]byte("mixed 中文😀 <&> \\/ end"),
	}
}

// TestUnicodePayloadsMatchStdlib cross-checks every encoding variant against encoding/base64
// for non-ASCII and special-byte payloads, including all three padding residues. |
// TestUnicodePayloadsMatchStdlib 用非 ASCII 与特殊字节载荷对拍全部编码变体，并覆盖三种填充余数。
func TestUnicodePayloadsMatchStdlib(t *testing.T) {
	variants := []struct {
		name string
		enc  *Encoding
		std  *stdb64.Encoding
	}{
		{"std", StdEncoding, stdb64.StdEncoding},
		{"raw_std", RawStdEncoding, stdb64.RawStdEncoding},
		{"url", URLEncoding, stdb64.URLEncoding},
		{"raw_url", RawURLEncoding, stdb64.RawURLEncoding},
		{"no_padding", StdEncoding.WithPadding(NoPadding), stdb64.StdEncoding.WithPadding(stdb64.NoPadding)},
		{"hash_padding", StdEncoding.WithPadding('#'), stdb64.StdEncoding.WithPadding('#')},
	}
	for _, v := range variants {
		for _, base := range unicodeInputs() {
			for pad := 0; pad < 3; pad++ {
				src := append(append([]byte(nil), base...), bytes.Repeat([]byte{'x'}, pad)...)
				enc := make([]byte, v.enc.EncodedLen(len(src)))
				v.enc.Encode(enc, src)
				stdEnc := make([]byte, v.std.EncodedLen(len(src)))
				v.std.Encode(stdEnc, src)
				if !bytes.Equal(enc, stdEnc) {
					t.Fatalf("%s len=%d: Encode = %q want %q", v.name, len(src), enc, stdEnc)
				}
				back := make([]byte, v.enc.DecodedLen(len(enc)))
				n, err := v.enc.Decode(back, enc)
				if err != nil || !bytes.Equal(back[:n], src) {
					t.Fatalf("%s len=%d: Decode = (%q, %v)", v.name, len(src), back[:n], err)
				}
				if got, want := v.enc.EncodeToString(src), v.std.EncodeToString(src); got != want {
					t.Fatalf("%s len=%d: EncodeToString differs", v.name, len(src))
				}
				got, err := v.enc.DecodeString(string(stdEnc))
				want, wantErr := v.std.DecodeString(string(stdEnc))
				if (err == nil) != (wantErr == nil) || !bytes.Equal(got, want) {
					t.Fatalf("%s len=%d: DecodeString = (%q, %v) want (%q, %v)", v.name, len(src), got, err, want, wantErr)
				}
				// Append entry points must produce the same bytes. | 追加式入口必须产生相同字节。
				gotApp := v.enc.AppendEncode(nil, src)
				wantApp := v.std.AppendEncode(nil, src)
				if !bytes.Equal(gotApp, wantApp) {
					t.Fatalf("%s len=%d: AppendEncode differs", v.name, len(src))
				}
				gotDec, err := v.enc.AppendDecode(nil, stdEnc)
				if err != nil || !bytes.Equal(gotDec, src) {
					t.Fatalf("%s len=%d: AppendDecode = (%q, %v)", v.name, len(src), gotDec, err)
				}
			}
		}
	}
}

// TestUnicodeStreamingMatchesStdlib cross-checks the streaming codecs with unicode payloads. |
// TestUnicodeStreamingMatchesStdlib 用 Unicode 载荷对拍流式编解码器。
func TestUnicodeStreamingMatchesStdlib(t *testing.T) {
	for _, src := range unicodeInputs() {
		var ourBuf, stdBuf bytes.Buffer
		ourEnc := NewEncoder(StdEncoding, &ourBuf)
		stdEnc := stdb64.NewEncoder(stdb64.StdEncoding, &stdBuf)
		for off := 0; off < len(src); off += 3 {
			end := off + 3
			if end > len(src) {
				end = len(src)
			}
			if _, err := ourEnc.Write(src[off:end]); err != nil {
				t.Fatalf("ydx Write: %v", err)
			}
			if _, err := stdEnc.Write(src[off:end]); err != nil {
				t.Fatalf("std Write: %v", err)
			}
		}
		if err := ourEnc.Close(); err != nil {
			t.Fatalf("ydx Close: %v", err)
		}
		if err := stdEnc.Close(); err != nil {
			t.Fatalf("std Close: %v", err)
		}
		if ourBuf.String() != stdBuf.String() {
			t.Fatalf("stream output = %q want %q", ourBuf.String(), stdBuf.String())
		}
		var wrapped strings.Builder
		encoded := stdBuf.String()
		for i := 0; i < len(encoded); i += 4 {
			end := i + 4
			if end > len(encoded) {
				end = len(encoded)
			}
			wrapped.WriteString(encoded[i:end])
			wrapped.WriteString("\r\n")
		}
		ourBack, ourErr := io.ReadAll(NewDecoder(StdEncoding, strings.NewReader(wrapped.String())))
		stdBack, stdErr := io.ReadAll(stdb64.NewDecoder(stdb64.StdEncoding, strings.NewReader(wrapped.String())))
		if (ourErr == nil) != (stdErr == nil) || !bytes.Equal(ourBack, stdBack) {
			t.Fatalf("stream decode = (%q, %v) want (%q, %v)", ourBack, ourErr, stdBack, stdErr)
		}
	}
}
