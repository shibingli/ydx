package waf

import "testing"

func TestTransforms(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"urlDecode", "%41%42+c", "AB+c"},
		{"urlDecodeUni", "%u0041%uFF21%E4%B8%AD", "AA中"},
		{"htmlEntityDecode", "&lt;script&gt;&#x41;&#66;&colon;", "<script>AB:"},
		{"jsDecode", `\x41B\u{1F600}`, "AB\U0001F600"},
		{"cssDecode", `\41 \42`, "AB"},
		{"base64Decode", "aGVsbG8=", "hello"},
		{"base64DecodeExt", "aGVsbG8", "hello"},
		{"base64Encode", "hello", "aGVsbG8="},
		{"hexDecode", "68656c6c6f", "hello"},
		{"hexEncode", "hello", "68656c6c6f"},
		{"normalizePath", "/a//b/../c/", "/a/c/"},
		{"normalizePathWin", `\a\..\b`, "/b"},
		{"compressWhitespace", " a \t b\n c ", " a b c "},
		{"removeWhitespace", " a b ", "ab"},
		{"removeComments", "a/*x*/b<!--y-->c", "abc"},
		{"removeCommentsChar", "a/*x*/b<!--y-->c", "axbyc"},
		{"replaceComments", "a/*x*/b", "a b"},
		{"cmdLine", `CMD /C "A B"`, `cmd /c "a b"`},
		{"trim", "  x  ", "x"},
		{"trimLeft", "  x  ", "x  "},
		{"trimRight", "  x  ", "  x"},
		{"lowercase", "AbC", "abc"},
		{"uppercase", "AbC", "ABC"},
		{"length", "中文", "6"},
		{"md5", "abc", "900150983cd24fb0d6963f7d28e17f72"},
		{"sha1", "abc", "a9993e364706816aba3e25717850c26c9cd0d89d"},
		{"sha256", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"crc32", "abc", "891568578"},
		{"utf8toUnicode", "中", "%u4E2D"},
		{"urlEncode", "a b", "a%20b"},
		{"sqlHexDecode", "0x68656c6c6f", "hello"},
		{"escapeSeqDecode", `\x41\102`, "AB"},
		{"removeNulls", "a\x00b", "ab"},
		{"replaceNulls", "a\x00b", "a b"},
		{"none", "AbC", "AbC"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry, ok := lookupTransform(test.name)
			if !ok {
				t.Fatalf("transform %q not found", test.name)
			}
			if got := entry.fn(test.input); got != test.want {
				t.Fatalf("%s(%q) = %q, want %q", test.name, test.input, got, test.want)
			}
		})
	}
}

func TestTransformUnknown(t *testing.T) {
	if _, ok := lookupTransform("not-a-transform"); ok {
		t.Fatal("unknown transform resolved")
	}
}
