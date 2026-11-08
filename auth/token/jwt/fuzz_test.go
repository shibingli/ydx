package jwt

import (
	"testing"
)

// FuzzParseNeverPanics checks that malformed compact tokens never panic the parser. |
// FuzzParseNeverPanics 校验非法紧凑令牌不会使解析器 panic。
func FuzzParseNeverPanics(f *testing.F) {
	key := []byte("0123456789abcdef0123456789abcdef")
	valid, err := Sign(map[string]any{"sub": "fuzz", "exp": int64(4102444800)}, key, HS256, SignOptions{})
	if err != nil {
		f.Fatalf("Sign seed: %v", err)
	}
	for _, seed := range []string{
		"",
		".",
		"..",
		"e30.e30.",
		"eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.",
		"eyJhbGciOiJIUzI1NiIsImNyaXQiOlsiZXhwIl19.e30.",
		"eyJhbGciOiJIUzI1NiJ9.W10.",
		valid,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, token string) {
		if len(token) > DefaultMaxTokenSize+1 {
			return
		}
		_, _ = Parse(token, func(Header) (any, error) { return key, nil }, ParseOptions{})
	})
}

// FuzzSignJSONNeverPanics checks that arbitrary payload bytes never panic the signer. |
// FuzzSignJSONNeverPanics 校验任意载荷字节不会使签名器 panic。
func FuzzSignJSONNeverPanics(f *testing.F) {
	key := []byte("0123456789abcdef0123456789abcdef")
	for _, seed := range [][]byte{
		nil,
		[]byte(`{}`),
		[]byte(`{"sub":"fuzz"}`),
		[]byte(`{"a":[1,2,3]}`),
		[]byte(`{"x":[}}`),
		[]byte(`{"a":1 "b":2}`),
		[]byte(`[1 2]`),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 1<<20 {
			return
		}
		_, _ = SignJSON(payload, key, HS256, SignOptions{})
	})
}
