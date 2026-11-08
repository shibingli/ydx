package kmip

import (
	"strings"
	"testing"
)

// TestDefaultKeyLayout verifies the documented key names for a record and the index.
// | TestDefaultKeyLayout 验证文档化的记录键与索引键名称。
func TestDefaultKeyLayout(t *testing.T) {
	k := newKeys(DefaultKeyPrefix)
	if got, want := k.all(), "ydx:authstore:kmip:{authstore:kmip}:all"; got != want {
		t.Fatalf("all key = %q, want %q", got, want)
	}
	if got, want := k.object("obj"), "ydx:authstore:kmip:{authstore:kmip}:object:3:obj"; got != want {
		t.Fatalf("object key = %q, want %q", got, want)
	}
	if got, want := k.object(""), "ydx:authstore:kmip:{authstore:kmip}:object:0:"; got != want {
		t.Fatalf("empty object key = %q, want %q", got, want)
	}
}

// TestCustomKeyPrefix verifies that the caller prefix precedes the shared hash tag.
// | TestCustomKeyPrefix 验证调用方前缀位于共享哈希标签之前。
func TestCustomKeyPrefix(t *testing.T) {
	k := newKeys("myapp:kmip:")
	if got, want := k.all(), "myapp:kmip:{authstore:kmip}:all"; got != want {
		t.Fatalf("all key = %q, want %q", got, want)
	}
	if got, want := k.object("a"), "myapp:kmip:{authstore:kmip}:object:1:a"; got != want {
		t.Fatalf("object key = %q, want %q", got, want)
	}
}

// TestKeyLengthPrefixPreventsCollisions verifies that different identifiers never share an object
// key. | TestKeyLengthPrefixPreventsCollisions 验证不同标识符绝不共享对象键。
func TestKeyLengthPrefixPreventsCollisions(t *testing.T) {
	k := newKeys(DefaultKeyPrefix)
	pairs := [][2]string{
		{"1:a", "a"},
		{"a:b", "a"},
		{"a", ""},
		{"10:x", "1:0:x"},
		{"ab", "a"},
	}
	for _, pair := range pairs {
		firstKey := k.object(pair[0])
		secondKey := k.object(pair[1])
		if firstKey == secondKey {
			t.Fatalf("identifiers %q and %q collided on key %q", pair[0], pair[1], firstKey)
		}
	}
}

// TestSharedHashTag verifies that every key carries exactly one identical cluster hash tag, so one
// script always stays in one Redis Cluster slot. | TestSharedHashTag 验证每个键恰有一个相同的集群
// 哈希标签，因此单个脚本始终位于一个 Redis Cluster 槽位。
func TestSharedHashTag(t *testing.T) {
	for _, prefix := range []string{DefaultKeyPrefix, "custom:"} {
		k := newKeys(prefix)
		keys := []string{k.all(), k.object("one"), k.object("two:with:colons"), k.object("")}
		tag := ""
		for _, key := range keys {
			if strings.Count(key, "{") != 1 || strings.Count(key, "}") != 1 {
				t.Fatalf("key %q does not carry exactly one hash tag", key)
			}
			start := strings.IndexByte(key, '{')
			end := strings.IndexByte(key, '}')
			if start > end {
				t.Fatalf("key %q has a malformed hash tag", key)
			}
			current := key[start+1 : end]
			if tag == "" {
				tag = current
			} else if current != tag {
				t.Fatalf("key %q hash tag = %q, want %q", key, current, tag)
			}
		}
		if tag != "authstore:kmip" {
			t.Fatalf("hash tag = %q, want %q", tag, "authstore:kmip")
		}
	}
}

// TestKeysPrefixIsolation verifies that prefixes never produce the same key.
// | TestKeysPrefixIsolation 验证不同前缀绝不产生相同键。
func TestKeysPrefixIsolation(t *testing.T) {
	first := newKeys("app-a:")
	second := newKeys("app-b:")
	if first.all() == second.all() {
		t.Fatal("different prefixes produced the same index key")
	}
	if first.object("same") == second.object("same") {
		t.Fatal("different prefixes produced the same object key")
	}
}

// TestSegment verifies the length-prefix encoding. | TestSegment 验证长度前缀编码。
func TestSegment(t *testing.T) {
	cases := map[string]string{
		"":    "0:",
		"a":   "1:a",
		"abc": "3:abc",
		"a:b": "3:a:b",
		"中文":  "6:中文",
	}
	for value, want := range cases {
		if got := segment(value); got != want {
			t.Fatalf("segment(%q) = %q, want %q", value, got, want)
		}
	}
}
