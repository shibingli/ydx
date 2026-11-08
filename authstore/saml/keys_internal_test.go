package saml

import (
	"strings"
	"testing"
)

// TestSegmentIsUnambiguous verifies that length prefixes make arbitrary segments injective and
// prefix-free. | TestSegmentIsUnambiguous 验证长度前缀使任意键段既单射又无前缀关系。
func TestSegmentIsUnambiguous(t *testing.T) {
	values := []string{"", "a", "ab", "1:a", "0:", "2:ab", "a:b", "\x00", "\x00\xff", "10:xxxxxxxxxx"}
	encoded := make(map[string]string, len(values))
	for _, value := range values {
		got := segment(value)
		if previous, ok := encoded[got]; ok {
			t.Fatalf("segment(%q) collides with segment(%q) | 键段编码冲突", value, previous)
		}
		encoded[got] = value
		if !strings.HasSuffix(got, value) {
			t.Fatalf("segment(%q) = %q does not end with the value | 键段编码未包含原值", value, got)
		}
	}
	for left, leftValue := range encoded {
		for right, rightValue := range encoded {
			if left == right {
				continue
			}
			if strings.HasPrefix(left, right) {
				t.Fatalf("segment(%q) = %q is a prefix of segment(%q) = %q | 键段编码存在前缀关系",
					leftValue, left, rightValue, right)
			}
		}
	}
	if got := segment(""); got != "0:" {
		t.Fatalf("segment(\"\") = %q, want 0: | 空键段编码不符", got)
	}
	if got := segment("a:b"); got != "3:a:b" {
		t.Fatalf("segment(\"a:b\") = %q, want 3:a:b | 冒号键段编码不符", got)
	}
}

// hashTagOf returns the cluster hash tag of key and validates its shape.
// | hashTagOf 返回键的集群哈希标签并校验其形态。
func hashTagOf(t *testing.T, key string) string {
	t.Helper()
	open := strings.IndexByte(key, '{')
	close := strings.IndexByte(key, '}')
	if open < 0 || close < 0 || close <= open+1 {
		t.Fatalf("key %q has no usable hash tag | 键没有可用哈希标签", key)
	}
	tag := key[open : close+1]
	if strings.Count(key, "{") != 1 || strings.Count(key, "}") != 1 {
		t.Fatalf("key %q has more than one hash tag | 键存在多个哈希标签", key)
	}
	return tag
}

// TestHashTagsKeepScriptsInOneSlot verifies that each category shares one tag and categories use
// distinct tags. | TestHashTagsKeepScriptsInOneSlot 验证每个类别共享一个标签，且类别之间标签不同。
func TestHashTagsKeepScriptsInOneSlot(t *testing.T) {
	builder := newKeys("tenant:")
	categories := map[string][]string{
		"requests":   {builder.request("id"), builder.requestsExpiry()},
		"assertions": {builder.assertion("id"), builder.assertionsExpiry()},
		"sessions":   {builder.session("id"), builder.sessionsBySubject("alice"), builder.sessionsExpiry()},
		"artifacts":  {builder.artifact("key"), builder.artifactsExpiry()},
	}
	tags := make(map[string]string, len(categories))
	for category, categoryKeys := range categories {
		want := hashTagOf(t, categoryKeys[0])
		for _, key := range categoryKeys {
			if !strings.HasPrefix(key, "tenant:") {
				t.Fatalf("%s key %q lost the namespace | %s 键丢失命名空间", category, key, category)
			}
			if got := hashTagOf(t, key); got != want {
				t.Fatalf("%s key %q tag = %s, want %s | 同类键哈希标签不一致", category, key, got, want)
			}
		}
		tags[category] = want
	}
	seen := make(map[string]string, len(tags))
	for category, tag := range tags {
		if other, ok := seen[tag]; ok {
			t.Fatalf("categories %s and %s share tag %s | 不同类别共享哈希标签", category, other, tag)
		}
		seen[tag] = category
	}
}

// TestSessionSubjectKeyMatchesLua verifies that Go and Lua build identical subject set keys.
// | TestSessionSubjectKeyMatchesLua 验证 Go 与 Lua 构造出相同的主体集合键。
func TestSessionSubjectKeyMatchesLua(t *testing.T) {
	builder := newKeys("tenant:")
	for _, nameID := range []string{"", "alice", "a:b", "10:xxxxxxxxxx", "\x00\xff"} {
		want := builder.sessionsBySubject(nameID)
		got := builder.sessionSubjectPrefix() + segment(nameID)
		if got != want {
			t.Fatalf("subject key = %q, want %q | 主体集合键与 Lua 构造不一致", got, want)
		}
	}
}

// TestKeyLayout pins the exact key layout used on the wire.
// | TestKeyLayout 固定线上使用的精确键布局。
func TestKeyLayout(t *testing.T) {
	builder := newKeys("tenant:")
	cases := map[string]string{
		builder.request("req"):             "tenant:{authstore:saml:requests}:request:3:req",
		builder.requestsExpiry():           "tenant:{authstore:saml:requests}:expiry",
		builder.assertion("sso"):           "tenant:{authstore:saml:assertions}:assertion:3:sso",
		builder.assertionsExpiry():         "tenant:{authstore:saml:assertions}:expiry",
		builder.session("sid"):             "tenant:{authstore:saml:sessions}:session:3:sid",
		builder.sessionsBySubject("alice"): "tenant:{authstore:saml:sessions}:subject:5:alice",
		builder.sessionsExpiry():           "tenant:{authstore:saml:sessions}:expiry",
		builder.artifact("artifact-key"):   "tenant:{authstore:saml:artifacts}:artifact:12:artifact-key",
		builder.artifactsExpiry():          "tenant:{authstore:saml:artifacts}:expiry",
	}
	for got, want := range cases {
		if got != want {
			t.Fatalf("key = %q, want %q | 键布局不符", got, want)
		}
	}
	defaultKey := newKeys(DefaultKeyPrefix).request("req")
	if defaultKey != "ydx:authstore:saml:{authstore:saml:requests}:request:3:req" {
		t.Fatalf("default prefix key = %q | 默认前缀键布局不符", defaultKey)
	}
}
