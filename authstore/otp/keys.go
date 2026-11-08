package otp

import "strconv"

// keys builds every key below one configurable namespace. | keys 在一个可配置命名空间下构造所有键。
type keys struct {
	// prefix is the caller-configured namespace. | prefix 是调用方配置的命名空间。
	prefix string
}

// newKeys returns a key builder for prefix. | newKeys 返回 prefix 的键构造器。
func newKeys(prefix string) keys {
	return keys{prefix: prefix}
}

// replay is the string key recording one accepted (key, step) pair. | replay 是记录单个已接受
// (key, step) 键值对的字符串键。
func (k keys) replay(key string, step int64) string {
	return k.prefix + redisTag + ":replay:" + segment(key) + ":" + strconv.FormatInt(step, 10)
}

// segment length-prefixes an arbitrary value so concatenated segments stay unambiguous.
// | segment 为任意值添加长度前缀，使拼接后的段保持无歧义。
func segment(value string) string {
	return strconv.Itoa(len(value)) + ":" + value
}
