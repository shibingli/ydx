package wsfed

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

// namespaced returns one key carrying the shared cluster hash tag.
// | namespaced 返回携带共享集群哈希标签的单个键。
func (k keys) namespaced(suffix string) string {
	return k.prefix + redisTag + ":" + suffix
}

// request is the string key holding one outstanding request state. | request 是保存单个未完成
// 请求状态的字符串键。
func (k keys) request(wctx string) string {
	return k.namespaced("request:" + segment(wctx))
}

// segment length-prefixes an arbitrary value so concatenated segments stay unambiguous.
// | segment 为任意值添加长度前缀，使拼接后的段保持无歧义。
func segment(value string) string {
	return strconv.Itoa(len(value)) + ":" + value
}
