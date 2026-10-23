//go:build jsonx_std

package json

// prewarm is a no-op for the standard-library backend, which keeps its own caches. | prewarm 在
// 标准库后端下为空操作，该后端维护自己的缓存。
func prewarm(...any) {}
