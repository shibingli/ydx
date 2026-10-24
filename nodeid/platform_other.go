//go:build !linux && !windows && !darwin

package nodeid

// platformFacts returns no facts on other operating systems. | platformFacts 在其它操作系统
// 不返回事实。
func platformFacts() (string, string) { return "", "" }

// platformSeed has no seed on other operating systems; Resolve generates a
// random id and persists it. | platformSeed 在其它操作系统没有种子；Resolve 会生成随机 id 并
// 持久化。
func platformSeed(Environment, bool) (Source, string, bool) { return "", "", false }

// durablePath returns true on other operating systems; the common
// temporary-directory check still applies. | durablePath 在其它操作系统返回 true；通用临时
// 目录检查仍然生效。
func durablePath(string) bool { return true }
