//go:build !race

package regexpx

// raceEnabled reports whether the test binary was built with the race detector. | raceEnabled
// 报告测试二进制是否启用了竞态检测。
const raceEnabled = false
