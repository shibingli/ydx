//go:build race

package regexpx

// raceEnabled reports whether the test binary was built with the race detector. Allocation
// assertions are skipped under -race because the detector changes pool behavior and always-on
// instrumentation. | raceEnabled 报告测试二进制是否启用了竞态检测。竞态检测会改变池行为并加入
// 始终启用的插桩，因此在 -race 下跳过分配断言。
const raceEnabled = true
