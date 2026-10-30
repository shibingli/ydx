package redis

import (
	"io"
	"os"
	"testing"

	ydlog "github.com/shibingli/ydx/log"
)

// TestMain silences the default logger so expected failure paths do not pollute
// the test output. | TestMain 关闭默认日志器，避免预期内的失败路径污染测试输出。
func TestMain(m *testing.M) {
	ydlog.SetDefault(ydlog.New(ydlog.Options{Writer: io.Discard, Level: ydlog.FatalLevel}))
	os.Exit(m.Run())
}
