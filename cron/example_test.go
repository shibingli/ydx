package cron_test

import (
	"fmt"
	"time"

	"github.com/shibingli/ydx/cron"
)

// ExampleParse shows the public schedule API and the POSIX day rule. |
// ExampleParse 展示公开调度 API 与 POSIX 日期规则。
func ExampleParse() {
	schedule := cron.MustParseIn("*/5 9-17 * * MON-FRI", time.UTC)
	start := time.Date(2026, time.January, 1, 8, 58, 0, 0, time.UTC)
	fmt.Println(schedule.Next(start).Format(time.RFC3339))
	// Output: 2026-01-01T09:00:00Z
}
