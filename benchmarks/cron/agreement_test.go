package cron

import (
	"testing"
	"time"

	robfig "github.com/robfig/cron/v3"

	yd "github.com/shibingli/ydx/cron"
)

// TestNextAgreesWithRobfig checks that every shared syntax form produces the
// same activation sequence as robfig/cron. It is the correctness gate behind
// the Next benchmark: a faster implementation that disagrees is a regression. |
// TestNextAgreesWithRobfig 校验所有共享语法与 robfig/cron 产生相同的触发序列。
// 它是 Next 基准的正确性门禁：更快但不一致的实现属于回归。
func TestNextAgreesWithRobfig(t *testing.T) {
	cases := []struct {
		name   string
		expr   string
		fields int
	}{
		{name: "minutes", expr: "*/5 * * * *", fields: 5},
		{name: "business", expr: "0 9-17 * * MON-FRI", fields: 5},
		{name: "lists", expr: "15 2 * * 1,3,5", fields: 5},
		{name: "months", expr: "0 0 1 JAN-MAR *", fields: 5},
		{name: "leap_day", expr: "0 0 29 2 *", fields: 5},
		{name: "day_or", expr: "0 0 13 * FRI", fields: 5},
		{name: "seconds", expr: "*/10 * * * * *", fields: 6},
		{name: "seconds_range", expr: "0 0/15 9-17 * * MON-FRI", fields: 6},
		{name: "daily", expr: "@daily", fields: 5},
		{name: "hourly", expr: "@hourly", fields: 5},
	}
	start := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.Local)
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			mine, err := yd.ParseIn(tc.expr, time.Local)
			if err != nil {
				t.Fatalf("ydx ParseIn(%q): %v", tc.expr, err)
			}
			var theirs robfig.Schedule
			if tc.fields == 6 {
				theirs, err = robfigSecondsParser.Parse(tc.expr)
			} else {
				theirs, err = robfig.ParseStandard(tc.expr)
			}
			if err != nil {
				t.Fatalf("robfig parse(%q): %v", tc.expr, err)
			}

			at := start
			for step := 0; step < 200; step++ {
				got := mine.Next(at)
				want := theirs.Next(at)
				if !got.Equal(want) {
					t.Fatalf("step %d: ydx Next = %s, robfig Next = %s | 第 %d 步不一致",
						step, got.Format(time.RFC3339), want.Format(time.RFC3339), step)
				}
				if got.IsZero() {
					return
				}
				at = got
			}
		})
	}
}
