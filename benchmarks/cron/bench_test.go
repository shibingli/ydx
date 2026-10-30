package cron

import (
	"testing"
	"time"

	"github.com/adhocore/gronx"
	robfig "github.com/robfig/cron/v3"

	yd "github.com/shibingli/ydx/cron"
)

// benchSink* keep results observable so the compiler cannot elide the work. |
// benchSink* 让结果保持可观测，避免编译器消除被测工作。
var (
	benchSinkSchedule yd.Schedule
	benchSinkRobfig   robfig.Schedule
	benchSinkTime     time.Time
	benchSinkBool     bool
	benchSinkError    error
)

// parseCase is one expression shared by the parsers. fields is 5 or 6; quartz
// marks forms only ydx supports. | parseCase 是各解析器共享的表达式；fields 为 5 或 6，
// quartz 标记仅 ydx 支持的形式。
type parseCase struct {
	name   string
	expr   string
	fields int
	quartz bool
}

// parseCases covers the common shapes: five fields, six fields with seconds,
// names, descriptors and the Quartz-only special forms. | parseCases 覆盖常见形态：
// 五字段、带秒六字段、名称、描述符与仅 Quartz 的特殊形式。
var parseCases = []parseCase{
	{name: "std5", expr: "*/5 9-17 * * MON-FRI", fields: 5},
	{name: "seconds6", expr: "*/10 * * * * *", fields: 6},
	{name: "names", expr: "0 0 1 JAN-MAR MON", fields: 5},
	{name: "daily", expr: "@daily"},
	{name: "every", expr: "@every 90s"},
	{name: "quartz_lastday", expr: "0 0 12 L * *", fields: 5, quartz: true},
	{name: "quartz_nth", expr: "0 0 12 ? * FRI#3", fields: 5, quartz: true},
}

// robfigSecondsParser accepts the six-field form and descriptors. |
// robfigSecondsParser 接受六字段形式与描述符。
var robfigSecondsParser = robfig.NewParser(
	robfig.Second | robfig.Minute | robfig.Hour | robfig.Dom | robfig.Month | robfig.Dow | robfig.Descriptor,
)

// robfigParse parses a shared case with the matching robfig parser. |
// robfigParse 用匹配的 robfig 解析器解析共享用例。
func robfigParse(tc parseCase) (robfig.Schedule, error) {
	if tc.fields == 6 {
		return robfigSecondsParser.Parse(tc.expr)
	}
	return robfig.ParseStandard(tc.expr)
}

// BenchmarkParse compares building a reusable schedule from an expression. |
// BenchmarkParse 对比从表达式构建可复用调度的成本。
func BenchmarkParse(b *testing.B) {
	for _, tc := range parseCases {
		tc := tc
		if _, err := yd.ParseIn(tc.expr, time.UTC); err != nil {
			b.Fatalf("ydx ParseIn(%q): %v", tc.expr, err)
		}
		b.Run("ydx/"+tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				schedule, err := yd.ParseIn(tc.expr, time.UTC)
				if err != nil {
					b.Fatal(err)
				}
				benchSinkSchedule = schedule
			}
		})
		if tc.quartz {
			continue
		}
		if _, err := robfigParse(tc); err != nil {
			b.Fatalf("robfig parse(%q): %v", tc.expr, err)
		}
		b.Run("robfig/"+tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				schedule, err := robfigParse(tc)
				if err != nil {
					b.Fatal(err)
				}
				benchSinkRobfig = schedule
			}
		})
	}
}

// nextCase is one parsed schedule shared by the Next benchmarks. |
// nextCase 是 Next 基准共享的已解析调度。
type nextCase struct {
	name   string
	expr   string
	fields int
	quartz bool
}

// nextCases covers minute, second, descriptor and Quartz schedules. |
// nextCases 覆盖分钟、秒、描述符与 Quartz 调度。
var nextCases = []nextCase{
	{name: "minutes", expr: "*/5 * * * *", fields: 5},
	{name: "business", expr: "0 9-17 * * MON-FRI", fields: 5},
	{name: "seconds", expr: "*/10 * * * * *", fields: 6},
	{name: "daily", expr: "@daily"},
	{name: "every", expr: "@every 90s"},
	{name: "quartz_lastday", expr: "0 0 12 L * *", fields: 5, quartz: true},
	{name: "quartz_nth", expr: "0 0 12 ? * FRI#3", fields: 5, quartz: true},
	{name: "quartz_nearest", expr: "0 0 12 15W * *", fields: 5, quartz: true},
}

// BenchmarkNext measures computing the next activation from a parsed schedule. |
// BenchmarkNext 测量从已解析调度计算下次触发时刻的成本。
func BenchmarkNext(b *testing.B) {
	after := time.Date(2026, time.January, 1, 8, 0, 0, 0, time.UTC)
	for _, tc := range nextCases {
		tc := tc
		ydSchedule, err := yd.ParseIn(tc.expr, time.UTC)
		if err != nil {
			b.Fatalf("ydx ParseIn(%q): %v", tc.expr, err)
		}
		if ydSchedule.Next(after).IsZero() {
			b.Fatalf("ydx Next(%q) is zero", tc.expr)
		}
		b.Run("ydx/"+tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				benchSinkTime = ydSchedule.Next(after)
			}
		})
		if tc.quartz {
			continue
		}
		roSchedule, err := robfigParse(parseCase{expr: tc.expr, fields: tc.fields})
		if err != nil {
			b.Fatalf("robfig parse(%q): %v", tc.expr, err)
		}
		if roSchedule.Next(after).IsZero() {
			b.Fatalf("robfig Next(%q) is zero", tc.expr)
		}
		b.Run("robfig/"+tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				benchSinkTime = roSchedule.Next(after)
			}
		})
		if tc.expr[0] != '@' {
			b.Run("gronx/"+tc.name+"_parse_next", func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					next, err := gronx.NextTickAfter(tc.expr, after, false)
					if err != nil {
						b.Fatal(err)
					}
					benchSinkTime = next
				}
			})
		}
	}
}

// BenchmarkNextWalk advances the reference time with each result, mirroring the
// scheduler loop instead of recomputing from a fixed instant. |
// BenchmarkNextWalk 用结果推进参考时间，模拟调度循环，而不是从固定时刻重算。
func BenchmarkNextWalk(b *testing.B) {
	cases := []struct {
		name   string
		expr   string
		fields int
	}{
		{name: "minutes", expr: "*/5 * * * *", fields: 5},
		{name: "business", expr: "0 9-17 * * MON-FRI", fields: 5},
		{name: "seconds", expr: "*/10 * * * * *", fields: 6},
	}
	for _, tc := range cases {
		tc := tc
		ydSchedule, err := yd.ParseIn(tc.expr, time.UTC)
		if err != nil {
			b.Fatalf("ydx ParseIn(%q): %v", tc.expr, err)
		}
		roSchedule, err := robfigParse(parseCase{expr: tc.expr, fields: tc.fields})
		if err != nil {
			b.Fatalf("robfig parse(%q): %v", tc.expr, err)
		}
		b.Run("ydx/"+tc.name, func(b *testing.B) {
			b.ReportAllocs()
			at := time.Date(2026, time.January, 1, 8, 0, 0, 0, time.UTC)
			for i := 0; i < b.N; i++ {
				at = ydSchedule.Next(at)
				if at.IsZero() {
					b.Fatal("zero")
				}
			}
			benchSinkTime = at
		})
		b.Run("robfig/"+tc.name, func(b *testing.B) {
			b.ReportAllocs()
			at := time.Date(2026, time.January, 1, 8, 0, 0, 0, time.UTC)
			for i := 0; i < b.N; i++ {
				at = roSchedule.Next(at)
				if at.IsZero() {
					b.Fatal("zero")
				}
			}
			benchSinkTime = at
		})
	}
}
