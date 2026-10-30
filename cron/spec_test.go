package cron

import (
	"errors"
	"testing"
	"time"
)

// utc builds a UTC instant for the table tests. | utc 为表驱动测试构造 UTC 时刻。
func utc(year int, month time.Month, day, hour, minute, second int) time.Time {
	return time.Date(year, month, day, hour, minute, second, 0, time.UTC)
}

// TestSpecNext covers the mainstream cron syntax: five to seven fields, names,
// ranges, lists, steps, descriptors, time zones and the Quartz special forms. |
// TestSpecNext 覆盖主流 cron 语法：5 到 7 个字段、名称、范围、列表、步长、描述符、时区与
// Quartz 特殊形式。
func TestSpecNext(t *testing.T) {
	tests := []struct {
		name  string
		expr  string
		after time.Time
		want  time.Time
	}{
		{
			name:  "every five minutes",
			expr:  "*/5 * * * *",
			after: utc(2026, time.January, 1, 0, 2, 0),
			want:  utc(2026, time.January, 1, 0, 5, 0),
		},
		{
			name:  "daily is strictly after",
			expr:  "0 9 * * *",
			after: utc(2026, time.January, 1, 9, 0, 0),
			want:  utc(2026, time.January, 2, 9, 0, 0),
		},
		{
			name:  "first day of next month",
			expr:  "0 0 1 * *",
			after: utc(2026, time.January, 15, 12, 0, 0),
			want:  utc(2026, time.February, 1, 0, 0, 0),
		},
		{
			name:  "weekday name",
			expr:  "0 0 * * MON",
			after: utc(2026, time.January, 1, 0, 0, 0),
			want:  utc(2026, time.January, 5, 0, 0, 0),
		},
		{
			name:  "sunday as seven",
			expr:  "0 0 * * 7",
			after: utc(2026, time.January, 1, 0, 0, 0),
			want:  utc(2026, time.January, 4, 0, 0, 0),
		},
		{
			name:  "sunday as name",
			expr:  "0 0 * * SUN",
			after: utc(2026, time.January, 1, 0, 0, 0),
			want:  utc(2026, time.January, 4, 0, 0, 0),
		},
		{
			name:  "day of month or day of week",
			expr:  "0 0 13 * FRI",
			after: utc(2026, time.January, 1, 0, 0, 0),
			want:  utc(2026, time.January, 2, 0, 0, 0),
		},
		{
			name:  "day of month alone",
			expr:  "0 0 13 * *",
			after: utc(2026, time.January, 13, 0, 0, 0),
			want:  utc(2026, time.February, 13, 0, 0, 0),
		},
		{
			name:  "seconds field",
			expr:  "*/10 * * * * *",
			after: utc(2026, time.January, 1, 0, 0, 0),
			want:  utc(2026, time.January, 1, 0, 0, 10),
		},
		{
			name:  "seconds range with step",
			expr:  "10-20/5 * * * * *",
			after: utc(2026, time.January, 1, 0, 0, 0),
			want:  utc(2026, time.January, 1, 0, 0, 10),
		},
		{
			name:  "step from start",
			expr:  "0/15 * * * * *",
			after: utc(2026, time.January, 1, 0, 0, 16),
			want:  utc(2026, time.January, 1, 0, 0, 30),
		},
		{
			name:  "second monday",
			expr:  "0 0 12 ? * MON#2",
			after: utc(2026, time.January, 1, 0, 0, 0),
			want:  utc(2026, time.January, 12, 12, 0, 0),
		},
		{
			name:  "third friday",
			expr:  "0 0 12 ? * FRI#3",
			after: utc(2026, time.January, 1, 0, 0, 0),
			want:  utc(2026, time.January, 16, 12, 0, 0),
		},
		{
			name:  "last friday",
			expr:  "0 0 12 ? * 5L",
			after: utc(2026, time.January, 1, 0, 0, 0),
			want:  utc(2026, time.January, 30, 12, 0, 0),
		},
		{
			name:  "last day of month",
			expr:  "0 0 12 L * *",
			after: utc(2026, time.January, 1, 0, 0, 0),
			want:  utc(2026, time.January, 31, 12, 0, 0),
		},
		{
			name:  "two days before last day",
			expr:  "0 0 12 L-2 * *",
			after: utc(2026, time.January, 1, 0, 0, 0),
			want:  utc(2026, time.January, 29, 12, 0, 0),
		},
		{
			name:  "last weekday of month",
			expr:  "0 0 12 LW * *",
			after: utc(2026, time.January, 1, 0, 0, 0),
			want:  utc(2026, time.January, 30, 12, 0, 0),
		},
		{
			name:  "nearest weekday",
			expr:  "0 0 12 15W * *",
			after: utc(2026, time.January, 1, 0, 0, 0),
			want:  utc(2026, time.January, 15, 12, 0, 0),
		},
		{
			name:  "nearest weekday shifts off sunday",
			expr:  "0 0 12 15W * *",
			after: utc(2026, time.February, 1, 0, 0, 0),
			want:  utc(2026, time.February, 16, 12, 0, 0),
		},
		{
			name:  "nearest weekday shifts first sunday forward",
			expr:  "0 0 12 1W * *",
			after: utc(2026, time.February, 1, 0, 0, 0),
			want:  utc(2026, time.February, 2, 12, 0, 0),
		},
		{
			name:  "year field",
			expr:  "0 0 0 1 1 * 2030",
			after: utc(2026, time.January, 1, 0, 0, 0),
			want:  utc(2030, time.January, 1, 0, 0, 0),
		},
		{
			name:  "daily descriptor",
			expr:  "@daily",
			after: utc(2026, time.January, 1, 12, 0, 0),
			want:  utc(2026, time.January, 2, 0, 0, 0),
		},
		{
			name:  "weekday range",
			expr:  "0 0 0 * * 1-5",
			after: utc(2026, time.January, 1, 0, 0, 0),
			want:  utc(2026, time.January, 2, 0, 0, 0),
		},
		{
			name:  "month names",
			expr:  "0 0 1 JAN-MAR *",
			after: utc(2026, time.January, 2, 0, 0, 0),
			want:  utc(2026, time.February, 1, 0, 0, 0),
		},
		{
			name:  "time zone prefix",
			expr:  "CRON_TZ=Asia/Shanghai 0 9 * * *",
			after: utc(2026, time.January, 1, 0, 0, 0),
			want:  utc(2026, time.January, 1, 1, 0, 0),
		},
		{
			name:  "every descriptor",
			expr:  "@every 90m",
			after: utc(2026, time.January, 1, 0, 0, 0),
			want:  utc(2026, time.January, 1, 1, 30, 0),
		},
		{
			name:  "once descriptor",
			expr:  "@once 2026-01-01T00:10:00Z",
			after: utc(2026, time.January, 1, 0, 0, 0),
			want:  utc(2026, time.January, 1, 0, 10, 0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sched, err := ParseIn(tt.expr, time.UTC)
			if err != nil {
				t.Fatalf("ParseIn(%q) error: %v | 解析失败", tt.expr, err)
			}
			if got := sched.Next(tt.after); !got.Equal(tt.want) {
				t.Fatalf("Next(%q, %s) = %s, want %s | 下次触发时间不符",
					tt.expr, tt.after.Format(time.RFC3339), got.Format(time.RFC3339), tt.want.Format(time.RFC3339))
			}
		})
	}
}

// TestDescriptorMacros pins every built-in macro before the direct-construction
// fast path is introduced. | TestDescriptorMacros 在引入直接构造快路径前固定每个内置宏的语义。
func TestDescriptorMacros(t *testing.T) {
	after := utc(2026, time.January, 1, 8, 30, 0) // Thursday.
	tests := []struct {
		expr string
		want time.Time
	}{
		{"@yearly", utc(2027, time.January, 1, 0, 0, 0)},
		{"@annually", utc(2027, time.January, 1, 0, 0, 0)},
		{"@monthly", utc(2026, time.February, 1, 0, 0, 0)},
		{"@weekly", utc(2026, time.January, 4, 0, 0, 0)},
		{"@daily", utc(2026, time.January, 2, 0, 0, 0)},
		{"@midnight", utc(2026, time.January, 2, 0, 0, 0)},
		{"@hourly", utc(2026, time.January, 1, 9, 0, 0)},
	}
	for _, tt := range tests {
		schedule, err := ParseIn(tt.expr, time.UTC)
		if err != nil {
			t.Fatalf("ParseIn(%q): %v | 解析失败", tt.expr, err)
		}
		if got := schedule.Next(after); !got.Equal(tt.want) {
			t.Fatalf("Next(%q) = %s, want %s | 宏触发时间不符", tt.expr, got, tt.want)
		}
		roundTrip, err := ParseIn(schedule.String(), time.UTC)
		if err != nil {
			t.Fatalf("ParseIn(String(%q)=%q): %v | 往返解析失败", tt.expr, schedule.String(), err)
		}
		if got := roundTrip.Next(after); !got.Equal(tt.want) {
			t.Fatalf("round trip Next(%q) = %s, want %s | 往返触发时间不符", tt.expr, got, tt.want)
		}
	}
}

// TestParseIn verifies a schedule inherits the supplied location and keeps the
// wall-clock fields of the expression. | TestParseIn 验证调度继承传入时区并保持表达式的墙上时间字段。
func TestParseIn(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatalf("LoadLocation: %v | 加载时区失败", err)
	}
	sched, err := ParseIn("30 8 * * *", loc)
	if err != nil {
		t.Fatalf("ParseIn: %v | 解析失败", err)
	}
	after := utc(2026, time.January, 1, 0, 0, 0) // 08:00 in Shanghai.
	want := utc(2026, time.January, 1, 0, 30, 0) // 08:30 in Shanghai.
	if got := sched.Next(after); !got.Equal(want) {
		t.Fatalf("Next = %s, want %s | 下次触发时间不符", got, want)
	}
	spec, ok := sched.(*Spec)
	if !ok {
		t.Fatalf("ParseIn returned %T, want *Spec | 返回类型不符", sched)
	}
	if spec.Location() != loc {
		t.Fatalf("Location = %v, want %v | 时区不符", spec.Location(), loc)
	}
}

// TestScheduleStringRoundTrip requires every schedule to render a parseable expression. |
// TestScheduleStringRoundTrip 要求每种调度都渲染出可再次解析的表达式。
func TestScheduleStringRoundTrip(t *testing.T) {
	exprs := []string{
		"*/5 * * * *",
		"0 9 * * MON-FRI",
		"0 0 0 L * *",
		"0 0 12 ? * FRI#3",
		"@daily",
		"@every 1h30m0s",
		"@once 2026-01-01T00:10:00Z",
	}
	for _, expr := range exprs {
		sched, err := Parse(expr)
		if err != nil {
			t.Fatalf("Parse(%q): %v | 解析失败", expr, err)
		}
		rendered := sched.String()
		if rendered == "" {
			t.Fatalf("String(%q) is empty | 表达式为空", expr)
		}
		again, err := Parse(rendered)
		if err != nil {
			t.Fatalf("Parse(String(%q)=%q): %v | 往返解析失败", expr, rendered, err)
		}
		after := utc(2026, time.January, 1, 0, 0, 0)
		if a, b := sched.Next(after), again.Next(after); !a.Equal(b) {
			t.Fatalf("round trip %q: %s != %s | 往返结果不一致", expr, a, b)
		}
	}
}

// TestParseErrors requires every malformed expression to report a declared sentinel. |
// TestParseErrors 要求每个非法表达式都返回已声明的哨兵错误。
func TestParseErrors(t *testing.T) {
	tests := []struct {
		expr string
		want error
	}{
		{"", ErrEmptySpec},
		{"   ", ErrEmptySpec},
		{"* * *", ErrInvalidField},
		{"* * * * * * * *", ErrInvalidField},
		{"61 * * * *", ErrInvalidValue},
		{"* 24 * * *", ErrInvalidValue},
		{"* * 32 * *", ErrInvalidValue},
		{"* * * 13 *", ErrInvalidValue},
		{"* * * * 8", ErrInvalidValue},
		{"* * * * FOO", ErrInvalidValue},
		{"0 0 W * *", ErrInvalidValue},
		{"0 0 * * L#2", ErrInvalidValue},
		{"0 0 0 1 1 * 1960", ErrInvalidValue},
		{"@every 0s", ErrInvalidValue},
		{"@every nope", ErrInvalidValue},
		{"@once nope", ErrInvalidValue},
		{"@daily extra", ErrInvalidValue},
		{"@yearly x", ErrInvalidValue},
		{"@reboot", ErrUnsupportedSpec},
		{"@unknown", ErrUnsupportedSpec},
		{"CRON_TZ=Nope/Zone 0 0 * * *", ErrInvalidValue},
		{"5/0 * * * *", ErrInvalidValue},
		{"10-5 * * * *", ErrInvalidValue},
	}
	for _, tt := range tests {
		_, err := Parse(tt.expr)
		if err == nil {
			t.Errorf("Parse(%q) returned nil error | 未返回错误", tt.expr)
			continue
		}
		if !errors.Is(err, tt.want) {
			t.Errorf("Parse(%q) = %v, want errors.Is(%v) | 错误类型不符", tt.expr, err, tt.want)
		}
	}
}

// TestSpecNoFuture reports an impossible date as a zero next time instead of looping. |
// TestSpecNoFuture 对不可能出现的日期返回零值下次时间，而不是死循环。
func TestSpecNoFuture(t *testing.T) {
	sched, err := Parse("0 0 0 30 2 *")
	if err != nil {
		t.Fatalf("Parse: %v | 解析失败", err)
	}
	if got := sched.Next(utc(2026, time.January, 1, 0, 0, 0)); !got.IsZero() {
		t.Fatalf("Next = %s, want zero | 应返回零值", got)
	}
}

// TestIntervalAndOnce verifies the built-in simple schedules. | TestIntervalAndOnce 验证内置的简单调度。
func TestIntervalAndOnce(t *testing.T) {
	after := utc(2026, time.January, 1, 0, 0, 0)
	if got, want := Interval(90*time.Minute).Next(after), utc(2026, time.January, 1, 1, 30, 0); !got.Equal(want) {
		t.Fatalf("Interval.Next = %s, want %s | 间隔调度结果不符", got, want)
	}
	if got := Interval(0).Next(after); !got.IsZero() {
		t.Fatalf("Interval(0).Next = %s, want zero | 零间隔应返回零值", got)
	}
	if got, want := Once(utc(2026, time.January, 1, 0, 10, 0)).Next(after), utc(2026, time.January, 1, 0, 10, 0); !got.Equal(want) {
		t.Fatalf("Once.Next = %s, want %s | 一次性调度结果不符", got, want)
	}
	if got := Once(after).Next(after); !got.IsZero() {
		t.Fatalf("Once(past).Next = %s, want zero | 过去时刻应返回零值", got)
	}
}

// TestMustParse covers the package-declaration convenience. | TestMustParse 覆盖包级声明用的便捷构造器。
func TestMustParse(t *testing.T) {
	if schedule := MustParse("@daily"); schedule == nil {
		t.Fatal("MustParse returned nil | MustParse 返回 nil")
	}
	panicked := false
	func() {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		MustParse("not a schedule")
	}()
	if !panicked {
		t.Fatal("MustParse did not panic on a bad expression | 非法表达式未 panic")
	}
}

// TestNextHasNoAllocations protects the scheduler hot path from accidental allocations. |
// TestNextHasNoAllocations 防止调度热路径产生意外分配。
func TestNextHasNoAllocations(t *testing.T) {
	sched, err := Parse("*/5 9-17 * * MON-FRI")
	if err != nil {
		t.Fatalf("Parse: %v | 解析失败", err)
	}
	after := utc(2026, time.January, 1, 8, 0, 0)
	zero := false
	allocs := testing.AllocsPerRun(100, func() {
		if next := sched.Next(after); next.IsZero() {
			zero = true
		}
	})
	if zero {
		t.Fatal("Next returned zero | Next 返回零值")
	}
	if allocs != 0 {
		t.Fatalf("Next allocated %v times per run, want 0 | 热路径产生分配", allocs)
	}
}
