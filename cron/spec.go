package cron

import (
	"math/bits"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Declared sentinel errors for schedule parsing. | 调度解析的已声明哨兵错误。
var (
	// ErrEmptySpec indicates an empty expression. | ErrEmptySpec 表示表达式为空。
	ErrEmptySpec = errs.New("cron: empty schedule expression | cron：调度表达式为空")
	// ErrInvalidField indicates a wrong number of cron fields. | ErrInvalidField 表示 cron 字段数量错误。
	ErrInvalidField = errs.New("cron: invalid field count | cron：字段数量非法")
	// ErrInvalidValue indicates a field value outside its supported range or an unparsable token. |
	// ErrInvalidValue 表示字段取值超出范围或标记无法解析。
	ErrInvalidValue = errs.New("cron: invalid field value | cron：字段取值非法")
	// ErrUnsupportedSpec indicates a descriptor the scheduler does not implement. |
	// ErrUnsupportedSpec 表示调度器未实现的描述符。
	ErrUnsupportedSpec = errs.New("cron: unsupported schedule | cron：不支持的调度表达式")
)

// Schedule computes activation instants. Next must return a time strictly after
// after, or the zero time when the schedule will never fire again. |
// Schedule 计算触发时刻；Next 必须返回严格晚于 after 的时刻，永不再触发时返回零值。
type Schedule interface {
	// Next returns the next activation strictly after after. | Next 返回严格晚于 after 的下次触发时刻。
	Next(after time.Time) time.Time
	// String renders an expression Parse accepts. | String 渲染可被 Parse 再次解析的表达式。
	String() string
}

// maxScheduleYear is the last year the year field can select. | maxScheduleYear 是年份字段能选中的最后一年。
const maxScheduleYear = 2099

// minScheduleYear is the first year the year field can select. | minScheduleYear 是年份字段能选中的第一年。
const minScheduleYear = 1970

// yearSpan is the number of selectable years. | yearSpan 是可选年份的数量。
const yearSpan = maxScheduleYear - minScheduleYear + 1

// Spec is a parsed cron expression. It stores every field as a bit mask, so Next
// never parses or allocates; one Spec costs a few dozen bytes regardless of how
// many values the expression names. | Spec 是已解析的 cron 表达式：每个字段存为位图，
// 因此 Next 不做解析也不分配内存；无论表达式列出多少取值，一个 Spec 只占几十字节。
type Spec struct {
	// loc is the time zone whose wall clock the fields refer to. | loc 是字段所依据的时区。
	loc *time.Location
	// expr is the canonical expression without a time-zone prefix. | expr 是不含时区前缀的规范表达式。
	expr string
	// years holds allowed years relative to 1970; it is used only when yearSet is true. |
	// years 是相对 1970 年的允许年份位图，仅当 yearSet 为 true 时使用。
	years [3]uint64
	// sec, min and hour hold allowed seconds, minutes and hours. | sec、min、hour 是允许的秒、分、时位图。
	sec, min, hour uint64
	// domLastOffset subtracts days from the last day; used with domLast. | domLastOffset 从最后一天回退的天数，与 domLast 配合。
	domLastOffset int
	// domNearestDay is the target day for the W form. | domNearestDay 是 W 形式的目标日期。
	domNearestDay int
	// dowLastDay is the weekday of the L form. | dowLastDay 是 L 形式选中的星期。
	dowLastDay int
	// dowNthDay is the weekday of the # form. | dowNthDay 是 # 形式选中的星期。
	dowNthDay int
	// dowNthNum is the occurrence of the # form, 1 through 5. | dowNthNum 是 # 形式中的第几次，取值 1 到 5。
	dowNthNum int
	// dom holds allowed days of month, bit 1 through bit 31. | dom 是允许的月内日期位图，第 1 到第 31 位。
	dom uint32
	// month holds allowed months, bit 1 through bit 12. | month 是允许的月份位图，第 1 到第 12 位。
	month uint16
	// dow holds allowed weekdays, bit 0 (Sunday) through bit 6 (Saturday). |
	// dow 是允许的星期位图，第 0 位（周日）到第 6 位（周六）。
	dow uint8
	// yearSet reports whether the expression carried an explicit year field. | yearSet 表示表达式是否带有年份字段。
	yearSet bool
	// domStar reports whether the day-of-month field was a wildcard. | domStar 表示月内日期字段是否为通配符。
	domStar bool
	// dowStar reports whether the day-of-week field was a wildcard. | dowStar 表示星期字段是否为通配符。
	dowStar bool
	// domLast selects the last day of the month. | domLast 选择当月最后一天。
	domLast bool
	// domLastWeekday selects the last weekday (Monday to Friday) of the month. | domLastWeekday 选择当月最后一个工作日。
	domLastWeekday bool
	// domNearest selects the weekday nearest to domNearestDay. | domNearest 选择最接近 domNearestDay 的工作日。
	domNearest bool
	// dowLast selects the last dowLastDay weekday of the month. | dowLast 选择当月最后一个 dowLastDay 星期。
	dowLast bool
	// dowNth selects the dowNthNum-th dowNthDay weekday of the month. | dowNth 选择当月第 dowNthNum 个 dowNthDay 星期。
	dowNth bool
}

// Next returns the first activation strictly after after, or the zero time when
// the schedule has no activation within five years (or within the explicit year
// range). It is safe for concurrent use. | Next 返回严格晚于 after 的第一个触发时刻；
// 五年内（或显式年份范围内）没有触发时返回零值。该方法可安全并发使用。
func (s *Spec) Next(after time.Time) time.Time {
	loc := s.loc
	if loc == nil {
		loc = time.Local
	}
	t := after.In(loc)
	// Move to the next whole second with one Add instead of Truncate+Add. |
	// 用一次 Add 移到下一个整秒，避免 Truncate+Add。
	t = t.Add(time.Second - time.Duration(t.Nanosecond()))

	// A year bound is enough for the search horizon and avoids AddDate on every
	// call. | 用年份上限即可界定搜索范围，避免每次调用都做 AddDate。
	limitYear := t.Year() + 5
	if s.yearSet {
		limitYear = maxScheduleYear
	}

	for t.Year() <= limitYear {
		if s.yearSet && !s.yearAllowed(t.Year()) {
			year, ok := s.nextYear(t.Year() + 1)
			if !ok {
				return time.Time{}
			}
			t = time.Date(year, time.January, 1, 0, 0, 0, 0, loc)
			continue
		}
		if !maskHas(s.month, t.Month()) {
			if next := nextSetBit64(uint64(s.month), int(t.Month())+1); next >= 1 && next <= 12 {
				t = time.Date(t.Year(), time.Month(next), 1, 0, 0, 0, 0, loc)
			} else {
				t = time.Date(t.Year()+1, time.January, 1, 0, 0, 0, 0, loc)
			}
			continue
		}
		if !s.dayAllowed(t) {
			t = s.nextDay(t, loc)
			continue
		}
		if !maskHas64(s.hour, t.Hour()) {
			if next := nextSetBit64(s.hour, t.Hour()); next >= 0 && next <= 23 {
				t = time.Date(t.Year(), t.Month(), t.Day(), next, 0, 0, 0, loc)
			} else {
				t = time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, loc)
			}
			continue
		}
		if !maskHas64(s.min, t.Minute()) {
			if next := nextSetBit64(s.min, t.Minute()); next >= 0 && next <= 59 {
				t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), next, firstSetBit64(s.sec), 0, loc)
			} else {
				t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour()+1, 0, 0, 0, loc)
			}
			continue
		}
		if !maskHas64(s.sec, t.Second()) {
			if next := nextSetBit64(s.sec, t.Second()); next >= 0 && next <= 59 {
				t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), next, 0, loc)
			} else {
				t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute()+1, 0, 0, loc)
			}
			continue
		}
		return t
	}
	return time.Time{}
}

// nextDay returns the first day at or after the following midnight that can
// match, jumping directly for the single-rule forms instead of walking one day
// at a time. | nextDay 返回次日零点及之后第一个可能匹配的日期；对单规则形式直接跳转，
// 而不是逐日推进。
func (s *Spec) nextDay(t time.Time, loc *time.Location) time.Time {
	year, month, day := t.Date()
	last := daysInMonth(year, month)
	candidate := 0

	switch {
	case s.dowStar && !s.domLast && !s.domLastWeekday && !s.domNearest:
		// Only the day-of-month bit mask applies. | 仅月内日期位图生效。
		if next := nextSetBit64(uint64(s.dom), day+1); next >= 1 && next <= last {
			candidate = next
		}
	case s.domStar && !s.dowLast && !s.dowNth:
		// Only the day-of-week bit mask applies; a match is at most six days away. |
		// 仅星期位图生效；最多六天后就会匹配。
		for d := day + 1; d <= last; d++ {
			weekday := int(time.Date(year, month, d, 0, 0, 0, 0, time.UTC).Weekday())
			if s.dow&(1<<uint(weekday)) != 0 {
				candidate = d
				break
			}
		}
	case s.domStar && s.dowLast:
		// Only the last weekday form applies. | 仅“最后一个星期”形式生效。
		if next := lastWeekdayOf(year, month, s.dowLastDay); next > day {
			candidate = next
		}
	case s.domStar && s.dowNth:
		// Only the nth weekday form applies. | 仅“第 n 个星期”形式生效。
		if next := nthWeekdayOf(year, month, s.dowNthDay, s.dowNthNum); next > day {
			candidate = next
		}
	case s.dowStar && s.domLast:
		// Only the last-day form applies. | 仅最后一天形式生效。
		if next := last - s.domLastOffset; next >= 1 && next > day {
			candidate = next
		}
	case s.dowStar && s.domLastWeekday:
		if next := lastWeekday(year, month); next > day {
			candidate = next
		}
	case s.dowStar && s.domNearest:
		if next := nearestWeekday(year, month, s.domNearestDay); next > day {
			candidate = next
		}
	}

	if candidate > day {
		return time.Date(year, month, candidate, 0, 0, 0, 0, loc)
	}
	if day < last {
		return time.Date(year, month, day+1, 0, 0, 0, 0, loc)
	}
	return time.Date(year, month+1, 1, 0, 0, 0, 0, loc)
}

// nextSetBit64 returns the first set bit at or after from, or -1. |
// nextSetBit64 返回 from 及之后第一个置位，未找到返回 -1。
func nextSetBit64(mask uint64, from int) int {
	if from < 0 {
		from = 0
	}
	if from > 63 {
		return -1
	}
	shifted := mask >> uint(from)
	if shifted == 0 {
		return -1
	}
	return from + bits.TrailingZeros64(shifted)
}

// firstSetBit64 returns the lowest set bit, or 0 for an empty mask. |
// firstSetBit64 返回最低置位；空位图返回 0。
func firstSetBit64(mask uint64) int {
	if mask == 0 {
		return 0
	}
	return bits.TrailingZeros64(mask)
}

// lastWeekdayOf returns the last occurrence of weekday in the month. |
// lastWeekdayOf 返回当月最后一个指定星期。
func lastWeekdayOf(year int, month time.Month, weekday int) int {
	last := daysInMonth(year, month)
	offset := (int(time.Date(year, month, last, 0, 0, 0, 0, time.UTC).Weekday()) - weekday + 7) % 7
	return last - offset
}

// nthWeekdayOf returns the nth occurrence of weekday in the month, or 0 when it
// does not exist. | nthWeekdayOf 返回当月第 n 个指定星期；不存在时返回 0。
func nthWeekdayOf(year int, month time.Month, weekday, nth int) int {
	first := int(time.Date(year, month, 1, 0, 0, 0, 0, time.UTC).Weekday())
	day := 1 + (weekday-first+7)%7 + (nth-1)*7
	if day > daysInMonth(year, month) {
		return 0
	}
	return day
}

// String returns the canonical expression. | String 返回规范表达式。
func (s *Spec) String() string { return s.expr }

// Location returns the time zone of the expression; a zero Spec falls back to
// time.Local so the result is never nil. | Location 返回表达式时区；零值 Spec 回落到
// time.Local，因此结果永不为 nil。
func (s *Spec) Location() *time.Location {
	if s == nil || s.loc == nil {
		return time.Local
	}
	return s.loc
}

// dayAllowed applies the POSIX day rule: when both day fields are restricted,
// either one matching activates the job; when only one is restricted, only that
// one is consulted. | dayAllowed 应用 POSIX 日期规则：两个日期字段都受限时任一匹配即触发；
// 仅一个受限时只看该字段。
func (s *Spec) dayAllowed(t time.Time) bool {
	switch {
	case s.domStar && s.dowStar:
		return true
	case s.domStar:
		return s.dowMatch(t)
	case s.dowStar:
		return s.domMatch(t)
	default:
		return s.domMatch(t) || s.dowMatch(t)
	}
}

// domMatch reports whether t matches the day-of-month constraints. | domMatch 报告 t 是否匹配月内日期约束。
func (s *Spec) domMatch(t time.Time) bool {
	if s.dom != 0 && s.dom&(1<<uint(t.Day())) != 0 {
		return true
	}
	last := daysInMonth(t.Year(), t.Month())
	if s.domLast && t.Day() == last-s.domLastOffset {
		return true
	}
	if s.domLastWeekday && t.Day() == lastWeekday(t.Year(), t.Month()) {
		return true
	}
	if s.domNearest && t.Day() == nearestWeekday(t.Year(), t.Month(), s.domNearestDay) {
		return true
	}
	return false
}

// dowMatch reports whether t matches the day-of-week constraints. | dowMatch 报告 t 是否匹配星期约束。
func (s *Spec) dowMatch(t time.Time) bool {
	weekday := int(t.Weekday())
	if s.dow&(1<<uint(weekday)) != 0 {
		return true
	}
	if s.dowLast && weekday == s.dowLastDay && t.Day()+7 > daysInMonth(t.Year(), t.Month()) {
		return true
	}
	if s.dowNth && weekday == s.dowNthDay && (t.Day()-1)/7+1 == s.dowNthNum {
		return true
	}
	return false
}

// yearAllowed reports whether year is selected by the year field. | yearAllowed 报告年份是否被年份字段选中。
func (s *Spec) yearAllowed(year int) bool {
	if !s.yearSet {
		return true
	}
	index := year - minScheduleYear
	if index < 0 || index >= yearSpan {
		return false
	}
	return s.years[index/64]&(1<<uint(index%64)) != 0
}

// nextYear returns the first allowed year at or after from. | nextYear 返回 from 及之后第一个允许的年份。
func (s *Spec) nextYear(from int) (int, bool) {
	if from < minScheduleYear {
		from = minScheduleYear
	}
	for year := from; year <= maxScheduleYear; year++ {
		if s.yearAllowed(year) {
			return year, true
		}
	}
	return 0, false
}

// maskHas reports whether bit v is set in mask. | maskHas 报告 mask 的第 v 位是否置位。
func maskHas(mask uint16, v time.Month) bool {
	bit := uint(v)
	if bit >= 16 {
		return false
	}
	return mask&(1<<bit) != 0
}

// maskHas64 reports whether bit v is set in mask. | maskHas64 报告 mask 的第 v 位是否置位。
func maskHas64(mask uint64, v int) bool {
	return v >= 0 && v < 64 && mask&(1<<uint(v)) != 0
}

// daysInMonth returns the number of days in the given month. | daysInMonth 返回给定月份的天数。
func daysInMonth(year int, month time.Month) int {
	return time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

// lastWeekday returns the last Monday-to-Friday day of the month. | lastWeekday 返回当月最后一个周一至周五的日期。
func lastWeekday(year int, month time.Month) int {
	for day := daysInMonth(year, month); day >= 1; day-- {
		switch time.Date(year, month, day, 0, 0, 0, 0, time.UTC).Weekday() {
		case time.Saturday, time.Sunday:
			continue
		default:
			return day
		}
	}
	return 1
}

// nearestWeekday returns the weekday nearest to day within the month, following
// the Quartz rule that a weekend target never crosses a month boundary. It
// returns 0 when day does not exist in the month. | nearestWeekday 返回当月最接近 day 的
// 工作日；遵循 Quartz 规则，周末目标不会跨月。当月不存在该日期时返回 0。
func nearestWeekday(year int, month time.Month, day int) int {
	last := daysInMonth(year, month)
	if day < 1 || day > last {
		return 0
	}
	switch time.Date(year, month, day, 0, 0, 0, 0, time.UTC).Weekday() {
	case time.Saturday:
		if day == 1 {
			return 3
		}
		return day - 1
	case time.Sunday:
		if day == last {
			return day - 2
		}
		return day + 1
	default:
		return day
	}
}

// Interval is a fixed duration between activations, aligned to the Unix epoch so
// every node in a cluster derives the same fire times without shared state. |
// Interval 是固定间隔调度，按 Unix 纪元对齐，使集群中每个节点无需共享状态即可得到相同触发时刻。
type Interval time.Duration

// Next returns the next epoch-aligned activation strictly after after. A
// non-positive interval never fires. | Next 返回严格晚于 after 的下一个纪元对齐触发时刻；
// 非正间隔不会触发。
func (i Interval) Next(after time.Time) time.Time {
	d := time.Duration(i)
	if d <= 0 {
		return time.Time{}
	}
	// Whole-second intervals use the Unix second counter and a float64 quotient.
	// Every Unix second up to 2^53 is exact in float64, and one correction step
	// absorbs the rounding of the division; the result is still strictly
	// epoch-aligned but avoids a 64-bit integer division. Beyond 2^53 seconds
	// the code falls back to the exact integer remainder. |
	// 整秒间隔使用 Unix 秒计数与 float64 商。2^53 以内的 Unix 秒在 float64 中精确，
	// 一步校正吸收除法舍入；结果仍是严格的纪元对齐，但避免 64 位整数除法。超过 2^53 秒时
	// 回落到精确的整数取余。
	if d%time.Second == 0 {
		secs := int64(d / time.Second)
		sec := after.Unix()
		var rem int64
		if sec > (1<<53) || sec < -(1<<53) {
			rem = sec % secs
		} else {
			quotient := int64(float64(sec) / float64(secs))
			rem = sec - quotient*secs
			if rem >= secs {
				rem -= secs
			} else if rem < 0 {
				rem += secs
			}
		}
		if rem < 0 {
			rem += secs
		}
		delta := time.Duration(secs-rem)*time.Second - time.Duration(after.Nanosecond())
		if delta <= 0 {
			delta += d
		}
		return after.Add(delta)
	}
	n := after.UnixNano()
	rem := n % int64(d)
	if rem < 0 {
		rem += int64(d)
	}
	return after.Add(time.Duration(int64(d) - rem))
}

// String renders the interval as @every duration. | String 把间隔渲染为 @every 时长。
func (i Interval) String() string { return "@every " + time.Duration(i).String() }

// Once is a one-shot schedule at a fixed instant. | Once 是固定时刻的一次性调度。
type Once time.Time

// Next returns the instant when it is still strictly after after. | Next 在该时刻仍严格晚于 after 时返回它。
func (o Once) Next(after time.Time) time.Time {
	at := time.Time(o)
	if at.After(after) {
		return at
	}
	return time.Time{}
}

// String renders the instant as @once RFC3339Nano in UTC. | String 以 UTC 的 RFC3339Nano 渲染为 @once。
func (o Once) String() string {
	return "@once " + time.Time(o).UTC().Format(time.RFC3339Nano)
}
