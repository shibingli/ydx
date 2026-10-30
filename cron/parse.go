package cron

import (
	"strconv"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Parse parses expr in time.Local. | Parse 以 time.Local 解析 expr。
//
// It accepts the five-field Unix form, the six-field form with seconds, the
// seven-field form with an explicit year, the @yearly/@monthly/@weekly/@daily/
// @hourly macros, @every duration and @once RFC3339. A leading CRON_TZ= or TZ=
// token selects the time zone of the remaining expression. | 支持五字段 Unix 形式、
// 带秒的六字段形式、带年份的七字段形式、@yearly/@monthly/@weekly/@daily/@hourly 宏、
// @every 时长与 @once RFC3339；前导 CRON_TZ= 或 TZ= 标记为其余表达式选择时区。
func Parse(expr string) (Schedule, error) { return ParseIn(expr, time.Local) }

// MustParse is Parse for package-level declarations; it panics with the parse
// error. Panic is the documented contract of Must constructors. |
// MustParse 是供包级声明使用的 Parse；解析失败时 panic。panic 是 Must 构造器的文档化契约。
func MustParse(expr string) Schedule {
	schedule, err := Parse(expr)
	if err != nil {
		panic(err)
	}
	return schedule
}

// MustParseIn is ParseIn for package-level declarations; it panics with the
// parse error. | MustParseIn 是供包级声明使用的 ParseIn；解析失败时 panic。
func MustParseIn(expr string, loc *time.Location) Schedule {
	schedule, err := ParseIn(expr, loc)
	if err != nil {
		panic(err)
	}
	return schedule
}

// ParseIn parses expr in loc; a nil loc means time.Local. | ParseIn 以 loc 解析 expr；loc 为 nil 时使用 time.Local。
func ParseIn(expr string, loc *time.Location) (Schedule, error) {
	if loc == nil {
		loc = time.Local
	}
	raw := strings.TrimSpace(expr)
	if raw == "" {
		return nil, ErrEmptySpec
	}

	// A plain descriptor needs neither a time-zone scan nor a field split. |
	// 普通描述符既不需要扫描时区，也不需要切分字段。
	if raw[0] == '@' {
		return parseDescriptor(raw, loc)
	}

	// Peel an optional time-zone prefix without allocating a Fields slice; a
	// descriptor then goes straight to its fast path. | 不分配 Fields 切片地剥离可选时区
	// 前缀；描述符随后直接进入快路径。
	if index := strings.IndexAny(raw, " \t"); index > 0 {
		if name, ok := timeZonePrefix(raw[:index]); ok {
			zone, err := time.LoadLocation(name)
			if err != nil {
				return nil, errs.WrapDetail(err, ErrInvalidValue, "time zone %q", name)
			}
			loc = zone
			raw = strings.TrimSpace(raw[index+1:])
			if raw == "" {
				return nil, ErrEmptySpec
			}
		}
	} else if _, ok := timeZonePrefix(raw); ok {
		return nil, ErrEmptySpec
	}
	if strings.HasPrefix(raw, "@") {
		return parseDescriptor(raw, loc)
	}

	fields := strings.Fields(raw)
	var second, minute, hour, dom, month, dow, year string
	switch len(fields) {
	case 5:
		second = "0"
		minute, hour, dom, month, dow = fields[0], fields[1], fields[2], fields[3], fields[4]
	case 6:
		second, minute, hour, dom, month, dow = fields[0], fields[1], fields[2], fields[3], fields[4], fields[5]
	case 7:
		second, minute, hour, dom, month, dow, year = fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6]
	default:
		return nil, errs.Detail(ErrInvalidField, "%d fields", len(fields))
	}

	spec := &Spec{expr: raw, loc: loc}
	var err error
	if spec.sec, _, err = parseField(second, 0, 59, nil, false); err != nil {
		return nil, err
	}
	if spec.min, _, err = parseField(minute, 0, 59, nil, false); err != nil {
		return nil, err
	}
	if spec.hour, _, err = parseField(hour, 0, 23, nil, false); err != nil {
		return nil, err
	}
	if err = spec.parseDOM(dom); err != nil {
		return nil, err
	}
	var monthMask uint64
	if monthMask, _, err = parseField(month, 1, 12, monthName, false); err != nil {
		return nil, err
	}
	spec.month = uint16(monthMask)
	if err = spec.parseDOW(dow); err != nil {
		return nil, err
	}
	if year != "" {
		if spec.years, spec.yearSet, err = parseYear(year); err != nil {
			return nil, err
		}
	}
	return spec, nil
}

// parseDescriptor expands a macro or parses a parameterised descriptor. |
// parseDescriptor 展开宏或解析带参数的描述符。
func parseDescriptor(raw string, loc *time.Location) (Schedule, error) {
	// Exact no-argument macros avoid name extraction and case folding. |
	// 无参数宏的精确匹配避免名称提取与大小写折叠。
	switch raw {
	case "@yearly", "@annually":
		return fixedSpec("0 0 0 1 1 *", 1, 1<<1, 1<<1, allWeekdays, loc), nil
	case "@monthly":
		return fixedSpec("0 0 0 1 * *", 1, 1<<1, allMonths, allWeekdays, loc), nil
	case "@weekly":
		return fixedSpec("0 0 0 * * 0", 1, allDays, allMonths, 1<<0, loc), nil
	case "@daily", "@midnight":
		return fixedSpec("0 0 0 * * *", 1, allDays, allMonths, allWeekdays, loc), nil
	case "@hourly":
		return fixedSpec("0 0 * * * *", allHours, allDays, allMonths, allWeekdays, loc), nil
	case "@reboot":
		return nil, errs.Detail(ErrUnsupportedSpec, "%q", raw)
	}
	if arg, ok := strings.CutPrefix(raw, "@every "); ok {
		return parseEvery(arg)
	}
	if arg, ok := strings.CutPrefix(raw, "@once "); ok {
		return parseOnce(arg)
	}

	name := raw
	arg := ""
	if index := strings.IndexAny(raw, " \t"); index >= 0 {
		name = raw[:index]
		arg = strings.TrimSpace(raw[index+1:])
	}
	lower := strings.ToLower(name)
	switch lower {
	case "@every", "@once", "@reboot":
	default:
		if arg != "" {
			return nil, errs.Detail(ErrInvalidValue, "%q", raw)
		}
	}
	switch lower {
	case "@yearly", "@annually":
		return fixedSpec("0 0 0 1 1 *", 1, 1<<1, 1<<1, allWeekdays, loc), nil
	case "@monthly":
		return fixedSpec("0 0 0 1 * *", 1, 1<<1, allMonths, allWeekdays, loc), nil
	case "@weekly":
		return fixedSpec("0 0 0 * * 0", 1, allDays, allMonths, 1<<0, loc), nil
	case "@daily", "@midnight":
		return fixedSpec("0 0 0 * * *", 1, allDays, allMonths, allWeekdays, loc), nil
	case "@hourly":
		return fixedSpec("0 0 * * * *", allHours, allDays, allMonths, allWeekdays, loc), nil
	case "@every":
		return parseEvery(arg)
	case "@once":
		return parseOnce(arg)
	case "@reboot":
		return nil, errs.Detail(ErrUnsupportedSpec, "%q", name)
	default:
		return nil, errs.Detail(ErrUnsupportedSpec, "%q", name)
	}
}

// parseEvery parses the @every duration argument. | parseEvery 解析 @every 的时长参数。
func parseEvery(arg string) (Schedule, error) {
	if strings.ContainsAny(arg, " \t") {
		arg = strings.ReplaceAll(strings.ReplaceAll(arg, " ", ""), "\t", "")
	}
	duration, err := time.ParseDuration(arg)
	if err != nil || duration <= 0 {
		return nil, errs.Detail(ErrInvalidValue, "%q", arg)
	}
	return Interval(duration), nil
}

// parseOnce parses the @once RFC3339 argument. | parseOnce 解析 @once 的 RFC3339 参数。
func parseOnce(arg string) (Schedule, error) {
	at, err := time.Parse(time.RFC3339Nano, arg)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidValue, "%q", arg)
	}
	return Once(at), nil
}

// Bit masks shared by the macro fast paths. | 宏快路径共享的位图。
const (
	// allHours selects every hour. | allHours 选择全部小时。
	allHours uint64 = (1 << 24) - 1
	// allDays selects every day of month, bits 1 through 31. | allDays 选择全部月内日期，第 1 到 31 位。
	allDays uint32 = 0xFFFF_FFFE
	// allMonths selects every month, bits 1 through 12. | allMonths 选择全部月份，第 1 到 12 位。
	allMonths uint16 = 0x0FFE
	// allWeekdays selects every weekday. | allWeekdays 选择全部星期。
	allWeekdays uint8 = 0x7F
)

// fixedSpec builds a macro schedule directly, avoiding a second parse pass. |
// fixedSpec 直接构建宏调度，避免二次解析。
func fixedSpec(expr string, hour uint64, dom uint32, month uint16, dow uint8, loc *time.Location) *Spec {
	return &Spec{
		expr:    expr,
		loc:     loc,
		sec:     1,
		min:     1,
		hour:    hour,
		dom:     dom,
		month:   month,
		dow:     dow,
		domStar: dom == allDays,
		dowStar: dow == allWeekdays,
	}
}

// timeZonePrefix reports whether token is CRON_TZ=name or TZ=name and returns
// the zone name. | timeZonePrefix 报告 token 是否为 CRON_TZ=name 或 TZ=name，并返回时区名。
func timeZonePrefix(token string) (string, bool) {
	if len(token) >= len("CRON_TZ=") && strings.EqualFold(token[:len("CRON_TZ=")], "CRON_TZ=") {
		return token[len("CRON_TZ="):], true
	}
	if len(token) >= len("TZ=") && strings.EqualFold(token[:len("TZ=")], "TZ=") {
		return token[len("TZ="):], true
	}
	return "", false
}

// parseDOM fills the day-of-month constraints, including L, L-n, W and LW. |
// parseDOM 填充月内日期约束，包括 L、L-n、W 与 LW。
func (s *Spec) parseDOM(field string) error {
	upper := strings.ToUpper(field)
	switch {
	case upper == "?":
		s.domStar = true
		return nil
	case strings.Contains(upper, "?"):
		return errs.Detail(ErrInvalidValue, "%q", field)
	case upper == "L":
		s.domLast = true
		return nil
	case upper == "LW":
		s.domLastWeekday = true
		return nil
	case strings.HasPrefix(upper, "L-"):
		offset, err := strconv.Atoi(upper[2:])
		if err != nil || offset < 0 || offset > 30 {
			return errs.Detail(ErrInvalidValue, "%q", field)
		}
		s.domLast = true
		s.domLastOffset = offset
		return nil
	case strings.HasSuffix(upper, "W"):
		day, err := strconv.Atoi(upper[:len(upper)-1])
		if err != nil || day < 1 || day > 31 {
			return errs.Detail(ErrInvalidValue, "%q", field)
		}
		s.domNearest = true
		s.domNearestDay = day
		return nil
	}
	mask, star, err := parseField(field, 1, 31, nil, false)
	if err != nil {
		return err
	}
	s.dom = uint32(mask)
	s.domStar = star
	return nil
}

// parseDOW fills the day-of-week constraints, including dayL and day#n. |
// parseDOW 填充星期约束，包括 dayL 与 day#n。
func (s *Spec) parseDOW(field string) error {
	upper := strings.ToUpper(field)
	switch {
	case upper == "?":
		s.dowStar = true
		return nil
	case strings.Contains(upper, "?"):
		return errs.Detail(ErrInvalidValue, "%q", field)
	case upper == "L":
		// Quartz treats a standalone L as Saturday. | Quartz 把单独的 L 视为周六。
		s.dow = 1 << 6
		return nil
	case strings.HasSuffix(upper, "L"):
		day, ok := parseDayValue(upper[:len(upper)-1])
		if !ok {
			return errs.Detail(ErrInvalidValue, "%q", field)
		}
		s.dowLast = true
		s.dowLastDay = day % 7
		return nil
	case strings.Contains(upper, "#"):
		parts := strings.Split(upper, "#")
		if len(parts) != 2 {
			return errs.Detail(ErrInvalidValue, "%q", field)
		}
		day, ok := parseDayValue(parts[0])
		if !ok {
			return errs.Detail(ErrInvalidValue, "%q", field)
		}
		nth, err := strconv.Atoi(parts[1])
		if err != nil || nth < 1 || nth > 5 {
			return errs.Detail(ErrInvalidValue, "%q", field)
		}
		s.dowNth = true
		s.dowNthDay = day % 7
		s.dowNthNum = nth
		return nil
	}
	mask, star, err := parseField(field, 0, 7, weekdayName, true)
	if err != nil {
		return err
	}
	s.dow = uint8(mask)
	s.dowStar = star
	return nil
}

// parseField parses a comma-separated cron field into a bit mask. The star
// result reports whether the whole field is a wildcard, which the day-of-month
// and day-of-week OR rule depends on. | parseField 把逗号分隔的 cron 字段解析为位图；
// star 报告整个字段是否为通配符，月内日期与星期的 OR 规则依赖它。
func parseField(field string, min, max int, nameFn func(string) (int, bool), normalizeSunday bool) (uint64, bool, error) {
	if field == "" {
		return 0, false, errs.Detail(ErrInvalidValue, "empty field")
	}
	if strings.Contains(field, "?") {
		return 0, false, errs.Detail(ErrInvalidValue, "%q", field)
	}
	parts := strings.Split(field, ",")
	var mask uint64
	star := false
	for _, part := range parts {
		lo, hi, step, partStar, err := parseTerm(part, min, max, nameFn)
		if err != nil {
			return 0, false, err
		}
		star = star || partStar
		for value := lo; value <= hi; value += step {
			bit := value
			if normalizeSunday && bit == 7 {
				bit = 0
			}
			mask |= 1 << uint(bit)
		}
	}
	return mask, star, nil
}

// parseTerm parses one list element into an inclusive range and a step. |
// parseTerm 把一个列表元素解析为闭区间与步长。
func parseTerm(term string, min, max int, nameFn func(string) (int, bool)) (int, int, int, bool, error) {
	if term == "" {
		return 0, 0, 0, false, errs.Detail(ErrInvalidValue, "empty term")
	}
	base := term
	step := 1
	hasStep := false
	if index := strings.IndexByte(term, '/'); index >= 0 {
		if strings.IndexByte(term[index+1:], '/') >= 0 {
			return 0, 0, 0, false, errs.Detail(ErrInvalidValue, "%q", term)
		}
		base = term[:index]
		n, err := strconv.Atoi(term[index+1:])
		if err != nil || n <= 0 {
			return 0, 0, 0, false, errs.Detail(ErrInvalidValue, "%q", term)
		}
		step = n
		hasStep = true
	}

	var lo, hi int
	star := false
	switch {
	case base == "*":
		lo, hi = min, max
		star = !hasStep || step == 1
	case strings.Contains(base, "-"):
		parts := strings.SplitN(base, "-", 2)
		first, err := parseValue(parts[0], min, max, nameFn)
		if err != nil {
			return 0, 0, 0, false, err
		}
		last, err := parseValue(parts[1], min, max, nameFn)
		if err != nil {
			return 0, 0, 0, false, err
		}
		if first > last {
			return 0, 0, 0, false, errs.Detail(ErrInvalidValue, "%q", term)
		}
		lo, hi = first, last
	default:
		value, err := parseValue(base, min, max, nameFn)
		if err != nil {
			return 0, 0, 0, false, err
		}
		lo = value
		hi = value
		if hasStep {
			hi = max
		}
	}
	if lo < min || hi > max {
		return 0, 0, 0, false, errs.Detail(ErrInvalidValue, "%q", term)
	}
	return lo, hi, step, star, nil
}

// parseValue parses one numeric or named value within [min, max]. |
// parseValue 解析 [min, max] 范围内的一个数字或名称。
func parseValue(token string, min, max int, nameFn func(string) (int, bool)) (int, error) {
	if token == "" {
		return 0, errs.Detail(ErrInvalidValue, "empty value")
	}
	if value, err := strconv.Atoi(token); err == nil {
		if value < min || value > max {
			return 0, errs.Detail(ErrInvalidValue, "%q", token)
		}
		return value, nil
	}
	if nameFn != nil {
		if value, ok := nameFn(strings.ToUpper(token)); ok {
			if value < min || value > max {
				return 0, errs.Detail(ErrInvalidValue, "%q", token)
			}
			return value, nil
		}
	}
	return 0, errs.Detail(ErrInvalidValue, "%q", token)
}

// parseDayValue parses a day-of-week token as a numeric value or a name. |
// parseDayValue 把星期标记解析为数字或名称。
func parseDayValue(token string) (int, bool) {
	if value, err := strconv.Atoi(token); err == nil {
		if value < 0 || value > 7 {
			return 0, false
		}
		return value, true
	}
	return weekdayName(strings.ToUpper(token))
}

// parseYear parses the optional year field into a bit set relative to 1970. |
// parseYear 把可选年份字段解析为相对 1970 年的位图。
func parseYear(field string) ([3]uint64, bool, error) {
	var years [3]uint64
	if field == "*" {
		return years, false, nil
	}
	parts := strings.Split(field, ",")
	for _, part := range parts {
		lo, hi, step, star, err := parseTerm(part, minScheduleYear, maxScheduleYear, nil)
		if err != nil {
			return years, false, err
		}
		if star {
			return years, false, nil
		}
		for year := lo; year <= hi; year += step {
			index := year - minScheduleYear
			years[index/64] |= 1 << uint(index%64)
		}
	}
	return years, true, nil
}

// monthName maps a three-letter English month name to its number. |
// monthName 把三字母英文月份名映射为月份数字。
func monthName(name string) (int, bool) {
	switch name {
	case "JAN":
		return 1, true
	case "FEB":
		return 2, true
	case "MAR":
		return 3, true
	case "APR":
		return 4, true
	case "MAY":
		return 5, true
	case "JUN":
		return 6, true
	case "JUL":
		return 7, true
	case "AUG":
		return 8, true
	case "SEP":
		return 9, true
	case "OCT":
		return 10, true
	case "NOV":
		return 11, true
	case "DEC":
		return 12, true
	default:
		return 0, false
	}
}

// weekdayName maps a three-letter English weekday name to its number. |
// weekdayName 把三字母英文星期名映射为星期数字。
func weekdayName(name string) (int, bool) {
	switch name {
	case "SUN":
		return 0, true
	case "MON":
		return 1, true
	case "TUE":
		return 2, true
	case "WED":
		return 3, true
	case "THU":
		return 4, true
	case "FRI":
		return 5, true
	case "SAT":
		return 6, true
	default:
		return 0, false
	}
}
