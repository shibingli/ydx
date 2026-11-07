package cn

import (
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Identity-card sentinels. | 身份证哨兵错误。
var (
	// ErrInvalidIDCard reports a malformed resident identity card number. | ErrInvalidIDCard 表示居民身份证号码格式非法。
	ErrInvalidIDCard = errs.New("cn: invalid resident identity card number | cn：居民身份证号码非法")
	// ErrIDCardChecksum reports an ISO 7064 MOD 11-2 check-digit mismatch. | ErrIDCardChecksum 表示 ISO 7064 MOD 11-2 校验码不匹配。
	ErrIDCardChecksum = errs.New("cn: identity card checksum mismatch | cn：身份证校验码不匹配")
	// ErrIDCardBirthdate reports an unparsable or implausible birth date. | ErrIDCardBirthdate 表示出生日期无法解析或不在合理范围。
	ErrIDCardBirthdate = errs.New("cn: identity card birthdate is invalid | cn：身份证出生日期非法")
	// ErrIDCardRegion reports a region code whose province-level prefix is not recognized. | ErrIDCardRegion 表示地区码的省级前缀无法识别。
	ErrIDCardRegion = errs.New("cn: identity card region code is not recognized | cn：身份证地区码无法识别")
)

// idCardWeights are the ISO 7064 MOD 11-2 weights for the first 17 digits, from left to right. | idCardWeights 是 ISO 7064 MOD 11-2 对前 17 位从左到右的权重。
var idCardWeights = [17]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}

// idCardCheckMap maps sum modulo 11 to the check character. | idCardCheckMap 把和模 11 映射到校验字符。
const idCardCheckMap = "10X98765432"

// idCardLocation is the civil time zone used for birth dates and age calculation. | idCardLocation 是出生日期与年龄计算使用的民用时区。
var idCardLocation = time.FixedZone("CST", 8*60*60)

// minIDCardBirthYear is the earliest plausible birth year. A 15-digit number is upgraded with the
// 19xx rule, so a year below 1900 cannot be represented by the legacy form and is treated as a data
// entry error. | minIDCardBirthYear 是最早的合理出生年份。15 位号码按 19xx 规则升级，因此早于
// 1900 年的年份无法由旧格式表示，视为录入错误。
const minIDCardBirthYear = 1900

// provincePrefixes lists the province-level region codes accepted by ParseIDCard. | provincePrefixes 列出 ParseIDCard 接受的省级地区码。
//
// The values follow GB/T 2260: 11 Beijing, 12 Tianjin, 13 Hebei, 14 Shanxi, 15 Inner Mongolia,
// 21 Liaoning, 22 Jilin, 23 Heilongjiang, 31 Shanghai, 32 Jiangsu, 33 Zhejiang, 34 Anhui, 35 Fujian,
// 36 Jiangxi, 37 Shandong, 41 Henan, 42 Hubei, 43 Hunan, 44 Guangdong, 45 Guangxi, 46 Hainan,
// 50 Chongqing, 51 Sichuan, 52 Guizhou, 53 Yunnan, 54 Tibet, 61 Shaanxi, 62 Gansu, 63 Qinghai,
// 64 Ningxia, 65 Xinjiang, 71 Taiwan, 81 Hong Kong and 82 Macao. | 取值遵循 GB/T 2260：11 北京、
// 12 天津、13 河北、14 山西、15 内蒙古、21 辽宁、22 吉林、23 黑龙江、31 上海、32 江苏、33 浙江、
// 34 安徽、35 福建、36 江西、37 山东、41 河南、42 湖北、43 湖南、44 广东、45 广西、46 海南、
// 50 重庆、51 四川、52 贵州、53 云南、54 西藏、61 陕西、62 甘肃、63 青海、64 宁夏、65 新疆、
// 71 台湾、81 香港、82 澳门。
//
// Only the province level is checked; the full GB/T 2260 county-level table is not embedded, so a
// code with a valid province prefix but an unknown city or district is accepted. | 仅校验省级前缀；
// 未内嵌完整的 GB/T 2260 县级表，因此省级前缀合法但市、区未知的代码仍会被接受。
var provincePrefixes = map[string]string{
	"11": "beijing",
	"12": "tianjin",
	"13": "hebei",
	"14": "shanxi",
	"15": "inner_mongolia",
	"21": "liaoning",
	"22": "jilin",
	"23": "heilongjiang",
	"31": "shanghai",
	"32": "jiangsu",
	"33": "zhejiang",
	"34": "anhui",
	"35": "fujian",
	"36": "jiangxi",
	"37": "shandong",
	"41": "henan",
	"42": "hubei",
	"43": "hunan",
	"44": "guangdong",
	"45": "guangxi",
	"46": "hainan",
	"50": "chongqing",
	"51": "sichuan",
	"52": "guizhou",
	"53": "yunnan",
	"54": "tibet",
	"61": "shaanxi",
	"62": "gansu",
	"63": "qinghai",
	"64": "ningxia",
	"65": "xinjiang",
	"71": "taiwan",
	"81": "hong_kong",
	"82": "macao",
}

// IDCard is the parsed form of a resident identity card number. | IDCard 是居民身份证号码的解析结果。
type IDCard struct {
	// Number is the normalized 18-character number; a 15-digit input is upgraded first. | Number 是规范化后的 18 位号码；15 位输入会先升级。
	Number string `json:"number"`
	// RegionCode is the six-digit region code (the first six characters). | RegionCode 是六位地区码（前六个字符）。
	RegionCode string `json:"regionCode"`
	// Birthdate is the birth date in "YYYY-MM-DD" form. | Birthdate 是 "YYYY-MM-DD" 形式的出生日期。
	Birthdate string `json:"birthdate"`
	// Gender is "male", "female" or "unknown". | Gender 取值为 "male"、"female" 或 "unknown"。
	Gender string `json:"gender"`
	// Age is the completed age in years at parse time, using China Standard Time. | Age 是解析时按中国标准时间计算的周岁。
	Age int `json:"age"`
	// Valid reports that every structural, checksum, birthdate and region check passed. | Valid 表示结构、校验码、出生日期与地区检查全部通过。
	Valid bool `json:"valid"`
}

// ParseIDCard parses an 18-digit resident identity card number. | ParseIDCard 解析 18 位居民身份证号码。
//
// Legacy 15-digit numbers are accepted and upgraded with the documented 19xx rule: the six-digit
// region code is followed by YYMMDD and a three-digit sequence, and "19" is inserted before YY
// because the 15-digit form only existed for people born in the 20th century. The 18th digit is then
// computed with ISO 7064 MOD 11-2. | 接受 15 位旧号码并按文档化的 19xx 规则升级：六位地区码之后
// 是 YYMMDD 与三位顺序码，由于 15 位格式只用于 20 世纪出生的人，因此在 YY 前插入 "19"，随后用
// ISO 7064 MOD 11-2 计算第 18 位。
//
// Validation covers the 18-character length, the first 17 numeric digits, the MOD 11-2 check digit
// (weights 7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2 and check map "10X98765432"), the birth date with a
// plausible range of 1900-01-01 through today, and the province-level region prefix. The check digit
// may be written in lower-case x. | 校验覆盖 18 位长度、前 17 位数字、MOD 11-2 校验码（权重
// 7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2，校验映射 "10X98765432"）、出生日期（合理范围
// 1900-01-01 至今天）以及省级地区前缀。校验码允许写作小写 x。
func ParseIDCard(raw string) (*IDCard, error) {
	return parseIDCardAt(raw, time.Now())
}

// ValidateIDCard reports whether raw is a valid resident identity card number. | ValidateIDCard 报告 raw 是否为合法居民身份证号码。
func ValidateIDCard(raw string) bool {
	_, err := ParseIDCard(raw)
	return err == nil
}

// IDCardBirthdate returns the "YYYY-MM-DD" birth date of raw, or an empty string when invalid. | IDCardBirthdate 返回 raw 的 "YYYY-MM-DD" 出生日期，非法时返回空串。
func IDCardBirthdate(raw string) string {
	card, err := ParseIDCard(raw)
	if err != nil {
		return ""
	}
	return card.Birthdate
}

// IDCardGender returns "male" or "female" for raw, or "unknown" when invalid. | IDCardGender 返回 raw 的 "male" 或 "female"，非法时返回 "unknown"。
func IDCardGender(raw string) string {
	card, err := ParseIDCard(raw)
	if err != nil {
		return "unknown"
	}
	return card.Gender
}

// MaskIDCard masks an identity card number, keeping the first six and last four characters. | MaskIDCard 掩码身份证号码，保留前六位与后四位。
//
// "11010519491231002X" becomes "110105********002X". The masking is structural and does not require
// the checksum to pass; values that are neither 15 nor 18 characters fall back to MaskGeneric. |
// "11010519491231002X" 变为 "110105********002X"。掩码只依赖结构，不要求校验码通过；既非 15 位
// 也非 18 位的值回退到 MaskGeneric。
func MaskIDCard(raw string) string {
	s := strings.ToUpper(strings.TrimSpace(raw))
	switch {
	case len(s) == 18:
		return s[:6] + "********" + s[14:]
	case len(s) == 15 && allDigits(s):
		return s[:6] + "******" + s[12:]
	default:
		return MaskGeneric(s)
	}
}

// parseIDCardAt is ParseIDCard with an explicit clock for deterministic age calculation. | parseIDCardAt 是带显式时钟的 ParseIDCard，用于确定性的年龄计算。
func parseIDCardAt(raw string, now time.Time) (*IDCard, error) {
	s := strings.ToUpper(strings.TrimSpace(raw))
	if len(s) == 15 {
		if !allDigits(s) {
			return nil, errs.Detail(ErrInvalidIDCard, "15-digit form must contain digits only | 15 位格式只能包含数字")
		}
		s = upgradeIDCard15(s)
	}
	if len(s) != 18 {
		return nil, errs.Detail(ErrInvalidIDCard, "expected 15 or 18 characters, got %d | 需要 15 或 18 个字符，实际 %d", len(s), len(s))
	}
	if !allDigits(s[:17]) {
		return nil, errs.Detail(ErrInvalidIDCard, "the first 17 characters must be digits | 前 17 个字符必须为数字")
	}
	if (s[17] < '0' || s[17] > '9') && s[17] != 'X' {
		return nil, errs.Detail(ErrInvalidIDCard, "the last character must be a digit or X | 最后一个字符必须为数字或 X")
	}
	if got := idCardCheckDigit(s[:17]); got != s[17] {
		return nil, errs.Detail(ErrIDCardChecksum, "check digit mismatch | 校验码不匹配")
	}

	birth, err := time.ParseInLocation("20060102", s[6:14], idCardLocation)
	if err != nil {
		return nil, errs.Detail(ErrIDCardBirthdate, "cannot parse birth date | 无法解析出生日期")
	}
	today := now.In(idCardLocation)
	latest := time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, idCardLocation)
	earliest := time.Date(minIDCardBirthYear, time.January, 1, 0, 0, 0, 0, idCardLocation)
	if birth.Before(earliest) || birth.After(latest) {
		return nil, errs.Detail(ErrIDCardBirthdate, "birth date is outside the plausible range | 出生日期不在合理范围内")
	}

	region := s[:6]
	if _, ok := provincePrefixes[region[:2]]; !ok {
		return nil, errs.Detail(ErrIDCardRegion, "province-level prefix is not in the GB/T 2260 table | 省级前缀不在 GB/T 2260 表中")
	}

	gender := "female"
	if (s[16]-'0')%2 == 1 {
		gender = "male"
	}

	return &IDCard{
		Number:     s,
		RegionCode: region,
		Birthdate:  birth.Format("2006-01-02"),
		Gender:     gender,
		Age:        fullYearsBetween(birth, today),
		Valid:      true,
	}, nil
}

// upgradeIDCard15 converts a 15-character number to the 18-character form. | upgradeIDCard15 把 15 位号码转换为 18 位形式。
func upgradeIDCard15(s string) string {
	base := s[:6] + "19" + s[6:]
	return base + string(idCardCheckDigit(base))
}

// idCardCheckDigit computes the ISO 7064 MOD 11-2 check character for a 17-character base. | idCardCheckDigit 计算 17 位基串的 ISO 7064 MOD 11-2 校验字符。
func idCardCheckDigit(base string) byte {
	sum := 0
	for i := 0; i < len(idCardWeights); i++ {
		sum += int(base[i]-'0') * idCardWeights[i]
	}
	return idCardCheckMap[sum%11]
}

// fullYearsBetween returns completed years from birth to now. | fullYearsBetween 返回 birth 到 now 的完整年数。
func fullYearsBetween(birth, now time.Time) int {
	years := now.Year() - birth.Year()
	if now.Month() < birth.Month() || (now.Month() == birth.Month() && now.Day() < birth.Day()) {
		years--
	}
	if years < 0 {
		return 0
	}
	return years
}

// allDigits reports whether s is non-empty and contains ASCII digits only. | allDigits 报告 s 是否非空且仅含 ASCII 数字。
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
