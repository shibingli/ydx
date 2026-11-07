package cn

import (
	"strings"

	"github.com/shibingli/ydx/errs"
)

// ErrInvalidMobile reports a malformed or unassigned mainland mobile number. | ErrInvalidMobile 表示中国大陆手机号格式非法或号段未分配。
var ErrInvalidMobile = errs.New("cn: invalid mainland mobile number | cn：中国大陆手机号非法")

// Carrier identifiers returned by Carrier. | Carrier 返回的运营商标识。
const (
	// CarrierChinaMobile is China Mobile (中国移动). | CarrierChinaMobile 是中国移动。
	CarrierChinaMobile = "china_mobile"
	// CarrierChinaUnicom is China Unicom (中国联通). | CarrierChinaUnicom 是中国联通。
	CarrierChinaUnicom = "china_unicom"
	// CarrierChinaTelecom is China Telecom (中国电信). | CarrierChinaTelecom 是中国电信。
	CarrierChinaTelecom = "china_telecom"
	// CarrierChinaBroadnet is China Broadnet (中国广电). | CarrierChinaBroadnet 是中国广电。
	CarrierChinaBroadnet = "china_broadnet"
	// CarrierUnknown marks a structurally valid number whose prefix is not in the carrier table. | CarrierUnknown 表示结构合法但号段不在运营商表中的号码。
	CarrierUnknown = "unknown"
)

// mainlandMobilePrefixCarriers maps the three-digit 1xx prefix of a mainland mobile number to its
// carrier. | mainlandMobilePrefixCarriers 把中国大陆手机号的三位 1xx 号段映射到运营商。
//
// The table follows the MIIT allocations current as of 2025: 13x, 14x, 15x, 16x, 17x, 18x and 19x.
// 154, 160, 161, 163, 164, 168, 169, 179 and 194 are not assigned to public mobile service and are
// deliberately absent, so IsMainlandMobile rejects them. Update this table when MIIT publishes a new
// allocation; every validator and masking helper reads it. | 本表依据截至 2025 年的工信部号段分配：
// 13x、14x、15x、16x、17x、18x、19x。154、160、161、163、164、168、169、179、194 尚未分配给公众
// 移动业务，故有意留空，IsMainlandMobile 会拒绝它们。工信部发布新号段时只需更新本表，所有校验与
// 掩码辅助函数都会自动生效。
//
//   - China Mobile: 134-139, 147, 148, 150-152, 157-159, 165 (MVNO), 172, 178, 182-184, 187,
//     188, 195, 197, 198, and the 140/143/144 IoT ranges. | 中国移动：134-139、147、148、
//     150-152、157-159、165（虚拟运营商）、172、178、182-184、187、188、195、197、198，以及
//     140/143/144 物联网号段。
//   - China Unicom: 130-132, 145, 146 (IoT), 155, 156, 162 (MVNO), 166, 167 (MVNO), 171, 175,
//     176, 185, 186, 196, and the 142 IoT range. | 中国联通：130-132、145、146（物联网）、155、
//     156、162（虚拟运营商）、166、167（虚拟运营商）、171、175、176、185、186、196，以及 142
//     物联网号段。
//   - China Telecom: 133, 141 (IoT), 149 (IoT), 153, 173, 174 (satellite), 177, 180, 181, 189,
//     190, 191, 193, 199. | 中国电信：133、141（物联网）、149（物联网）、153、173、174（卫星）、
//     177、180、181、189、190、191、193、199。
//   - China Broadnet: 192. | 中国广电：192。
var mainlandMobilePrefixCarriers = map[string]string{
	"130": CarrierChinaUnicom,
	"131": CarrierChinaUnicom,
	"132": CarrierChinaUnicom,
	"133": CarrierChinaTelecom,
	"134": CarrierChinaMobile,
	"135": CarrierChinaMobile,
	"136": CarrierChinaMobile,
	"137": CarrierChinaMobile,
	"138": CarrierChinaMobile,
	"139": CarrierChinaMobile,

	"140": CarrierChinaMobile,  // IoT | 物联网
	"141": CarrierChinaTelecom, // IoT | 物联网
	"142": CarrierChinaUnicom,  // IoT | 物联网
	"143": CarrierChinaMobile,  // IoT | 物联网
	"144": CarrierChinaMobile,  // IoT | 物联网
	"145": CarrierChinaUnicom,
	"146": CarrierChinaUnicom, // IoT | 物联网
	"147": CarrierChinaMobile,
	"148": CarrierChinaMobile,  // IoT | 物联网
	"149": CarrierChinaTelecom, // IoT | 物联网

	"150": CarrierChinaMobile,
	"151": CarrierChinaMobile,
	"152": CarrierChinaMobile,
	"153": CarrierChinaTelecom,
	"155": CarrierChinaUnicom,
	"156": CarrierChinaUnicom,
	"157": CarrierChinaMobile,
	"158": CarrierChinaMobile,
	"159": CarrierChinaMobile,

	"162": CarrierChinaUnicom, // MVNO | 虚拟运营商
	"165": CarrierChinaMobile, // MVNO | 虚拟运营商
	"166": CarrierChinaUnicom,
	"167": CarrierChinaUnicom, // MVNO | 虚拟运营商

	"170": CarrierUnknown, // MVNO, resolved by mainlandMobileFourPrefixCarriers | 虚拟运营商，按四位号段细分
	"171": CarrierChinaUnicom,
	"172": CarrierChinaMobile,
	"173": CarrierChinaTelecom,
	"174": CarrierChinaTelecom, // satellite | 卫星通信
	"175": CarrierChinaMobile,
	"176": CarrierChinaUnicom,
	"177": CarrierChinaTelecom,
	"178": CarrierChinaMobile,

	"180": CarrierChinaTelecom,
	"181": CarrierChinaTelecom,
	"182": CarrierChinaMobile,
	"183": CarrierChinaMobile,
	"184": CarrierChinaMobile,
	"185": CarrierChinaUnicom,
	"186": CarrierChinaUnicom,
	"187": CarrierChinaMobile,
	"188": CarrierChinaMobile,
	"189": CarrierChinaTelecom,

	"190": CarrierChinaTelecom,
	"191": CarrierChinaTelecom,
	"192": CarrierChinaBroadnet,
	"193": CarrierChinaTelecom,
	"195": CarrierChinaMobile,
	"196": CarrierChinaUnicom,
	"197": CarrierChinaMobile,
	"198": CarrierChinaMobile,
	"199": CarrierChinaTelecom,
}

// mainlandMobileFourPrefixCarriers refines the 170 virtual-operator range, whose sub-ranges are
// hosted by different base networks. | mainlandMobileFourPrefixCarriers 细分 170 虚拟运营商号段，
// 其各子号段由不同基础网络承载。
var mainlandMobileFourPrefixCarriers = map[string]string{
	"1700": CarrierChinaTelecom,
	"1701": CarrierChinaTelecom,
	"1702": CarrierChinaTelecom,
	"1703": CarrierChinaMobile,
	"1704": CarrierChinaUnicom,
	"1705": CarrierChinaMobile,
	"1706": CarrierChinaMobile,
	"1707": CarrierChinaUnicom,
	"1708": CarrierChinaUnicom,
	"1709": CarrierChinaTelecom,
}

// NormalizeMobile normalizes a mainland mobile number to E.164 form. | NormalizeMobile 把中国大陆手机号规范化为 E.164 形式。
//
// It accepts the 11-digit local form (13800138000), an optional country code written as +86, 86 or
// 0086, and ASCII spaces, tabs, hyphens, parentheses and the ideographic space as separators. The
// result is "+86" followed by the 11 local digits, for example "+8613800138000". Numbers whose length
// is not 11 digits after the country code, that do not start with 1, or whose prefix is absent from
// the MIIT table are rejected. | 接受 11 位本地形式（13800138000）、以 +86、86 或 0086 书写的可选
// 国家码，以及 ASCII 空格、制表符、连字符、圆括号与全角空格等分隔符。结果是 "+86" 加 11 位本地
// 号码，例如 "+8613800138000"。去掉国家码后不是 11 位、不以 1 开头或号段不在工信部表中的号码会被
// 拒绝。
func NormalizeMobile(raw string) (string, error) {
	local, ok := mobileLocal(raw)
	if !ok {
		return "", errs.Detail(ErrInvalidMobile, "expected 11 local digits starting with 1 | 需要以 1 开头的 11 位本地号码")
	}
	if !assignedMobilePrefix(local) {
		return "", errs.Detail(ErrInvalidMobile, "prefix %q is not assigned to mainland mobile service | 号段 %q 未分配给中国大陆移动业务", local[:3], local[:3])
	}
	return "+86" + local, nil
}

// IsMainlandMobile reports whether raw is a mainland mobile number with an assigned MIIT prefix. | IsMainlandMobile 报告 raw 是否为号段已分配的中国大陆手机号。
//
// It accepts the same country-code and separator forms as NormalizeMobile. | 接受与 NormalizeMobile 相同的国家码与分隔符形式。
func IsMainlandMobile(raw string) bool {
	local, ok := mobileLocal(raw)
	return ok && assignedMobilePrefix(local)
}

// Carrier returns the carrier of a mainland mobile number. | Carrier 返回中国大陆手机号的运营商。
//
// The result is one of CarrierChinaMobile, CarrierChinaUnicom, CarrierChinaTelecom,
// CarrierChinaBroadnet or CarrierUnknown. A structurally valid number whose prefix is not assigned
// returns CarrierUnknown with a nil error; a malformed number returns ErrInvalidMobile. | 结果为
// CarrierChinaMobile、CarrierChinaUnicom、CarrierChinaTelecom、CarrierChinaBroadnet 或
// CarrierUnknown。结构合法但号段未分配时返回 CarrierUnknown 与 nil 错误；格式非法时返回
// ErrInvalidMobile。
func Carrier(raw string) (string, error) {
	local, ok := mobileLocal(raw)
	if !ok {
		return "", errs.Detail(ErrInvalidMobile, "expected 11 local digits starting with 1 | 需要以 1 开头的 11 位本地号码")
	}
	if carrier, ok := mainlandMobileFourPrefixCarriers[local[:4]]; ok {
		return carrier, nil
	}
	if carrier, ok := mainlandMobilePrefixCarriers[local[:3]]; ok {
		return carrier, nil
	}
	return CarrierUnknown, nil
}

// MaskMobile masks a mainland mobile number, keeping the first three and last four digits. | MaskMobile 掩码中国大陆手机号，保留前三位与后四位。
//
// "13800138000" and "+86 138-0013-8000" both mask to "138****8000". Values that cannot be parsed as
// a mobile number fall back to MaskGeneric. | "13800138000" 与 "+86 138-0013-8000" 均掩码为
// "138****8000"。无法解析为手机号的值回退到 MaskGeneric。
func MaskMobile(raw string) string {
	local, ok := mobileLocal(raw)
	if !ok {
		return MaskGeneric(raw)
	}
	return local[:3] + "****" + local[7:]
}

// assignedMobilePrefix reports whether local (11 digits) has an assigned MIIT prefix. | assignedMobilePrefix 报告 local（11 位）是否具有已分配的工信部号段。
func assignedMobilePrefix(local string) bool {
	_, ok := mainlandMobilePrefixCarriers[local[:3]]
	return ok
}

// mobileLocal extracts the 11 local digits from an accepted mobile form. | mobileLocal 从接受的手机号形式中提取 11 位本地号码。
func mobileLocal(raw string) (string, bool) {
	digits, ok := sanitizeMobile(raw)
	if !ok {
		return "", false
	}
	switch {
	case strings.HasPrefix(digits, "+86"):
		digits = digits[3:]
	case strings.HasPrefix(digits, "0086"):
		digits = digits[4:]
	case len(digits) == 13 && strings.HasPrefix(digits, "86"):
		digits = digits[2:]
	}
	if len(digits) != 11 || digits[0] != '1' {
		return "", false
	}
	return digits, true
}

// sanitizeMobile removes the accepted separators and keeps digits plus one leading plus sign. | sanitizeMobile 去掉接受的分隔符，保留数字与一个前导加号。
func sanitizeMobile(raw string) (string, bool) {
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '+' && b.Len() == 0:
			b.WriteRune(r)
		case r == ' ' || r == '\t' || r == '\r' || r == '\n' || r == '-' || r == '(' || r == ')' || r == '　':
			continue
		default:
			return "", false
		}
	}
	return b.String(), true
}
