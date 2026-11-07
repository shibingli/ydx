package cn

import (
	"strings"

	"github.com/shibingli/ydx/errs"
)

// ErrInvalidUSCC reports a malformed or checksum-invalid unified social credit code. | ErrInvalidUSCC 表示统一社会信用代码格式非法或校验码不匹配。
var ErrInvalidUSCC = errs.New("cn: invalid unified social credit code | cn：统一社会信用代码非法")

// Unknown decode names. | 未知解码名称。
const nameUnknown = "unknown"

// usccAlphabet is the official GB 32100-2015 alphabet of 31 characters. It excludes the easily
// confused letters I, O, S, V and Z. | usccAlphabet 是 GB 32100-2015 规定的 31 字符字母表，排除容易
// 混淆的字母 I、O、S、V 与 Z。
const usccAlphabet = "0123456789ABCDEFGHJKLMNPQRTUWXY"

// usccWeights are the GB 32100-2015 weights for the first 17 characters. | usccWeights 是 GB 32100-2015 对前 17 个字符的权重。
var usccWeights = [17]int{1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28}

// usccRegistrationAuthorities decodes the first character, the registration authority code. | usccRegistrationAuthorities 解码第一个字符，即登记管理部门代码。
var usccRegistrationAuthorities = map[byte]string{
	'1': "organization_establishment", // 机构编制 | organization establishment
	'2': "foreign_affairs",            // 外交 | foreign affairs
	'3': "justice_administration",     // 司法行政 | justice administration
	'4': "culture",                    // 文化 | culture
	'5': "civil_affairs",              // 民政 | civil affairs
	'6': "tourism",                    // 旅游 | tourism
	'7': "religious_affairs",          // 宗教 | religious affairs
	'8': "trade_union",                // 工会 | trade union
	'9': "market_regulation",          // 工商 | market regulation
	'A': "military_establishment",     // 中央军委改革和编制办公室 | military establishment
	'N': "agriculture",                // 农业 | agriculture
	'Y': "other",                      // 其他 | other
}

// usccEntityTypes decodes the first two characters, the authority plus the entity category. | usccEntityTypes 解码前两个字符，即登记管理部门与机构类别。
var usccEntityTypes = map[string]string{
	"11": "government_agency",               // 机关 | government agency
	"12": "public_institution",              // 事业单位 | public institution
	"13": "mass_organization",               // 群众团体 | mass organization
	"19": "other",                           // 其他 | other
	"51": "social_organization",             // 社会团体 | social organization
	"52": "private_non_enterprise_unit",     // 民办非企业单位 | private non-enterprise unit
	"53": "foundation",                      // 基金会 | foundation
	"59": "other",                           // 其他 | other
	"91": "enterprise",                      // 企业 | enterprise
	"92": "individual_business",             // 个体工商户 | individual business
	"93": "farmer_professional_cooperative", // 农民专业合作社 | farmer professional cooperative
	"Y1": "other",                           // 其他 | other
}

// UnifiedSocialCreditCode is the decoded form of a GB 32100-2015 code. | UnifiedSocialCreditCode 是 GB 32100-2015 代码的解码结果。
type UnifiedSocialCreditCode struct {
	// Code is the normalized 18-character upper-case code. | Code 是规范化后的 18 位大写代码。
	Code string `json:"code"`
	// RegistrationAuthority is the one-character registration authority code. | RegistrationAuthority 是一位登记管理部门代码。
	RegistrationAuthority string `json:"registrationAuthority"`
	// RegistrationAuthorityName is the English key of the authority, or "unknown". | RegistrationAuthorityName 是登记管理部门的英文键，未知时为 "unknown"。
	RegistrationAuthorityName string `json:"registrationAuthorityName"`
	// EntityType is the two-character authority plus entity-category code. | EntityType 是两位的登记管理部门加机构类别代码。
	EntityType string `json:"entityType"`
	// EntityTypeName is the English key of the entity type, or "unknown". | EntityTypeName 是机构类别的英文键，未知时为 "unknown"。
	EntityTypeName string `json:"entityTypeName"`
	// RegionCode is the six-character registration region code. | RegionCode 是六位登记地区码。
	RegionCode string `json:"regionCode"`
	// OrganizationCode is the nine-character organization identifier at positions 9 through 17. | OrganizationCode 是第 9 至 17 位的九位组织机构标识。
	OrganizationCode string `json:"organizationCode"`
}

// ValidateUnifiedSocialCreditCode reports whether raw is a valid GB 32100-2015 unified social credit
// code. | ValidateUnifiedSocialCreditCode 报告 raw 是否为合法的 GB 32100-2015 统一社会信用代码。
//
// The check covers the 18-character length, membership in the 31-character alphabet
// "0123456789ABCDEFGHJKLMNPQRTUWXY" (I, O, S, V and Z are not allowed) and the MOD 31 check
// character computed with weights 1,3,9,27,19,26,16,17,20,29,25,13,8,24,10,30,28. Lower-case input
// is upper-cased first. | 校验覆盖 18 位长度、是否属于 31 字符字母表
// "0123456789ABCDEFGHJKLMNPQRTUWXY"（不允许 I、O、S、V、Z）以及按权重
// 1,3,9,27,19,26,16,17,20,29,25,13,8,24,10,30,28 计算的 MOD 31 校验字符。小写输入会先转为大写。
func ValidateUnifiedSocialCreditCode(raw string) bool {
	s, ok := normalizeUSCC(raw)
	if !ok {
		return false
	}
	return usccCheckDigit(s[:17]) == s[17]
}

// ParseUnifiedSocialCreditCode decodes a valid GB 32100-2015 code. | ParseUnifiedSocialCreditCode 解码合法的 GB 32100-2015 代码。
//
// The returned structure exposes the registration authority, entity type, region and organization
// code embedded in the code. Unknown authority or entity-type values are reported as "unknown"
// instead of failing, because GB 32100 leaves room for future allocations. | 返回结构暴露代码中内嵌的
// 登记管理部门、机构类别、地区与组织机构代码。未知的部门或类别值报告为 "unknown" 而不是失败，
// 因为 GB 32100 为未来分配保留了空间。
func ParseUnifiedSocialCreditCode(raw string) (*UnifiedSocialCreditCode, error) {
	s, ok := normalizeUSCC(raw)
	if !ok {
		return nil, errs.Detail(ErrInvalidUSCC, "expected 18 characters from the GB 32100 alphabet | 需要 GB 32100 字母表中的 18 个字符")
	}
	if usccCheckDigit(s[:17]) != s[17] {
		return nil, errs.Detail(ErrInvalidUSCC, "MOD 31 check character mismatch | MOD 31 校验字符不匹配")
	}

	authority := s[:1]
	authorityName, ok := usccRegistrationAuthorities[s[0]]
	if !ok {
		authorityName = nameUnknown
	}
	entityType := s[:2]
	entityName, ok := usccEntityTypes[entityType]
	if !ok {
		entityName = nameUnknown
	}

	return &UnifiedSocialCreditCode{
		Code:                      s,
		RegistrationAuthority:     authority,
		RegistrationAuthorityName: authorityName,
		EntityType:                entityType,
		EntityTypeName:            entityName,
		RegionCode:                s[2:8],
		OrganizationCode:          s[8:17],
	}, nil
}

// normalizeUSCC trims, upper-cases and validates length plus alphabet membership. | normalizeUSCC 去除空白、转大写并校验长度与字母表成员资格。
func normalizeUSCC(raw string) (string, bool) {
	s := strings.ToUpper(strings.TrimSpace(raw))
	if len(s) != 18 {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(usccAlphabet, s[i]) < 0 {
			return "", false
		}
	}
	return s, true
}

// usccCheckDigit computes the MOD 31 check character for a 17-character base. | usccCheckDigit 计算 17 位基串的 MOD 31 校验字符。
func usccCheckDigit(base string) byte {
	sum := 0
	for i := 0; i < len(usccWeights); i++ {
		sum += strings.IndexByte(usccAlphabet, base[i]) * usccWeights[i]
	}
	return usccAlphabet[(31-sum%31)%31]
}
