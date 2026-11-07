package ldap

import (
	"context"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Active Directory userAccountControl flags. | Active Directory
// userAccountControl 标志位。
const (
	// UACAccountDisabled disables the account. | UACAccountDisabled 禁用账号。
	UACAccountDisabled = 0x0002
	// UACLockout marks an account lockout; modern AD uses lockoutTime. | UACLockout
	// 标记账号锁定；现代 AD 使用 lockoutTime。
	UACLockout = 0x0010
	// UACPasswordNotRequired requires no password. | UACPasswordNotRequired 表示不需要口令。
	UACPasswordNotRequired = 0x0020
	// UACPasswordCannotChange forbids user password changes. | UACPasswordCannotChange 禁止用户修改口令。
	UACPasswordCannotChange = 0x0040
	// UACEncryptedTextPasswordAllowed permits reversible password storage. | UACEncryptedTextPasswordAllowed
	// 允许可逆口令存储。
	UACEncryptedTextPasswordAllowed = 0x0080
	// UACNormalAccount is the normal user account flag. | UACNormalAccount 是普通用户账号标志。
	UACNormalAccount = 0x0200
	// UACInterdomainTrustAccount is an interdomain trust account. | UACInterdomainTrustAccount
	// 是域间信任账号。
	UACInterdomainTrustAccount = 0x0800
	// UACWorkstationTrustAccount is a workstation trust account. | UACWorkstationTrustAccount
	// 是工作站信任账号。
	UACWorkstationTrustAccount = 0x1000
	// UACServerTrustAccount is a server trust account. | UACServerTrustAccount 是服务器信任账号。
	UACServerTrustAccount = 0x2000
	// UACDontExpirePassword never expires the password. | UACDontExpirePassword 表示口令永不过期。
	UACDontExpirePassword = 0x10000
	// UACMNSLogonAccount is an MNS logon account. | UACMNSLogonAccount 是 MNS 登录账号。
	UACMNSLogonAccount = 0x20000
	// UACSmartcardRequired requires smart-card logon. | UACSmartcardRequired 要求智能卡登录。
	UACSmartcardRequired = 0x40000
	// UACTrustedForDelegation marks a trusted-for-delegation account. | UACTrustedForDelegation
	// 标记可委派账号。
	UACTrustedForDelegation = 0x80000
	// UACNotDelegated forbids delegation. | UACNotDelegated 禁止委派。
	UACNotDelegated = 0x100000
	// UACUseDESKeyOnly restricts encryption to DES. | UACUseDESKeyOnly 仅允许 DES 加密。
	UACUseDESKeyOnly = 0x200000
	// UACDontRequirePreauth disables Kerberos pre-authentication. | UACDontRequirePreauth 禁用 Kerberos 预认证。
	UACDontRequirePreauth = 0x400000
	// UACPasswordExpired forces a password change at next logon. | UACPasswordExpired 强制下次登录修改口令。
	UACPasswordExpired = 0x800000
	// UACTrustedToAuthForDelegation allows protocol transition. | UACTrustedToAuthForDelegation
	// 允许协议转换委派。
	UACTrustedToAuthForDelegation = 0x1000000
	// UACPartialSecretsAccount marks a partial-secrets account. | UACPartialSecretsAccount
	// 标记部分机密账号。
	UACPartialSecretsAccount = 0x04000000
)

// ADMatchingRuleInChain is the Active Directory recursive membership matching
// rule 1.2.840.113556.1.4.1941. | ADMatchingRuleInChain 是 Active Directory 递归
// 成员关系匹配规则 1.2.840.113556.1.4.1941。
const ADMatchingRuleInChain = "1.2.840.113556.1.4.1941"

const (
	// adFileTimeOffset is the number of 100ns ticks between 1601-01-01 and
	// 1970-01-01. | adFileTimeOffset 是 1601-01-01 到 1970-01-01 之间的 100ns 刻度数。
	adFileTimeOffset int64 = 116444736000000000
	// adFileTimeNever is the Active Directory "never" sentinel. | adFileTimeNever
	// 是 Active Directory 的“永不”哨兵值。
	adFileTimeNever int64 = math.MaxInt64
	// maxADGroupResults bounds recursive group expansion. | maxADGroupResults 限制递归组展开。
	maxADGroupResults = 10000
)

// ADUser is the typed Active Directory view of a user object. | ADUser 是用户对象的
// 类型化 Active Directory 视图。
type ADUser struct {
	// DN is the distinguished name. | DN 是可分辨名称。
	DN string
	// UPN is userPrincipalName. | UPN 是 userPrincipalName。
	UPN string
	// SAMAccountName is the down-level account name. | SAMAccountName 是下层账号名。
	SAMAccountName string
	// Mail is the mail attribute. | Mail 是 mail 属性。
	Mail string
	// DisplayName is the displayName attribute. | DisplayName 是 displayName 属性。
	DisplayName string
	// MemberOf holds direct group distinguished names. | MemberOf 保存直接组可分辨名称。
	MemberOf []string
	// UserAccountControl holds the raw userAccountControl bit mask. | UserAccountControl
	// 保存原始 userAccountControl 位掩码。
	UserAccountControl uint32
	// PwdLastSet is the last password set time; zero when never set or not requested. |
	// PwdLastSet 是最后一次设置口令的时间；从未设置或未请求时为零值。
	PwdLastSet time.Time
	// PasswordExpiry is msDS-UserPasswordExpiryTimeComputed; zero means never or
	// unavailable. | PasswordExpiry 是 msDS-UserPasswordExpiryTimeComputed；零值表示永不
	// 过期或不可用。
	PasswordExpiry time.Time
	// LastLogonTimestamp is the replicated last logon time. | LastLogonTimestamp
	// 是复制的最后登录时间。
	LastLogonTimestamp time.Time
	// LockoutTime is the lockout time; zero means not locked. | LockoutTime 是锁定时间；
	// 零值表示未锁定。
	LockoutTime time.Time
	// WhenCreated is the object creation time. | WhenCreated 是对象创建时间。
	WhenCreated time.Time
	// AccountExpires is the account expiration time; zero means never. | AccountExpires
	// 是账号过期时间；零值表示永不过期。
	AccountExpires time.Time
	// Disabled reports the UAC account-disable bit. | Disabled 报告 UAC 账号禁用位。
	Disabled bool
	// Locked reports a nonzero lockoutTime. | Locked 报告非零 lockoutTime。
	Locked bool
	// PasswordExpired reports an elapsed password expiry time or UAC password-expired bit.
	// | PasswordExpired 报告口令过期时间已过或 UAC 口令过期位。
	PasswordExpired bool
	// MustChangePassword reports pwdLastSet zero or the UAC password-expired bit. |
	// MustChangePassword 报告 pwdLastSet 为零或 UAC 口令过期位。
	MustChangePassword bool
	// AccountExpired reports an accountExpires time in the past. | AccountExpired
	// 报告 accountExpires 时间已过。
	AccountExpired bool
	// Authenticated reports whether this value came from a successful password bind. |
	// Authenticated 报告该值是否来自成功的口令绑定。
	Authenticated bool
}

// Enabled reports whether the account is neither disabled nor expired. | Enabled
// 报告账号既未禁用也未过期。
func (u *ADUser) Enabled() bool {
	if u == nil {
		return false
	}
	return !u.Disabled && !u.AccountExpired
}

// adUserAttributes is the attribute set requested for user lookup. | adUserAttributes
// 是用户查询请求的属性集合。
var adUserAttributes = []string{
	"distinguishedName",
	"userPrincipalName",
	"sAMAccountName",
	"mail",
	"displayName",
	"memberOf",
	"userAccountControl",
	"pwdLastSet",
	"msDS-UserPasswordExpiryTimeComputed",
	"lastLogonTimestamp",
	"lockoutTime",
	"whenCreated",
	"accountExpires",
}

// lookupUser searches for one user using the service connection. | lookupUser 使用
// 服务连接搜索一个用户。
func (ad *ActiveDirectory) lookupUser(ctx context.Context, identity string) (*ADUser, error) {
	if ad == nil || ad.client == nil {
		return nil, ErrServiceBindRequired
	}
	if ad.baseDN == "" {
		return nil, errs.Detail(ErrServiceBindRequired, "base DN is unknown | 基础 DN 未知")
	}
	baseDN, scope, filter, err := ad.userSearch(identity)
	if err != nil {
		return nil, err
	}
	result, searchErr := ad.client.Search(ctx, SearchOptions{
		BaseDN:     baseDN,
		Scope:      scope,
		Filter:     filter,
		Attributes: adUserAttributes,
		SizeLimit:  3,
	})
	if result == nil {
		return nil, searchErr
	}
	if len(result.Entries) > 1 {
		return nil, errs.Detail(ErrAmbiguousUser, "identity %q matches multiple entries | 身份 %q 匹配多个条目", identity, identity)
	}
	if len(result.Entries) == 0 {
		if searchErr != nil {
			return nil, searchErr
		}
		return nil, errs.Detail(ErrNoSuchObject, "user %q not found | 用户 %q 不存在", identity, identity)
	}
	user, err := entryToADUser(result.Entries[0])
	if err != nil {
		return nil, err
	}
	return user, nil
}

// userSearch returns the base, scope and typed filter for an AD login name. | userSearch
// 返回 AD 登录名对应的基准、范围与类型化过滤器。
func (ad *ActiveDirectory) userSearch(identity string) (string, Scope, Filter, error) {
	identity = strings.TrimSpace(identity)
	if identity == "" {
		return "", ScopeBaseObject, nil, errs.Detail(ErrInvalidConfig, "empty user identity | 用户身份为空")
	}
	if looksLikeDN(identity) {
		return identity, ScopeBaseObject, Present("objectClass"), nil
	}
	domain := ad.domain
	account := identity
	var candidates []Filter
	if index := strings.IndexByte(identity, '\\'); index >= 0 {
		domain = identity[:index]
		account = identity[index+1:]
		if account == "" {
			return "", ScopeBaseObject, nil, errs.Detail(ErrInvalidConfig, "empty account after domain | 域后的账号为空")
		}
		candidates = append(candidates, Equal("sAMAccountName", account))
		if domain != "" {
			candidates = append(candidates, Equal("userPrincipalName", account+"@"+domain))
		}
	} else if index := strings.IndexByte(identity, '@'); index >= 0 {
		candidates = append(candidates, Equal("userPrincipalName", identity))
		account = identity[:index]
		if account != "" {
			candidates = append(candidates, Equal("sAMAccountName", account))
		}
	} else {
		candidates = append(candidates, Equal("sAMAccountName", account))
		if domain != "" {
			candidates = append(candidates, Equal("userPrincipalName", account+"@"+domain))
		}
	}
	if len(candidates) == 1 {
		return ad.baseDN, ScopeWholeSubtree, candidates[0], nil
	}
	return ad.baseDN, ScopeWholeSubtree, Or(candidates...), nil
}

// entryToADUser converts a directory entry into its typed AD view. | entryToADUser
// 把目录条目转换为类型化 AD 视图。
func entryToADUser(entry *Entry) (*ADUser, error) {
	if entry == nil {
		return nil, errs.Detail(ErrInvalidResponse, "nil user entry | 用户条目为空")
	}
	user := &ADUser{
		DN:             entry.DN,
		UPN:            entry.First("userPrincipalName"),
		SAMAccountName: entry.First("sAMAccountName"),
		Mail:           entry.First("mail"),
		DisplayName:    entry.First("displayName"),
		MemberOf:       entry.Get("memberOf"),
	}
	uac, _, err := parseADUint(entry.First("userAccountControl"), 32)
	if err != nil {
		return nil, wrapADAttributeError(err, "userAccountControl")
	}
	user.UserAccountControl = uint32(uac)
	pwdLastSet, pwdPresent, err := parseADInt(entry.First("pwdLastSet"))
	if err != nil {
		return nil, wrapADAttributeError(err, "pwdLastSet")
	}
	if pwdPresent {
		user.PwdLastSet = adFileTime(pwdLastSet)
		user.MustChangePassword = pwdLastSet == 0
	}
	passwordExpiry, expiryPresent, err := parseADInt(entry.First("msDS-UserPasswordExpiryTimeComputed"))
	if err != nil {
		return nil, wrapADAttributeError(err, "msDS-UserPasswordExpiryTimeComputed")
	}
	if expiryPresent {
		user.PasswordExpiry = adFileTime(passwordExpiry)
	}
	lastLogon, logonPresent, err := parseADInt(entry.First("lastLogonTimestamp"))
	if err != nil {
		return nil, wrapADAttributeError(err, "lastLogonTimestamp")
	}
	if logonPresent {
		user.LastLogonTimestamp = adFileTime(lastLogon)
	}
	lockout, lockoutPresent, err := parseADInt(entry.First("lockoutTime"))
	if err != nil {
		return nil, wrapADAttributeError(err, "lockoutTime")
	}
	if lockoutPresent {
		user.LockoutTime = adFileTime(lockout)
		user.Locked = lockout != 0
	}
	accountExpires, accountPresent, err := parseADInt(entry.First("accountExpires"))
	if err != nil {
		return nil, wrapADAttributeError(err, "accountExpires")
	}
	if accountPresent {
		user.AccountExpires = adFileTime(accountExpires)
	}
	whenCreated := entry.First("whenCreated")
	if whenCreated != "" {
		created, err := parseADGeneralizedTime(whenCreated)
		if err != nil {
			return nil, wrapADAttributeError(err, "whenCreated")
		}
		user.WhenCreated = created
	}
	user.Disabled = user.UserAccountControl&UACAccountDisabled != 0
	passwordExpiredFlag := user.UserAccountControl&UACPasswordExpired != 0
	user.MustChangePassword = user.MustChangePassword || passwordExpiredFlag
	now := time.Now()
	user.PasswordExpired = passwordExpiredFlag || (!user.PasswordExpiry.IsZero() && user.PasswordExpiry.Before(now))
	if accountPresent && accountExpires > 0 && accountExpires != adFileTimeNever {
		user.AccountExpired = !user.AccountExpires.IsZero() && user.AccountExpires.Before(now)
	}
	return user, nil
}

// parseADUint parses an optional unsigned decimal attribute. | parseADUint 解析
// 可选的十进制无符号属性。
func parseADUint(value string, bitSize int) (uint64, bool, error) {
	if value == "" {
		return 0, false, nil
	}
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, bitSize)
	if err != nil {
		return 0, false, errs.WrapDetail(err, ErrInvalidResponse, "invalid integer attribute | 整数属性非法")
	}
	return parsed, true, nil
}

// parseADInt parses an optional signed decimal attribute. | parseADInt 解析可选的
// 十进制有符号属性。
func parseADInt(value string) (int64, bool, error) {
	if value == "" {
		return 0, false, nil
	}
	parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return 0, false, errs.WrapDetail(err, ErrInvalidResponse, "invalid integer attribute | 整数属性非法")
	}
	return parsed, true, nil
}

// wrapADAttributeError adds the attribute name without exposing secret values. |
// wrapADAttributeError 附加属性名且不暴露机密值。
func wrapADAttributeError(err error, attribute string) error {
	return errs.WrapDetail(err, ErrInvalidResponse, "attribute %s | 属性 %s", attribute, attribute)
}

// adFileTime converts a Windows FILETIME to UTC. Zero, the "never" sentinel,
// pre-epoch values, and overflowing values return the zero time. | adFileTime
// 把 Windows FILETIME 转换为 UTC。零值、“永不”哨兵、纪元前值与溢出值返回零时间。
func adFileTime(value int64) time.Time {
	if value <= 0 || value == adFileTimeNever || value < adFileTimeOffset {
		return time.Time{}
	}
	delta := value - adFileTimeOffset
	if delta > math.MaxInt64/100 {
		return time.Time{}
	}
	return time.Unix(0, delta*100).UTC()
}

// parseADGeneralizedTime parses the GeneralizedTime forms emitted by AD. | parseADGeneralizedTime
// 解析 AD 输出的 GeneralizedTime 形式。
func parseADGeneralizedTime(value string) (time.Time, error) {
	layouts := []string{
		"20060102150405.9999999Z",
		"20060102150405.999999Z",
		"20060102150405.99999Z",
		"20060102150405.9999Z",
		"20060102150405.999Z",
		"20060102150405.99Z",
		"20060102150405.9Z",
		"20060102150405Z",
		time.RFC3339Nano,
		time.RFC3339,
	}
	trimmed := strings.TrimSpace(value)
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, trimmed); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, errs.Detail(ErrInvalidResponse, "invalid Active Directory time %q | Active Directory 时间 %q 非法", value, value)
}

// looksLikeDN conservatively identifies a distinguished name. | looksLikeDN
// 保守识别可分辨名称。
func looksLikeDN(value string) bool {
	return strings.Contains(value, "=") && !strings.Contains(value, "@") && !strings.Contains(value, "\\")
}

// mapADError maps LDAP result codes and bind subcodes to AD sentinels while
// preserving the typed *Error. | mapADError 把 LDAP 结果码与绑定子码映射到 AD 哨兵，
// 同时保留类型化 *Error。
func mapADError(err error) error {
	if err == nil {
		return nil
	}
	var ldapErr *Error
	if !errors.As(err, &ldapErr) {
		return err
	}
	sentinel := adResultSentinel(ldapErr.Code, ldapErr.DiagnosticMessage)
	if sentinel == nil {
		return err
	}
	return errs.WrapDetail(err, sentinel, "Active Directory operation failed | Active Directory 操作失败")
}

// adResultSentinel returns the AD-specific sentinel for a result. | adResultSentinel
// 返回结果对应的 AD 专用哨兵。
func adResultSentinel(code ResultCode, diagnostic string) error {
	if code == ResultInvalidCredentials {
		switch adSubcode(diagnostic) {
		case "525", "52e":
			return ErrInvalidCredentials
		case "530", "531", "534":
			return ErrAccountRestricted
		case "532":
			return ErrPasswordExpired
		case "533":
			return ErrAccountDisabled
		case "539", "775":
			return ErrAccountLocked
		case "701":
			return ErrAccountExpired
		case "773":
			return ErrPasswordMustChange
		default:
			return ErrInvalidCredentials
		}
	}
	switch code {
	case ResultTimeLimitExceeded:
		return ErrTimeLimitExceeded
	case ResultSizeLimitExceeded:
		return ErrSizeLimitExceeded
	case ResultReferral:
		return ErrReferral
	case ResultConstraintViolation:
		return ErrConstraintViolation
	case ResultInsufficientAccess:
		return ErrInsufficientAccess
	case ResultBusy:
		return ErrBusy
	case ResultUnavailable:
		return ErrUnavailable
	case ResultEntryAlreadyExists:
		return ErrEntryAlreadyExists
	case ResultNoSuchObject:
		return ErrNoSuchObject
	default:
		return nil
	}
}

// adSubcode extracts the Active Directory "data XXX" authentication subcode. |
// adSubcode 提取 Active Directory 的 "data XXX" 认证子码。
func adSubcode(diagnostic string) string {
	lower := strings.ToLower(diagnostic)
	index := strings.Index(lower, "data ")
	if index < 0 {
		return ""
	}
	rest := lower[index+len("data "):]
	end := len(rest)
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if c == ',' || c == ';' || c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			end = i
			break
		}
	}
	return strings.Trim(rest[:end], ".,;")
}

// minimalADUser builds the best-effort identity returned after a direct bind
// when no directory lookup succeeded. | minimalADUser 在目录查询未成功时构造直接绑定后
// 返回的尽力身份。
func minimalADUser(identity, bindName string) *ADUser {
	user := &ADUser{Authenticated: true}
	if looksLikeDN(bindName) {
		user.DN = bindName
	}
	if index := strings.IndexByte(identity, '@'); index >= 0 {
		user.UPN = identity
		user.SAMAccountName = identity[:index]
		return user
	}
	if index := strings.IndexByte(identity, '\\'); index >= 0 {
		user.SAMAccountName = identity[index+1:]
		return user
	}
	if !looksLikeDN(identity) {
		user.SAMAccountName = identity
	}
	return user
}
