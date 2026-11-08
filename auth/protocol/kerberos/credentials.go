package kerberos

import (
	"strings"

	"github.com/shibingli/ydx/errs"
)

// Credentials is a client credential backed by a password or a keytab. Exactly
// one of Password and KeyTab is used. | Credentials 是由口令或 keytab 支持的客户端
// 凭据。Password 与 KeyTab 恰好使用其中一个。
type Credentials struct {
	// Principal is the client principal. | Principal 是客户端主体。
	Principal PrincipalName
	// Realm is the client realm, possibly empty until discovery. | Realm 是客户端 realm，
	// 在发现前可能为空。
	Realm string
	// Password is the client password. It is never included in errors or logs. | Password
	// 是客户端口令，绝不写入错误或日志。
	Password string
	// KeyTab is the client keytab. | KeyTab 是客户端 keytab。
	KeyTab *KeyTab
}

// NewPasswordCredentials builds password credentials. When rawPrincipal carries no
// realm, defaultRealm supplies it. | NewPasswordCredentials 构建口令凭据。rawPrincipal
// 未携带 realm 时由 defaultRealm 提供。
func NewPasswordCredentials(rawPrincipal, defaultRealm, password string) (*Credentials, error) {
	principal, realm, err := ParsePrincipal(rawPrincipal, defaultRealm)
	if err != nil {
		return nil, err
	}
	if password == "" {
		return nil, errs.Detail(ErrCredentials, "empty password | 口令为空")
	}
	return &Credentials{Principal: principal, Realm: realm, Password: password}, nil
}

// NewKeyTabCredentials builds keytab credentials. An empty rawPrincipal selects the
// first keytab principal, and a missing realm selects that principal's realm. | NewKeyTabCredentials
// 构建 keytab 凭据。rawPrincipal 为空时选择 keytab 的第一个主体，realm 缺失时选择该
// 主体的 realm。
func NewKeyTabCredentials(rawPrincipal, defaultRealm string, tab *KeyTab) (*Credentials, error) {
	if tab == nil || len(tab.entries) == 0 {
		return nil, errs.Detail(ErrCredentials, "keytab has no entries | keytab 没有条目")
	}
	principal := tab.entries[0].Principal
	realm := defaultRealm
	if strings.TrimSpace(rawPrincipal) == "" {
		if realm == "" {
			realm = tab.entries[0].Realm
		}
	} else {
		parsed, parsedRealm, err := ParsePrincipal(rawPrincipal, defaultRealm)
		if err != nil {
			return nil, err
		}
		principal = parsed
		realm = parsedRealm
		if realm == "" {
			realm = tab.entries[0].Realm
		}
	}
	if _, err := tab.Lookup(principal, realm, 0, 0); err != nil {
		return nil, errs.WrapDetail(err, ErrCredentials, "no keytab key for principal %s | 主体 %s 没有 keytab 密钥",
			principal.String(), principal.String())
	}
	return &Credentials{Principal: principal, Realm: realm, KeyTab: tab}, nil
}

// ParsePrincipal parses a principal name with optional realm and escaping. | ParsePrincipal
// 解析带可选 realm 与转义的主体名。
func ParsePrincipal(raw, defaultRealm string) (PrincipalName, string, error) {
	return parsePrincipal(raw, defaultRealm, NameTypePrincipal)
}

// ParseServicePrincipal parses a service principal name with KRB_NT_SRV_INST. | ParseServicePrincipal
// 以 KRB_NT_SRV_INST 解析服务主体名。
func ParseServicePrincipal(raw, defaultRealm string) (PrincipalName, string, error) {
	return parsePrincipal(raw, defaultRealm, NameTypeSRVInst)
}

// parsePrincipal implements principal parsing with Kerberos backslash escapes. | parsePrincipal
// 实现带 Kerberos 反斜杠转义的主体解析。
func parsePrincipal(raw, defaultRealm string, nameType int32) (PrincipalName, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return PrincipalName{}, "", errs.Detail(ErrCredentials, "empty principal name | 主体名为空")
	}
	realm := strings.TrimSpace(defaultRealm)
	at := -1
	escaped := false
	for i := 0; i < len(raw); i++ {
		switch {
		case escaped:
			escaped = false
		case raw[i] == '\\':
			escaped = true
		case raw[i] == '@':
			at = i
			i = len(raw)
		}
	}
	namePart := raw
	if at >= 0 {
		namePart = raw[:at]
		realmPart := raw[at+1:]
		if realmPart == "" {
			return PrincipalName{}, "", errs.Detail(ErrCredentials, "principal %q has an empty realm | 主体 %q 的 realm 为空", raw, raw)
		}
		decoded, err := unescapePrincipalPart(realmPart)
		if err != nil {
			return PrincipalName{}, "", err
		}
		realm = decoded
	}
	decoded, err := splitPrincipalComponents(namePart)
	if err != nil {
		return PrincipalName{}, "", err
	}
	if len(decoded) == 0 {
		return PrincipalName{}, "", errs.Detail(ErrCredentials, "principal %q has no components | 主体 %q 没有组成部分", raw, raw)
	}
	return NewPrincipalName(nameType, decoded...), realm, nil
}

// splitPrincipalComponents splits on unescaped slashes and unescapes components. | splitPrincipalComponents
// 按未转义斜杠分割并反转义各组成部分。
func splitPrincipalComponents(name string) ([]string, error) {
	var components []string
	var current strings.Builder
	escaped := false
	flush := func() error {
		component := current.String()
		if component == "" {
			return errs.Detail(ErrCredentials, "principal has an empty component | 主体包含空组成部分")
		}
		components = append(components, component)
		current.Reset()
		return nil
	}
	for i := 0; i < len(name); i++ {
		ch := name[i]
		if escaped {
			switch ch {
			case 'n':
				current.WriteByte('\n')
			case 't':
				current.WriteByte('\t')
			case 'b':
				current.WriteByte('\b')
			case '0':
				current.WriteByte(0)
			default:
				current.WriteByte(ch)
			}
			escaped = false
			continue
		}
		switch ch {
		case '\\':
			escaped = true
		case '/':
			if err := flush(); err != nil {
				return nil, err
			}
		default:
			current.WriteByte(ch)
		}
	}
	if escaped {
		return nil, errs.Detail(ErrCredentials, "principal ends with a trailing escape | 主体以孤立转义符结尾")
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return components, nil
}

// unescapePrincipalPart removes Kerberos escapes outside component splitting. | unescapePrincipalPart
// 去除组成部分分割之外的主体转义。
func unescapePrincipalPart(value string) (string, error) {
	components, err := splitPrincipalComponents(value)
	if err != nil {
		return "", err
	}
	return strings.Join(components, "/"), nil
}

// passwordKey derives the password key for etype with the supplied salt and
// iteration count. | passwordKey 用给定盐与迭代次数为 etype 派生口令密钥。
func (c *Credentials) passwordKey(etype int32, salt string, iterations int) (EncryptionKey, error) {
	if c == nil || c.Password == "" {
		return EncryptionKey{}, errs.Detail(ErrCredentials, "password credentials are unavailable | 口令凭据不可用")
	}
	value, err := StringToKey(c.Password, salt, iterations, etype)
	if err != nil {
		return EncryptionKey{}, err
	}
	return EncryptionKey{KeyType: etype, KeyValue: value}, nil
}

// keyTabKey looks up a keytab key for the principal, etype, and optional kvno. | keyTabKey
// 为主体、加密类型与可选 kvno 查找 keytab 密钥。
func (c *Credentials) keyTabKey(etype int32, kvno int32) (EncryptionKey, error) {
	if c == nil || c.KeyTab == nil {
		return EncryptionKey{}, errs.Detail(ErrCredentials, "keytab credentials are unavailable | keytab 凭据不可用")
	}
	entry, err := c.KeyTab.Lookup(c.Principal, c.Realm, etype, kvno)
	if err != nil {
		return EncryptionKey{}, err
	}
	return entry.Key, nil
}

// defaultSalt returns the RFC 4120 default salt for the credential principal:
// the realm followed by the principal components. | defaultSalt 返回凭据主体的
// RFC 4120 默认盐：realm 后接主体各组成部分。
func (c *Credentials) defaultSalt() string {
	if c == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(c.Realm)
	for _, component := range c.Principal.NameString {
		b.WriteString(component)
	}
	return b.String()
}
