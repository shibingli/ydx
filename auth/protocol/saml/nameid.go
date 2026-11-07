package saml

import (
	"crypto/hmac"
	"crypto/sha256"
	"strings"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
)

// NewNameID returns a NameID with the given format and value. | NewNameID 返回指定格式与取值的 NameID。
func NewNameID(format, value string) *NameID {
	if format == "" {
		format = NameIDUnspecified
	}
	return &NameID{Format: format, Value: value}
}

// NameIDForPrincipal maps a principal to a NameID. | NameIDForPrincipal 把主体映射为 NameID。
func NameIDForPrincipal(principal *auth.Principal, format string) (*NameID, error) {
	if principal == nil {
		return nil, errs.Detail(ErrInvalidRequest, "principal is nil | 主体为空")
	}
	switch format {
	case "", NameIDUnspecified, NameIDPersistent:
		if principal.Subject == "" {
			return nil, errs.Detail(ErrInvalidRequest, "principal has no subject | 主体没有标识")
		}
		return NewNameID(NameIDPersistent, principal.Subject), nil
	case NameIDEmailAddress:
		if principal.Email == "" {
			return nil, errs.Detail(ErrInvalidRequest, "principal has no email | 主体没有邮箱")
		}
		return NewNameID(format, principal.Email), nil
	case NameIDTransient:
		value, err := auth.RandomToken(24)
		if err != nil {
			return nil, err
		}
		return NewNameID(format, value), nil
	case NameIDEntity:
		if principal.Issuer == "" {
			return nil, errs.Detail(ErrInvalidRequest, "principal has no issuer | 主体没有签发方")
		}
		return NewNameID(format, principal.Issuer), nil
	case NameIDKerberos, NameIDWindowsDomainQualifiedName, NameIDX509SubjectName:
		value := principal.Username
		if value == "" {
			value = principal.Subject
		}
		if value == "" {
			return nil, errs.Detail(ErrInvalidRequest, "principal has no name | 主体没有名称")
		}
		return NewNameID(format, value), nil
	default:
		return nil, errs.Detail(ErrUnsupported, "unsupported NameID format %[1]q | 不支持 NameID 格式 %[1]q", format)
	}
}

// SubjectNameID returns the NameID value of a subject. | SubjectNameID 返回主体的 NameID 取值。
func SubjectNameID(subject *Subject) string {
	if subject == nil || subject.NameID == nil {
		return ""
	}
	return subject.NameID.Value
}

// PersistentNameID derives a stable pseudonymous NameID for an SP. | PersistentNameID 为 SP 派生稳定的假名 NameID。
func PersistentNameID(local, spEntityID, salt string) string {
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte(spEntityID))
	mac.Write([]byte{0})
	mac.Write([]byte(local))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// NameIDValueMatches compares a NameID value to want, allowing the common case-insensitive email
// comparison. | NameIDValueMatches 比较 NameID 取值与 want，允许常见的邮箱大小写不敏感比较。
func NameIDValueMatches(nameID *NameID, want string) bool {
	if nameID == nil {
		return false
	}
	if nameID.Value == want {
		return true
	}
	if nameID.Format == NameIDEmailAddress {
		return strings.EqualFold(nameID.Value, want)
	}
	return false
}
