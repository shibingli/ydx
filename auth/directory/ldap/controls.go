package ldap

import (
	"github.com/shibingli/ydx/errs"
)

// Control OIDs implemented or recognized by this package. | 本包实现或识别的控件 OID。
const (
	// OIDPagedResults is the RFC 2696 simple paged results control. | OIDPagedResults 是 RFC 2696 简单分页结果控件。
	OIDPagedResults = "1.2.840.113556.1.4.319"
	// OIDSortRequest is the RFC 2891 server-side sort request control. | OIDSortRequest 是 RFC 2891 服务端排序请求控件。
	OIDSortRequest = "1.2.840.113556.1.4.473"
	// OIDSortResponse is the RFC 2891 server-side sort response control. | OIDSortResponse 是 RFC 2891 服务端排序响应控件。
	OIDSortResponse = "1.2.840.113556.1.4.474"
	// OIDManageDsaIT is the RFC 3296 ManageDsaIT control. | OIDManageDsaIT 是 RFC 3296 ManageDsaIT 控件。
	OIDManageDsaIT = "2.16.840.1.113730.3.4.2"
	// OIDProxyAuthorization is the RFC 4370 proxied authorization v2 control. | OIDProxyAuthorization 是 RFC 4370 代理授权 v2 控件。
	OIDProxyAuthorization = "2.16.840.1.113730.3.4.18"
	// OIDSubentries is the RFC 3672 subentries control. | OIDSubentries 是 RFC 3672 子条目控件。
	OIDSubentries = "1.3.6.1.4.1.4203.1.10.1"
	// OIDMatchedValues is the RFC 3876 matched values control. | OIDMatchedValues 是 RFC 3876 匹配值控件。
	OIDMatchedValues = "1.2.826.0.1.3344810.2.3"
	// OIDPermissiveModify is the RFC 4527 permissive modify control. | OIDPermissiveModify 是 RFC 4527 宽松修改控件。
	OIDPermissiveModify = "1.2.840.113556.1.4.1413"
	// OIDPreRead is the RFC 4527 pre-read request control. | OIDPreRead 是 RFC 4527 预读请求控件。
	OIDPreRead = "1.3.6.1.1.13.1"
	// OIDPostRead is the RFC 4527 post-read request control. | OIDPostRead 是 RFC 4527 后读请求控件。
	OIDPostRead = "1.3.6.1.1.13.2"
	// OIDShowDeleted is the Active Directory LDAP_SERVER_SHOW_DELETED_OID control. | OIDShowDeleted 是 Active Directory 显示已删除对象控件。
	OIDShowDeleted = "1.2.840.113556.1.4.417"
	// OIDShowRecycled is the Active Directory LDAP_SERVER_SHOW_RECYCLED_OID control. | OIDShowRecycled 是 Active Directory 显示回收站对象控件。
	OIDShowRecycled = "1.2.840.113556.1.4.2064"
	// OIDSearchOptions is the Active Directory LDAP_SERVER_SEARCH_OPTIONS_OID control. | OIDSearchOptions 是 Active Directory 搜索选项控件。
	OIDSearchOptions = "1.2.840.113556.1.4.1340"
)

// Control is one LDAP control. A nil Value omits controlValue; an empty but
// non-nil Value encodes a present zero-length value. | Control 是一个 LDAP 控件。
// Value 为 nil 时省略 controlValue；空的非 nil Value 编码为零长度值。
type Control struct {
	// Type is the control OID. | Type 是控件 OID。
	Type string
	// Criticality marks the control critical. | Criticality 标记控件为关键控件。
	Criticality bool
	// Value is the optional control value. | Value 是可选控件值。
	Value []byte
}

// encodeControls appends the [0] Controls field. | encodeControls 追加 [0]
// Controls 字段。
func encodeControls(e *berEncoder, controls []Control) {
	e.open(berClassContext, 0)
	for _, control := range controls {
		e.open(berClassUniversal, berTagSequence)
		e.text(control.Type)
		if control.Criticality {
			e.boolean(true)
		}
		if control.Value != nil {
			e.octetString(control.Value)
		}
		e.close()
	}
	e.close()
}

// decodeControls consumes an optional [0] Controls field. | decodeControls
// 消费可选的 [0] Controls 字段。
func decodeControls(r *berReader) ([]Control, error) {
	tag, err := r.peekTag()
	if err != nil {
		return nil, err
	}
	if tag.Class != berClassContext || !tag.Constructed || tag.Number != 0 {
		return nil, nil
	}
	outer, err := r.next()
	if err != nil {
		return nil, err
	}
	controlsReader, err := r.subReader(outer)
	if err != nil {
		return nil, err
	}
	var controls []Control
	for controlsReader.remaining() > 0 {
		element, err := controlsReader.expectSequence()
		if err != nil {
			return nil, err
		}
		controlReader, err := controlsReader.subReader(element)
		if err != nil {
			return nil, err
		}
		var control Control
		control.Type, err = controlReader.readString()
		if err != nil {
			return nil, err
		}
		if control.Type == "" {
			return nil, errs.Detail(ErrProtocolError, "control type is empty | 控件类型为空")
		}
		tag, err := controlReader.peekTag()
		if err != nil {
			return nil, err
		}
		if tag.Class == berClassUniversal && !tag.Constructed && tag.Number == berTagBoolean {
			control.Criticality, err = controlReader.readBoolean()
			if err != nil {
				return nil, err
			}
		}
		if controlReader.remaining() > 0 {
			tag, err = controlReader.peekTag()
			if err != nil {
				return nil, err
			}
			if tag.Class == berClassUniversal && !tag.Constructed && tag.Number == berTagOctetString {
				control.Value, err = controlReader.readOctetString()
				if err != nil {
					return nil, err
				}
			}
		}
		if err := controlReader.expectEnd(); err != nil {
			return nil, err
		}
		controls = append(controls, control)
	}
	if err := controlsReader.expectEnd(); err != nil {
		return nil, err
	}
	return controls, nil
}

// findControl returns the first control with the requested OID. | findControl
// 返回 OID 匹配的第一个控件。
func findControl(controls []Control, oid string) (Control, bool) {
	for _, control := range controls {
		if control.Type == oid {
			return control, true
		}
	}
	return Control{}, false
}

// PagedResultsControl builds the RFC 2696 request control. Cookie is an opaque
// server cursor and is normally empty on the first page. | PagedResultsControl
// 构造 RFC 2696 请求控件。Cookie 是服务端不透明游标，第一页通常为空。
func PagedResultsControl(size int, cookie []byte) Control {
	e := newBEREncoder(32)
	e.open(berClassUniversal, berTagSequence)
	e.integer(int64(size))
	e.octetString(cookie)
	e.close()
	return Control{Type: OIDPagedResults, Value: e.bytes()}
}

// ParsePagedResultsControl decodes a paged results response control. | ParsePagedResultsControl
// 解码分页结果响应控件。
func ParsePagedResultsControl(control Control) (size int, cookie []byte, err error) {
	if control.Type != OIDPagedResults {
		return 0, nil, errs.Detail(ErrInvalidResponse, "control %s is not paged results | 控件 %s 不是分页结果", control.Type, control.Type)
	}
	if control.Value == nil {
		return 0, nil, errs.Detail(ErrInvalidResponse, "paged results control has no value | 分页结果控件没有值")
	}
	r := newBERReader(control.Value)
	element, err := r.expectSequence()
	if err != nil {
		return 0, nil, err
	}
	inner, err := r.subReader(element)
	if err != nil {
		return 0, nil, err
	}
	value, err := inner.readInt(false)
	if err != nil {
		return 0, nil, err
	}
	if value < 0 || value > 2147483647 {
		return 0, nil, errs.Detail(ErrInvalidResponse, "paged size %d is out of range | 分页大小 %d 超出范围", value, value)
	}
	rawCookie, err := inner.readOctetString()
	if err != nil {
		return 0, nil, err
	}
	if err := inner.expectEnd(); err != nil {
		return 0, nil, err
	}
	if err := r.expectEnd(); err != nil {
		return 0, nil, err
	}
	return int(value), append([]byte(nil), rawCookie...), nil
}

// SortKey is one server-side sort key. | SortKey 是一个服务端排序键。
type SortKey struct {
	// Attribute is the attribute description. | Attribute 是属性描述。
	Attribute string
	// OrderingRule optionally names a matching rule OID. | OrderingRule 可选地指定匹配规则 OID。
	OrderingRule string
	// Reverse requests descending order. | Reverse 请求降序。
	Reverse bool
}

// SortControl builds the RFC 2891 server-side sort request control. | SortControl
// 构造 RFC 2891 服务端排序请求控件。
func SortControl(keys ...SortKey) Control {
	e := newBEREncoder(64)
	e.open(berClassUniversal, berTagSequence)
	for _, key := range keys {
		e.open(berClassUniversal, berTagSequence)
		e.text(key.Attribute)
		if key.OrderingRule != "" {
			e.primitive(berClassContext, 0, []byte(key.OrderingRule))
		}
		if key.Reverse {
			// RFC 2891 reverseOrder is an implicit primitive BOOLEAN. | RFC 2891
			// reverseOrder 是隐式原始 BOOLEAN。
			e.primitive(berClassContext, 1, []byte{0xff})
		}
		e.close()
	}
	e.close()
	return Control{Type: OIDSortRequest, Value: e.bytes()}
}

// SortResult reports the server-side sort outcome. | SortResult 报告服务端排序结果。
type SortResult struct {
	// Code is the sort result code; zero means success and three means the
	// server did not support the requested ordering rule. | Code 是排序结果码；零表示成功，三表示服务端不支持请求的排序规则。
	Code ResultCode
	// Attribute is the attribute associated with a failure. | Attribute 是失败关联的属性。
	Attribute string
}

// ParseSortResponseControl decodes the RFC 2891 response control. | ParseSortResponseControl
// 解码 RFC 2891 响应控件。
func ParseSortResponseControl(control Control) (SortResult, error) {
	if control.Type != OIDSortResponse {
		return SortResult{}, errs.Detail(ErrInvalidResponse, "control %s is not sort response | 控件 %s 不是排序响应", control.Type, control.Type)
	}
	if control.Value == nil {
		return SortResult{}, errs.Detail(ErrInvalidResponse, "sort response control has no value | 排序响应控件没有值")
	}
	r := newBERReader(control.Value)
	element, err := r.expectSequence()
	if err != nil {
		return SortResult{}, err
	}
	inner, err := r.subReader(element)
	if err != nil {
		return SortResult{}, err
	}
	code, err := inner.readInt(true)
	if err != nil {
		return SortResult{}, err
	}
	result := SortResult{Code: ResultCode(code)}
	if inner.remaining() > 0 {
		element, err := inner.expect(berClassContext, false, 0)
		if err != nil {
			return SortResult{}, err
		}
		result.Attribute = string(element.Value)
	}
	if err := inner.expectEnd(); err != nil {
		return SortResult{}, err
	}
	if err := r.expectEnd(); err != nil {
		return SortResult{}, err
	}
	return result, nil
}

// ManageDsaITControl returns the RFC 3296 ManageDsaIT control. | ManageDsaITControl
// 返回 RFC 3296 ManageDsaIT 控件。
func ManageDsaITControl() Control { return Control{Type: OIDManageDsaIT} }

// ProxyAuthorizationControl returns the RFC 4370 control for an authorization
// identity in "dn:<DN>" or "u:<user>" form. | ProxyAuthorizationControl 返回
// RFC 4370 控件，授权身份采用 "dn:<DN>" 或 "u:<user>" 形式。
func ProxyAuthorizationControl(authzID string) Control {
	return Control{Type: OIDProxyAuthorization, Criticality: true, Value: []byte(authzID)}
}

// ProxyAuthorizationDNControl is ProxyAuthorizationControl with a "dn:" prefix
// added when the caller supplied a bare DN. | ProxyAuthorizationDNControl 是
// ProxyAuthorizationControl，在调用方传入裸 DN 时补上 "dn:" 前缀。
func ProxyAuthorizationDNControl(dn string) Control {
	if len(dn) >= 3 && (dn[:3] == "dn:" || dn[:2] == "u:") {
		return ProxyAuthorizationControl(dn)
	}
	return ProxyAuthorizationControl("dn:" + dn)
}

// SubentriesControl returns the RFC 3672 subentries visibility control. | SubentriesControl
// 返回 RFC 3672 子条目可见性控件。
func SubentriesControl(visible bool) Control {
	e := newBEREncoder(8)
	e.boolean(visible)
	return Control{Type: OIDSubentries, Criticality: true, Value: e.bytes()}
}

// MatchedValuesControl returns the RFC 3876 control selecting simple filters.
// Composite and/or/not filters are rejected because the control grammar only
// permits simple filter items. | MatchedValuesControl 返回 RFC 3876 控件以选择简单
// 过滤器。由于控件语法只允许简单过滤项，复合 and/or/not 过滤器会被拒绝。
func MatchedValuesControl(filters ...Filter) (Control, error) {
	e := newBEREncoder(64)
	e.open(berClassUniversal, berTagSequence)
	for _, filter := range filters {
		if filter == nil {
			return Control{}, errs.Detail(ErrInvalidMessage, "matched values filter is nil | 匹配值过滤器为空")
		}
		switch filter.(type) {
		case *AndFilter, *OrFilter, *NotFilter:
			return Control{}, errs.Detail(ErrInvalidMessage, "matched values control requires simple filters | 匹配值控件要求简单过滤器")
		}
		encodeFilter(e, filter)
	}
	e.close()
	return Control{Type: OIDMatchedValues, Criticality: true, Value: e.bytes()}, nil
}

// PermissiveModifyControl returns the Active Directory/RFC 4527 permissive
// modify control. | PermissiveModifyControl 返回 Active Directory/RFC 4527 宽松修改控件。
func PermissiveModifyControl() Control { return Control{Type: OIDPermissiveModify} }

// PreReadControl requests the entry before a modify in the response controls. | PreReadControl
// 请求在修改前的条目随响应控件返回。
func PreReadControl(attributes ...string) Control {
	return readControl(OIDPreRead, attributes)
}

// PostReadControl requests the entry after a modify in the response controls. | PostReadControl
// 请求在修改后的条目随响应控件返回。
func PostReadControl(attributes ...string) Control {
	return readControl(OIDPostRead, attributes)
}

// readControl builds an RFC 4527 read-entry request control. | readControl 构造
// RFC 4527 读取条目请求控件。
func readControl(oid string, attributes []string) Control {
	e := newBEREncoder(32)
	e.open(berClassUniversal, berTagSequence)
	for _, attribute := range attributes {
		e.text(attribute)
	}
	e.close()
	return Control{Type: oid, Criticality: true, Value: e.bytes()}
}

// ParseReadEntryControl decodes a pre-read or post-read response control. | ParseReadEntryControl
// 解码预读或后读响应控件。
func ParseReadEntryControl(control Control) (*Entry, error) {
	if control.Type != OIDPreRead && control.Type != OIDPostRead {
		return nil, errs.Detail(ErrInvalidResponse, "control %s is not a read-entry control | 控件 %s 不是读取条目控件", control.Type, control.Type)
	}
	if control.Value == nil {
		return nil, errs.Detail(ErrInvalidResponse, "read-entry control has no value | 读取条目控件没有值")
	}
	r := newBERReader(control.Value)
	element, err := r.expectSequence()
	if err != nil {
		return nil, err
	}
	inner, err := r.subReader(element)
	if err != nil {
		return nil, err
	}
	entry, err := decodeSearchEntryBody(inner)
	if err != nil {
		return nil, err
	}
	if err := r.expectEnd(); err != nil {
		return nil, err
	}
	return entry, nil
}

// ShowDeletedControl requests deleted Active Directory objects. | ShowDeletedControl
// 请求显示 Active Directory 已删除对象。
func ShowDeletedControl() Control { return Control{Type: OIDShowDeleted, Criticality: true} }

// ShowRecycledControl requests recycled Active Directory objects. | ShowRecycledControl
// 请求显示 Active Directory 回收站对象。
func ShowRecycledControl() Control { return Control{Type: OIDShowRecycled, Criticality: true} }
