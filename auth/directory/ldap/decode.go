package ldap

import (
	"github.com/shibingli/ydx/errs"
)

// decodeLDAPMessage parses one complete LDAPMessage. | decodeLDAPMessage 解析
// 一条完整 LDAPMessage。
func decodeLDAPMessage(data []byte) (*LDAPMessage, error) {
	outer := newBERReader(data)
	element, err := outer.expectSequence()
	if err != nil {
		return nil, err
	}
	if err := outer.expectEnd(); err != nil {
		return nil, err
	}
	r, err := outer.subReader(element)
	if err != nil {
		return nil, err
	}
	rawID, err := r.readInt(false)
	if err != nil {
		return nil, err
	}
	if rawID < 0 || rawID > 2147483647 {
		return nil, errs.Detail(ErrProtocolError, "message ID %d is out of range | 消息 ID %d 超出范围", rawID, rawID)
	}
	message := &LDAPMessage{MessageID: int(rawID)}
	message.Op, err = decodeProtocolOp(r)
	if err != nil {
		return nil, err
	}
	if r.remaining() > 0 {
		message.Controls, err = decodeControls(r)
		if err != nil {
			return nil, err
		}
	}
	if err := r.expectEnd(); err != nil {
		return nil, err
	}
	return message, nil
}

// decodeProtocolOp parses one application-tagged operation. | decodeProtocolOp
// 解析一个应用标签操作。
func decodeProtocolOp(r *berReader) (ProtocolOp, error) {
	tag, err := r.peekTag()
	if err != nil {
		return nil, err
	}
	if tag.Class != berClassApplication {
		return nil, errs.Detail(ErrProtocolError, "protocol op class %d is not application | 协议操作类别 %d 不是 application", tag.Class, tag.Class)
	}
	switch tag.Number {
	case appBindRequest:
		return decodeBindRequest(r)
	case appBindResponse:
		return decodeBindResponse(r)
	case appUnbindRequest:
		element, err := r.expect(berClassApplication, false, appUnbindRequest)
		if err != nil {
			return nil, err
		}
		if len(element.Value) != 0 {
			return nil, errs.Detail(ErrProtocolError, "unbind request carries a value | 解绑请求携带值")
		}
		return &UnbindRequest{}, nil
	case appSearchRequest:
		return decodeSearchRequest(r)
	case appSearchResultEntry:
		return decodeSearchEntry(r)
	case appSearchResultDone:
		return decodeSearchDone(r)
	case appSearchResultReference:
		return decodeSearchReference(r)
	case appModifyRequest:
		return decodeModifyRequest(r)
	case appModifyResponse:
		return decodeResultResponse(r, appModifyResponse, "modify response")
	case appAddRequest:
		return decodeAddRequest(r)
	case appAddResponse:
		return decodeResultResponse(r, appAddResponse, "add response")
	case appDeleteRequest:
		element, err := r.expect(berClassApplication, false, appDeleteRequest)
		if err != nil {
			return nil, err
		}
		return &DeleteRequest{DN: string(element.Value)}, nil
	case appDeleteResponse:
		return decodeResultResponse(r, appDeleteResponse, "delete response")
	case appModifyDNRequest:
		return decodeModifyDNRequest(r)
	case appModifyDNResponse:
		return decodeResultResponse(r, appModifyDNResponse, "modify DN response")
	case appCompareRequest:
		return decodeCompareRequest(r)
	case appCompareResponse:
		return decodeResultResponse(r, appCompareResponse, "compare response")
	case appAbandonRequest:
		element, err := r.expect(berClassApplication, false, appAbandonRequest)
		if err != nil {
			return nil, err
		}
		id, err := decodeBERInt(element.Value)
		if err != nil {
			return nil, err
		}
		if id <= 0 || id > 2147483647 {
			return nil, errs.Detail(ErrProtocolError, "abandon message ID %d is invalid | 放弃消息 ID %d 非法", id, id)
		}
		return &AbandonRequest{MessageID: int(id)}, nil
	case appExtendedRequest:
		return decodeExtendedRequest(r)
	case appExtendedResponse:
		return decodeExtendedResponse(r)
	case appIntermediateResponse:
		return decodeIntermediateResponse(r)
	default:
		return nil, errs.Detail(ErrProtocolError, "unsupported application tag %d | 不支持的应用标签 %d", tag.Number, tag.Number)
	}
}

// protocolBody consumes and opens a constructed application operation. | protocolBody
// 消费并打开一个构造应用操作。
func protocolBody(r *berReader, tag uint32) (*berReader, error) {
	element, err := r.expect(berClassApplication, true, tag)
	if err != nil {
		return nil, err
	}
	return r.subReader(element)
}

// decodeResultResponse decodes a response that only carries LDAPResult. | decodeResultResponse
// 解码只携带 LDAPResult 的响应。
func decodeResultResponse(r *berReader, tag uint32, name string) (ProtocolOp, error) {
	inner, err := protocolBody(r, tag)
	if err != nil {
		return nil, err
	}
	result, err := decodeResult(inner)
	if err != nil {
		return nil, err
	}
	if err := inner.expectEnd(); err != nil {
		return nil, err
	}
	switch tag {
	case appModifyResponse:
		return &ModifyResponse{Result: result}, nil
	case appAddResponse:
		return &AddResponse{Result: result}, nil
	case appDeleteResponse:
		return &DeleteResponse{Result: result}, nil
	case appModifyDNResponse:
		return &ModifyDNResponse{Result: result}, nil
	case appCompareResponse:
		return &CompareResponse{Result: result}, nil
	default:
		return nil, errs.Detail(ErrProtocolError, "unknown result response %s | 未知结果响应 %s", name, name)
	}
}

// decodeResult parses the common LDAPResult fields. | decodeResult 解析公共
// LDAPResult 字段。
func decodeResult(r *berReader) (LDAPResult, error) {
	rawCode, err := r.readInt(true)
	if err != nil {
		return LDAPResult{}, err
	}
	if rawCode < 0 || rawCode > 255 {
		return LDAPResult{}, errs.Detail(ErrProtocolError, "result code %d is out of range | 结果码 %d 超出范围", rawCode, rawCode)
	}
	result := LDAPResult{Code: ResultCode(rawCode)}
	result.MatchedDN, err = r.readString()
	if err != nil {
		return LDAPResult{}, err
	}
	result.DiagnosticMessage, err = r.readString()
	if err != nil {
		return LDAPResult{}, err
	}
	if r.remaining() > 0 {
		tag, err := r.peekTag()
		if err != nil {
			return LDAPResult{}, err
		}
		if tag.Class == berClassContext && tag.Constructed && tag.Number == 3 {
			element, err := r.next()
			if err != nil {
				return LDAPResult{}, err
			}
			referrals, err := r.subReader(element)
			if err != nil {
				return LDAPResult{}, err
			}
			for referrals.remaining() > 0 {
				uri, err := referrals.readString()
				if err != nil {
					return LDAPResult{}, err
				}
				result.Referrals = append(result.Referrals, uri)
			}
		}
	}
	return result, nil
}

// decodeBindRequest parses a BindRequest. | decodeBindRequest 解析 BindRequest。
func decodeBindRequest(r *berReader) (ProtocolOp, error) {
	inner, err := protocolBody(r, appBindRequest)
	if err != nil {
		return nil, err
	}
	version, err := inner.readInt(false)
	if err != nil {
		return nil, err
	}
	if version < 0 || version > 255 {
		return nil, errs.Detail(ErrProtocolError, "bind version %d is invalid | 绑定版本 %d 非法", version, version)
	}
	request := &BindRequest{Version: int(version)}
	request.DN, err = inner.readString()
	if err != nil {
		return nil, err
	}
	tag, err := inner.peekTag()
	if err != nil {
		return nil, err
	}
	if tag.Class != berClassContext {
		return nil, errs.Detail(ErrProtocolError, "bind authentication tag is not context-specific | 绑定认证标签不是上下文相关")
	}
	element, err := inner.next()
	if err != nil {
		return nil, err
	}
	switch tag.Number {
	case 0:
		if tag.Constructed {
			return nil, errs.Detail(ErrProtocolError, "simple authentication is constructed | 简单认证为构造类型")
		}
		request.Authentication = SimpleAuthentication{Password: string(element.Value)}
	case 3:
		if !tag.Constructed {
			return nil, errs.Detail(ErrProtocolError, "SASL authentication is primitive | SASL 认证为原始类型")
		}
		saslReader, err := inner.subReader(element)
		if err != nil {
			return nil, err
		}
		mechanism, err := saslReader.readString()
		if err != nil {
			return nil, err
		}
		credentials, err := saslReader.readOctetString()
		if err != nil {
			return nil, err
		}
		if err := saslReader.expectEnd(); err != nil {
			return nil, err
		}
		request.Authentication = SASLAuthentication{
			Mechanism:   mechanism,
			Credentials: append([]byte(nil), credentials...),
		}
	default:
		return nil, errs.Detail(ErrProtocolError, "unsupported bind authentication tag %d | 不支持的绑定认证标签 %d", tag.Number, tag.Number)
	}
	if err := inner.expectEnd(); err != nil {
		return nil, err
	}
	return request, nil
}

// decodeBindResponse parses a BindResponse. | decodeBindResponse 解析 BindResponse。
func decodeBindResponse(r *berReader) (ProtocolOp, error) {
	inner, err := protocolBody(r, appBindResponse)
	if err != nil {
		return nil, err
	}
	result, err := decodeResult(inner)
	if err != nil {
		return nil, err
	}
	response := &BindResponse{Result: result}
	if inner.remaining() > 0 {
		element, err := inner.expect(berClassContext, false, 7)
		if err != nil {
			return nil, err
		}
		response.ServerSASLCredentials = append([]byte(nil), element.Value...)
	}
	if err := inner.expectEnd(); err != nil {
		return nil, err
	}
	return response, nil
}

// decodeSearchRequest parses a SearchRequest. | decodeSearchRequest 解析 SearchRequest。
func decodeSearchRequest(r *berReader) (ProtocolOp, error) {
	inner, err := protocolBody(r, appSearchRequest)
	if err != nil {
		return nil, err
	}
	request := &SearchRequest{}
	request.BaseDN, err = inner.readString()
	if err != nil {
		return nil, err
	}
	scope, err := inner.readInt(true)
	if err != nil {
		return nil, err
	}
	if scope < 0 || scope > 2 {
		return nil, errs.Detail(ErrProtocolError, "search scope %d is invalid | 搜索范围 %d 非法", scope, scope)
	}
	request.Scope = Scope(scope)
	deref, err := inner.readInt(true)
	if err != nil {
		return nil, err
	}
	if deref < 0 || deref > 3 {
		return nil, errs.Detail(ErrProtocolError, "deref aliases %d is invalid | 别名解引用 %d 非法", deref, deref)
	}
	request.DerefAliases = DerefAliases(deref)
	sizeLimit, err := inner.readInt(false)
	if err != nil {
		return nil, err
	}
	timeLimit, err := inner.readInt(false)
	if err != nil {
		return nil, err
	}
	if sizeLimit < 0 || sizeLimit > 2147483647 || timeLimit < 0 || timeLimit > 2147483647 {
		return nil, errs.Detail(ErrProtocolError, "search limit is out of range | 搜索限制超出范围")
	}
	request.SizeLimit = int(sizeLimit)
	request.TimeLimit = int(timeLimit)
	request.TypesOnly, err = inner.readBoolean()
	if err != nil {
		return nil, err
	}
	request.Filter, err = decodeFilter(inner)
	if err != nil {
		return nil, err
	}
	attributes, err := inner.expectSequence()
	if err != nil {
		return nil, err
	}
	attrReader, err := inner.subReader(attributes)
	if err != nil {
		return nil, err
	}
	for attrReader.remaining() > 0 {
		attribute, err := attrReader.readString()
		if err != nil {
			return nil, err
		}
		request.Attributes = append(request.Attributes, attribute)
	}
	if err := inner.expectEnd(); err != nil {
		return nil, err
	}
	return request, nil
}

// decodeFilter parses a BER-encoded Filter. | decodeFilter 解析 BER 编码的 Filter。
func decodeFilter(r *berReader) (Filter, error) {
	tag, err := r.peekTag()
	if err != nil {
		return nil, err
	}
	if tag.Class != berClassContext {
		return nil, errs.Detail(ErrProtocolError, "filter tag class %d is not context-specific | 过滤器标签类别 %d 不是上下文相关", tag.Class, tag.Class)
	}
	switch tag.Number {
	case 0, 1:
		element, err := r.expect(berClassContext, true, tag.Number)
		if err != nil {
			return nil, err
		}
		childrenReader, err := r.subReader(element)
		if err != nil {
			return nil, err
		}
		var children []Filter
		for childrenReader.remaining() > 0 {
			child, err := decodeFilter(childrenReader)
			if err != nil {
				return nil, err
			}
			children = append(children, child)
		}
		if len(children) == 0 {
			return nil, errs.Detail(ErrProtocolError, "empty and/or filter | 空的 and/or 过滤器")
		}
		if tag.Number == 0 {
			return &AndFilter{Filters: children}, nil
		}
		return &OrFilter{Filters: children}, nil
	case 2:
		element, err := r.expect(berClassContext, true, 2)
		if err != nil {
			return nil, err
		}
		childReader, err := r.subReader(element)
		if err != nil {
			return nil, err
		}
		child, err := decodeFilter(childReader)
		if err != nil {
			return nil, err
		}
		if err := childReader.expectEnd(); err != nil {
			return nil, err
		}
		return &NotFilter{Filter: child}, nil
	case 3, 5, 6, 8:
		element, err := r.expect(berClassContext, true, tag.Number)
		if err != nil {
			return nil, err
		}
		assertion, err := r.subReader(element)
		if err != nil {
			return nil, err
		}
		attribute, err := assertion.readString()
		if err != nil {
			return nil, err
		}
		value, err := assertion.readString()
		if err != nil {
			return nil, err
		}
		if err := assertion.expectEnd(); err != nil {
			return nil, err
		}
		switch tag.Number {
		case 3:
			return &EqualityFilter{Attribute: attribute, Value: value}, nil
		case 5:
			return &GreaterOrEqualFilter{Attribute: attribute, Value: value}, nil
		case 6:
			return &LessOrEqualFilter{Attribute: attribute, Value: value}, nil
		default:
			return &ApproxFilter{Attribute: attribute, Value: value}, nil
		}
	case 4:
		return decodeSubstringFilter(r)
	case 7:
		element, err := r.expect(berClassContext, false, 7)
		if err != nil {
			return nil, err
		}
		return &PresentFilter{Attribute: string(element.Value)}, nil
	case 9:
		return decodeExtensibleFilter(r)
	default:
		return nil, errs.Detail(ErrProtocolError, "unsupported filter tag %d | 不支持的过滤器标签 %d", tag.Number, tag.Number)
	}
}

// decodeSubstringFilter parses an implicit [4] SubstringFilter. | decodeSubstringFilter
// 解析隐式 [4] SubstringFilter。
func decodeSubstringFilter(r *berReader) (Filter, error) {
	element, err := r.expect(berClassContext, true, 4)
	if err != nil {
		return nil, err
	}
	inner, err := r.subReader(element)
	if err != nil {
		return nil, err
	}
	attribute, err := inner.readString()
	if err != nil {
		return nil, err
	}
	components, err := inner.expectSequence()
	if err != nil {
		return nil, err
	}
	componentsReader, err := inner.subReader(components)
	if err != nil {
		return nil, err
	}
	filter := &SubstringFilter{Attribute: attribute}
	seenInitial, seenFinal := false, false
	for componentsReader.remaining() > 0 {
		tag, err := componentsReader.peekTag()
		if err != nil {
			return nil, err
		}
		if tag.Class != berClassContext || tag.Constructed {
			return nil, errs.Detail(ErrProtocolError, "invalid substring component tag | 非法子串组件标签")
		}
		part, err := componentsReader.next()
		if err != nil {
			return nil, err
		}
		switch tag.Number {
		case 0:
			if seenInitial {
				return nil, errs.Detail(ErrProtocolError, "duplicate initial substring | 重复的初始子串")
			}
			seenInitial = true
			filter.Initial = string(part.Value)
		case 1:
			filter.Any = append(filter.Any, string(part.Value))
		case 2:
			if seenFinal {
				return nil, errs.Detail(ErrProtocolError, "duplicate final substring | 重复的最终子串")
			}
			seenFinal = true
			filter.Final = string(part.Value)
		default:
			return nil, errs.Detail(ErrProtocolError, "unknown substring component %d | 未知子串组件 %d", tag.Number, tag.Number)
		}
	}
	if err := inner.expectEnd(); err != nil {
		return nil, err
	}
	if filter.Initial == "" && filter.Final == "" && len(filter.Any) == 0 {
		return nil, errs.Detail(ErrProtocolError, "empty substring filter | 空子串过滤器")
	}
	return filter, nil
}

// decodeExtensibleFilter parses an implicit [9] MatchingRuleAssertion. | decodeExtensibleFilter
// 解析隐式 [9] MatchingRuleAssertion。
func decodeExtensibleFilter(r *berReader) (Filter, error) {
	element, err := r.expect(berClassContext, true, 9)
	if err != nil {
		return nil, err
	}
	inner, err := r.subReader(element)
	if err != nil {
		return nil, err
	}
	filter := &ExtensibleMatchFilter{}
	seenRule, seenAttribute, seenValue, seenDN := false, false, false, false
	for inner.remaining() > 0 {
		tag, err := inner.peekTag()
		if err != nil {
			return nil, err
		}
		if tag.Class != berClassContext {
			return nil, errs.Detail(ErrProtocolError, "invalid extensible component tag | 非法扩展匹配组件标签")
		}
		component, err := inner.next()
		if err != nil {
			return nil, err
		}
		switch tag.Number {
		case 1:
			if tag.Constructed || seenRule {
				return nil, errs.Detail(ErrProtocolError, "invalid matching rule component | 非法匹配规则组件")
			}
			seenRule = true
			filter.MatchingRule = string(component.Value)
		case 2:
			if tag.Constructed || seenAttribute {
				return nil, errs.Detail(ErrProtocolError, "invalid attribute component | 非法属性组件")
			}
			seenAttribute = true
			filter.Attribute = string(component.Value)
		case 3:
			if tag.Constructed || seenValue {
				return nil, errs.Detail(ErrProtocolError, "invalid match value component | 非法匹配值组件")
			}
			seenValue = true
			filter.Value = string(component.Value)
		case 4:
			if !tag.Constructed || seenDN {
				return nil, errs.Detail(ErrProtocolError, "invalid dnAttributes component | 非法 dnAttributes 组件")
			}
			seenDN = true
			dnReader, err := inner.subReader(component)
			if err != nil {
				return nil, err
			}
			filter.DNAttributes, err = dnReader.readBoolean()
			if err != nil {
				return nil, err
			}
			if err := dnReader.expectEnd(); err != nil {
				return nil, err
			}
		default:
			return nil, errs.Detail(ErrProtocolError, "unknown extensible component %d | 未知扩展匹配组件 %d", tag.Number, tag.Number)
		}
	}
	if !seenValue {
		return nil, errs.Detail(ErrProtocolError, "extensible match has no value | 扩展匹配没有值")
	}
	if err := ValidateFilter(filter); err != nil {
		return nil, err
	}
	return filter, nil
}

// decodeSearchEntry parses a SearchResultEntry. | decodeSearchEntry 解析
// SearchResultEntry。
func decodeSearchEntry(r *berReader) (ProtocolOp, error) {
	inner, err := protocolBody(r, appSearchResultEntry)
	if err != nil {
		return nil, err
	}
	entry, err := decodeSearchEntryBody(inner)
	if err != nil {
		return nil, err
	}
	return entry, nil
}

// decodeSearchEntryBody parses the objectName and attributes of an entry. | decodeSearchEntryBody
// 解析条目的 objectName 与属性。
func decodeSearchEntryBody(r *berReader) (*Entry, error) {
	dn, err := r.readString()
	if err != nil {
		return nil, err
	}
	attributes, err := r.expectSequence()
	if err != nil {
		return nil, err
	}
	attributesReader, err := r.subReader(attributes)
	if err != nil {
		return nil, err
	}
	entry := &Entry{DN: dn}
	for attributesReader.remaining() > 0 {
		attribute, err := decodePartialAttribute(attributesReader)
		if err != nil {
			return nil, err
		}
		entry.Attributes = append(entry.Attributes, attribute)
	}
	if err := r.expectEnd(); err != nil {
		return nil, err
	}
	return entry, nil
}

// decodePartialAttribute parses a PartialAttribute. | decodePartialAttribute
// 解析 PartialAttribute。
func decodePartialAttribute(r *berReader) (Attribute, error) {
	element, err := r.expectSequence()
	if err != nil {
		return Attribute{}, err
	}
	inner, err := r.subReader(element)
	if err != nil {
		return Attribute{}, err
	}
	attribute := Attribute{}
	attribute.Type, err = inner.readString()
	if err != nil {
		return Attribute{}, err
	}
	if attribute.Type == "" {
		return Attribute{}, errs.Detail(ErrProtocolError, "attribute type is empty | 属性类型为空")
	}
	values, err := inner.expectSet()
	if err != nil {
		return Attribute{}, err
	}
	valuesReader, err := inner.subReader(values)
	if err != nil {
		return Attribute{}, err
	}
	for valuesReader.remaining() > 0 {
		value, err := valuesReader.readString()
		if err != nil {
			return Attribute{}, err
		}
		attribute.Values = append(attribute.Values, value)
	}
	if err := inner.expectEnd(); err != nil {
		return Attribute{}, err
	}
	return attribute, nil
}

// decodeSearchDone parses a SearchResultDone. | decodeSearchDone 解析
// SearchResultDone。
func decodeSearchDone(r *berReader) (ProtocolOp, error) {
	inner, err := protocolBody(r, appSearchResultDone)
	if err != nil {
		return nil, err
	}
	result, err := decodeResult(inner)
	if err != nil {
		return nil, err
	}
	if err := inner.expectEnd(); err != nil {
		return nil, err
	}
	return &SearchResultDone{Result: result}, nil
}

// decodeSearchReference parses a SearchResultReference. | decodeSearchReference
// 解析 SearchResultReference。
func decodeSearchReference(r *berReader) (ProtocolOp, error) {
	inner, err := protocolBody(r, appSearchResultReference)
	if err != nil {
		return nil, err
	}
	reference := &SearchResultReference{}
	for inner.remaining() > 0 {
		uri, err := inner.readString()
		if err != nil {
			return nil, err
		}
		reference.URIs = append(reference.URIs, uri)
	}
	return reference, nil
}

// decodeModifyRequest parses a ModifyRequest. | decodeModifyRequest 解析
// ModifyRequest。
func decodeModifyRequest(r *berReader) (ProtocolOp, error) {
	inner, err := protocolBody(r, appModifyRequest)
	if err != nil {
		return nil, err
	}
	request := &ModifyRequest{}
	request.DN, err = inner.readString()
	if err != nil {
		return nil, err
	}
	changes, err := inner.expectSequence()
	if err != nil {
		return nil, err
	}
	changesReader, err := inner.subReader(changes)
	if err != nil {
		return nil, err
	}
	for changesReader.remaining() > 0 {
		changeElement, err := changesReader.expectSequence()
		if err != nil {
			return nil, err
		}
		changeReader, err := changesReader.subReader(changeElement)
		if err != nil {
			return nil, err
		}
		operation, err := changeReader.readInt(true)
		if err != nil {
			return nil, err
		}
		if operation < 0 || operation > 3 {
			return nil, errs.Detail(ErrProtocolError, "modify operation %d is invalid | 修改操作 %d 非法", operation, operation)
		}
		attribute, err := decodePartialAttribute(changeReader)
		if err != nil {
			return nil, err
		}
		if err := changeReader.expectEnd(); err != nil {
			return nil, err
		}
		request.Changes = append(request.Changes, ModifyChange{
			Operation: ModifyOperation(operation),
			Attribute: attribute,
		})
	}
	if err := inner.expectEnd(); err != nil {
		return nil, err
	}
	return request, nil
}

// decodeAddRequest parses an AddRequest. | decodeAddRequest 解析 AddRequest。
func decodeAddRequest(r *berReader) (ProtocolOp, error) {
	inner, err := protocolBody(r, appAddRequest)
	if err != nil {
		return nil, err
	}
	request := &AddRequest{}
	request.DN, err = inner.readString()
	if err != nil {
		return nil, err
	}
	attributes, err := inner.expectSequence()
	if err != nil {
		return nil, err
	}
	attributesReader, err := inner.subReader(attributes)
	if err != nil {
		return nil, err
	}
	for attributesReader.remaining() > 0 {
		attribute, err := decodePartialAttribute(attributesReader)
		if err != nil {
			return nil, err
		}
		request.Attributes = append(request.Attributes, attribute)
	}
	if err := inner.expectEnd(); err != nil {
		return nil, err
	}
	return request, nil
}

// decodeModifyDNRequest parses a ModifyDNRequest. | decodeModifyDNRequest 解析
// ModifyDNRequest。
func decodeModifyDNRequest(r *berReader) (ProtocolOp, error) {
	inner, err := protocolBody(r, appModifyDNRequest)
	if err != nil {
		return nil, err
	}
	request := &ModifyDNRequest{}
	request.DN, err = inner.readString()
	if err != nil {
		return nil, err
	}
	request.NewRDN, err = inner.readString()
	if err != nil {
		return nil, err
	}
	request.DeleteOldRDN, err = inner.readBoolean()
	if err != nil {
		return nil, err
	}
	if inner.remaining() > 0 {
		element, err := inner.expect(berClassContext, false, 0)
		if err != nil {
			return nil, err
		}
		request.NewSuperior = string(element.Value)
	}
	if err := inner.expectEnd(); err != nil {
		return nil, err
	}
	return request, nil
}

// decodeCompareRequest parses a CompareRequest. | decodeCompareRequest 解析
// CompareRequest。
func decodeCompareRequest(r *berReader) (ProtocolOp, error) {
	inner, err := protocolBody(r, appCompareRequest)
	if err != nil {
		return nil, err
	}
	request := &CompareRequest{}
	request.DN, err = inner.readString()
	if err != nil {
		return nil, err
	}
	avaElement, err := inner.expectSequence()
	if err != nil {
		return nil, err
	}
	ava, err := inner.subReader(avaElement)
	if err != nil {
		return nil, err
	}
	request.Attribute, err = ava.readString()
	if err != nil {
		return nil, err
	}
	request.Value, err = ava.readString()
	if err != nil {
		return nil, err
	}
	if err := ava.expectEnd(); err != nil {
		return nil, err
	}
	if err := inner.expectEnd(); err != nil {
		return nil, err
	}
	return request, nil
}

// decodeExtendedRequest parses an ExtendedRequest. | decodeExtendedRequest 解析
// ExtendedRequest。
func decodeExtendedRequest(r *berReader) (ProtocolOp, error) {
	inner, err := protocolBody(r, appExtendedRequest)
	if err != nil {
		return nil, err
	}
	request := &ExtendedRequest{}
	element, err := inner.expect(berClassContext, false, 0)
	if err != nil {
		return nil, err
	}
	request.Name = string(element.Value)
	if inner.remaining() > 0 {
		value, err := inner.expect(berClassContext, false, 1)
		if err != nil {
			return nil, err
		}
		request.Value = append([]byte(nil), value.Value...)
	}
	if err := inner.expectEnd(); err != nil {
		return nil, err
	}
	return request, nil
}

// decodeExtendedResponse parses an ExtendedResponse. | decodeExtendedResponse
// 解析 ExtendedResponse。
func decodeExtendedResponse(r *berReader) (ProtocolOp, error) {
	inner, err := protocolBody(r, appExtendedResponse)
	if err != nil {
		return nil, err
	}
	result, err := decodeResult(inner)
	if err != nil {
		return nil, err
	}
	response := &ExtendedResponse{Result: result}
	for inner.remaining() > 0 {
		tag, err := inner.peekTag()
		if err != nil {
			return nil, err
		}
		if tag.Class != berClassContext || tag.Constructed {
			return nil, errs.Detail(ErrProtocolError, "invalid extended response field | 非法扩展响应字段")
		}
		element, err := inner.next()
		if err != nil {
			return nil, err
		}
		switch tag.Number {
		case 10:
			response.Name = string(element.Value)
		case 11:
			response.Value = append([]byte(nil), element.Value...)
		default:
			return nil, errs.Detail(ErrProtocolError, "unknown extended response field %d | 未知扩展响应字段 %d", tag.Number, tag.Number)
		}
	}
	return response, nil
}

// decodeIntermediateResponse parses an IntermediateResponse. | decodeIntermediateResponse
// 解析 IntermediateResponse。
func decodeIntermediateResponse(r *berReader) (ProtocolOp, error) {
	inner, err := protocolBody(r, appIntermediateResponse)
	if err != nil {
		return nil, err
	}
	response := &IntermediateResponse{}
	for inner.remaining() > 0 {
		tag, err := inner.peekTag()
		if err != nil {
			return nil, err
		}
		if tag.Class != berClassContext || tag.Constructed {
			return nil, errs.Detail(ErrProtocolError, "invalid intermediate response field | 非法中间响应字段")
		}
		element, err := inner.next()
		if err != nil {
			return nil, err
		}
		switch tag.Number {
		case 0:
			response.Name = string(element.Value)
		case 1:
			response.Value = append([]byte(nil), element.Value...)
		default:
			return nil, errs.Detail(ErrProtocolError, "unknown intermediate response field %d | 未知中间响应字段 %d", tag.Number, tag.Number)
		}
	}
	return response, nil
}
