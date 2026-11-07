package ldap

import (
	"context"

	"github.com/shibingli/ydx/errs"
)

// OperationResult is the result and response controls of a write operation. | OperationResult
// 是写操作的结果及响应控件。
type OperationResult struct {
	// Result is the LDAPResult returned by the server. | Result 是服务端返回的 LDAPResult。
	Result LDAPResult
	// Controls are the controls attached to the response message, including
	// pre-read and post-read entries. | Controls 是响应消息附加的控件，包括预读与后读条目。
	Controls []Control
}

// Add creates an entry. | Add 创建条目。
func (c *Client) Add(ctx context.Context, dn string, attributes []Attribute, controls ...Control) error {
	_, err := c.AddWithResult(ctx, dn, attributes, controls...)
	return err
}

// AddWithResult creates an entry and returns its result controls. | AddWithResult
// 创建条目并返回结果控件。
func (c *Client) AddWithResult(ctx context.Context, dn string, attributes []Attribute, controls ...Control) (*OperationResult, error) {
	return c.operation(ctx, &AddRequest{DN: dn, Attributes: attributes}, appAddResponse, "add", controls)
}

// Modify applies ordered changes to an entry. | Modify 对条目应用有序变更。
func (c *Client) Modify(ctx context.Context, dn string, changes []ModifyChange, controls ...Control) error {
	_, err := c.ModifyWithResult(ctx, dn, changes, controls...)
	return err
}

// ModifyWithResult applies changes and returns pre-read and post-read controls.
// | ModifyWithResult 应用变更并返回预读与后读控件。
func (c *Client) ModifyWithResult(ctx context.Context, dn string, changes []ModifyChange, controls ...Control) (*OperationResult, error) {
	return c.operation(ctx, &ModifyRequest{DN: dn, Changes: changes}, appModifyResponse, "modify", controls)
}

// Delete removes an entry. | Delete 删除条目。
func (c *Client) Delete(ctx context.Context, dn string, controls ...Control) error {
	_, err := c.DeleteWithResult(ctx, dn, controls...)
	return err
}

// DeleteWithResult removes an entry and returns its result controls. | DeleteWithResult
// 删除条目并返回结果控件。
func (c *Client) DeleteWithResult(ctx context.Context, dn string, controls ...Control) (*OperationResult, error) {
	return c.operation(ctx, &DeleteRequest{DN: dn}, appDeleteResponse, "delete", controls)
}

// ModifyDN renames or moves an entry. An empty newSuperior keeps the parent. | ModifyDN
// 重命名或移动条目。newSuperior 为空时保持原父节点。
func (c *Client) ModifyDN(ctx context.Context, dn, newRDN string, deleteOldRDN bool, newSuperior string, controls ...Control) error {
	_, err := c.ModifyDNWithResult(ctx, dn, newRDN, deleteOldRDN, newSuperior, controls...)
	return err
}

// ModifyDNWithResult renames or moves an entry and returns result controls. | ModifyDNWithResult
// 重命名或移动条目并返回结果控件。
func (c *Client) ModifyDNWithResult(ctx context.Context, dn, newRDN string, deleteOldRDN bool, newSuperior string, controls ...Control) (*OperationResult, error) {
	return c.operation(ctx, &ModifyDNRequest{
		DN:           dn,
		NewRDN:       newRDN,
		DeleteOldRDN: deleteOldRDN,
		NewSuperior:  newSuperior,
	}, appModifyDNResponse, "modify DN", controls)
}

// Compare reports whether value is an attribute value of dn. LDAP result codes
// five and six are the false and true answers; every other non-success code is
// an error. | Compare 报告 value 是否为 dn 的属性值。LDAP 结果码五与六分别表示假与真；
// 其他非成功结果码都是错误。
func (c *Client) Compare(ctx context.Context, dn, attribute, value string) (bool, error) {
	release, err := c.acquire(ctx, true)
	if err != nil {
		return false, err
	}
	defer release()
	message, err := c.exchangeLocked(ctx, &CompareRequest{DN: dn, Attribute: attribute, Value: value}, nil)
	if err != nil {
		return false, err
	}
	response, ok := message.Op.(*CompareResponse)
	if !ok {
		c.invalidateConnLocked()
		return false, errs.Detail(ErrUnexpectedResponse, "compare returned %T | 比较返回 %T", message.Op, message.Op)
	}
	switch response.Result.Code {
	case ResultCompareTrue:
		return true, nil
	case ResultCompareFalse:
		return false, nil
	default:
		return false, newResultError("compare", response.Result)
	}
}

// operation performs a write request and requires the expected response tag. | operation
// 执行写请求并要求预期的响应标签。
func (c *Client) operation(ctx context.Context, request ProtocolOp, responseTag uint32, operation string, controls []Control) (*OperationResult, error) {
	release, err := c.acquire(ctx, true)
	if err != nil {
		return nil, err
	}
	defer release()
	message, err := c.exchangeLocked(ctx, request, controls)
	if err != nil {
		return nil, err
	}
	if message.Op.protocolTag() != responseTag {
		c.invalidateConnLocked()
		return nil, errs.Detail(ErrUnexpectedResponse, "%s returned %T | %s 返回 %T", operation, message.Op, operation, message.Op)
	}
	result, ok := protocolResult(message.Op)
	if !ok {
		c.invalidateConnLocked()
		return nil, errs.Detail(ErrUnexpectedResponse, "%s returned %T | %s 返回 %T", operation, message.Op, operation, message.Op)
	}
	operationResult := &OperationResult{Result: result, Controls: append([]Control(nil), message.Controls...)}
	if result.Code != ResultSuccess {
		return operationResult, newResultError(operation, result)
	}
	return operationResult, nil
}

// protocolResult extracts the common result from a response operation. | protocolResult
// 从响应操作中提取公共结果。
func protocolResult(op ProtocolOp) (LDAPResult, bool) {
	switch response := op.(type) {
	case *BindResponse:
		return response.Result, true
	case *SearchResultDone:
		return response.Result, true
	case *ModifyResponse:
		return response.Result, true
	case *AddResponse:
		return response.Result, true
	case *DeleteResponse:
		return response.Result, true
	case *ModifyDNResponse:
		return response.Result, true
	case *CompareResponse:
		return response.Result, true
	case *ExtendedResponse:
		return response.Result, true
	default:
		return LDAPResult{}, false
	}
}

// Extended performs an RFC 4511 extended operation. A non-success result is
// returned together with its typed error. | Extended 执行 RFC 4511 扩展操作。非成功
// 结果会与类型化错误一起返回。
func (c *Client) Extended(ctx context.Context, name string, value []byte, controls ...Control) (*ExtendedResponse, error) {
	if name == "" {
		return nil, errs.Detail(ErrInvalidMessage, "extended operation name is empty | 扩展操作名为空")
	}
	release, err := c.acquire(ctx, true)
	if err != nil {
		return nil, err
	}
	defer release()
	message, err := c.exchangeLocked(ctx, &ExtendedRequest{Name: name, Value: value}, controls)
	if err != nil {
		return nil, err
	}
	response, ok := message.Op.(*ExtendedResponse)
	if !ok {
		c.invalidateConnLocked()
		return nil, errs.Detail(ErrUnexpectedResponse, "extended operation returned %T | 扩展操作返回 %T", message.Op, message.Op)
	}
	if response.Result.Code != ResultSuccess {
		return response, newResultError("extended operation "+name, response.Result)
	}
	return response, nil
}

// WhoAmI performs RFC 4532 and returns the authorization identity string. | WhoAmI
// 执行 RFC 4532 并返回授权身份字符串。
func (c *Client) WhoAmI(ctx context.Context) (string, error) {
	response, err := c.Extended(ctx, OIDWhoAmI, nil)
	if err != nil {
		return "", err
	}
	return string(response.Value), nil
}

// PasswordModify performs RFC 3062 and returns the server-generated password
// when one is supplied. Empty fields are omitted; the old password is never
// included in an error. | PasswordModify 执行 RFC 3062，并在服务端生成口令时返回它。
// 空字段会被省略；旧口令绝不会出现在错误中。
func (c *Client) PasswordModify(ctx context.Context, userIdentity, oldPassword, newPassword string) (string, error) {
	e := newBEREncoder(128)
	e.open(berClassUniversal, berTagSequence)
	if userIdentity != "" {
		e.primitive(berClassContext, 0, []byte(userIdentity))
	}
	if oldPassword != "" {
		e.primitive(berClassContext, 1, []byte(oldPassword))
	}
	if newPassword != "" {
		e.primitive(berClassContext, 2, []byte(newPassword))
	}
	e.close()
	response, err := c.Extended(ctx, OIDPasswordModify, e.bytes())
	if err != nil {
		return "", err
	}
	if len(response.Value) == 0 {
		return "", nil
	}
	r := newBERReader(response.Value)
	element, err := r.expectSequence()
	if err != nil {
		return "", err
	}
	inner, err := r.subReader(element)
	if err != nil {
		return "", err
	}
	var generated string
	if inner.remaining() > 0 {
		value, err := inner.expect(berClassContext, false, 0)
		if err != nil {
			return "", err
		}
		generated = string(value.Value)
	}
	if err := inner.expectEnd(); err != nil {
		return "", err
	}
	if err := r.expectEnd(); err != nil {
		return "", err
	}
	return generated, nil
}

// RootDSE returns the server root DSE. The search is base-scoped with an
// objectClass presence filter and requests user and operational attributes. | RootDSE
// 返回服务端根 DSE。搜索采用 base 范围与 objectClass 存在过滤器，并请求用户属性与操作属性。
func (c *Client) RootDSE(ctx context.Context) (*Entry, error) {
	result, err := c.Search(ctx, SearchOptions{
		BaseDN:     "",
		Scope:      ScopeBaseObject,
		Filter:     Present("objectClass"),
		Attributes: []string{"*", "+"},
	})
	if err != nil {
		return nil, err
	}
	if len(result.Entries) == 0 {
		return nil, errs.Detail(ErrNoSuchObject, "root DSE returned no entry | 根 DSE 未返回条目")
	}
	return result.Entries[0], nil
}

// Schema returns the subschema subentry advertised by the root DSE. | Schema
// 返回根 DSE 通告的子模式子条目。
func (c *Client) Schema(ctx context.Context) (*Entry, error) {
	root, err := c.RootDSE(ctx)
	if err != nil {
		return nil, err
	}
	subschema := root.First("subschemaSubentry")
	if subschema == "" {
		return nil, errs.Detail(ErrNoSuchAttribute, "root DSE has no subschemaSubentry | 根 DSE 没有 subschemaSubentry")
	}
	result, err := c.Search(ctx, SearchOptions{
		BaseDN:     subschema,
		Scope:      ScopeBaseObject,
		Filter:     Present("objectClass"),
		Attributes: []string{"*", "+"},
	})
	if err != nil {
		return nil, err
	}
	if len(result.Entries) == 0 {
		return nil, errs.Detail(ErrNoSuchObject, "subschema entry %s not found | 子模式条目 %s 不存在", subschema, subschema)
	}
	return result.Entries[0], nil
}

// Health checks server reachability by reading the root DSE. | Health 通过读取根 DSE
// 检查服务端可达性。
func (c *Client) Health(ctx context.Context) error {
	_, err := c.RootDSE(ctx)
	return err
}
