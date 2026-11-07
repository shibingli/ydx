package oauth2

import (
	"context"
	"net/url"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// resolveRequestObjectValues replaces outer authorization parameters with the verified contents of
// an RFC 9101 request object. | resolveRequestObjectValues 用 RFC 9101 请求对象的已校验内容替换外层
// 授权参数。
//
// Per RFC 9101 section 6.1 only the parameters inside the signed object are used; duplicate outer
// parameters are ignored rather than merged. PAR request URIs are returned untouched for the caller
// to consume. | 按 RFC 9101 第 6.1 节，仅使用已签名对象内的参数；外层重复参数被忽略而不是合并。
// PAR 请求 URI 原样返回，由调用方消费。
func (s *Server) resolveRequestObjectValues(ctx context.Context, raw url.Values) (url.Values, error) {
	if raw == nil {
		return nil, nil
	}
	requestObject := strings.TrimSpace(raw.Get("request"))
	requestURI := strings.TrimSpace(raw.Get("request_uri"))
	if requestObject != "" && requestURI != "" {
		// RFC 9101 section 6.1: request and request_uri are mutually exclusive. | RFC 9101 第 6.1
		// 节：request 与 request_uri 互斥。
		return nil, errs.Detail(ErrInvalidRequest, "request and request_uri cannot be combined | request 与 request_uri 不能同时使用")
	}
	if requestObject == "" && requestURI == "" {
		return raw, nil
	}
	if requestURI != "" && strings.HasPrefix(requestURI, PARRequestURIPrefix) {
		return raw, nil
	}
	clientID := strings.TrimSpace(raw.Get("client_id"))
	if clientID == "" {
		return nil, errs.Detail(ErrInvalidRequest, "client_id is required with a request object | 使用请求对象时必须提供 client_id")
	}
	client, err := s.config.Clients.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	object := requestObject
	if object == "" {
		if !s.config.RequestURIs.Enabled {
			return nil, NewError(ErrorRequestURINotSupported, "only pushed request_uri values are supported | 仅支持推送的 request_uri")
		}
		object, err = s.requestURIs.Fetch(ctx, client, requestURI)
		if err != nil {
			return nil, err
		}
	} else if !s.config.RequestObjects.Enabled {
		return nil, NewError(ErrorRequestNotSupported, "request objects are not supported | 不支持请求对象")
	}
	params, err := s.requestObjects.verify(ctx, client, object, s.Issuer())
	if err != nil {
		return nil, err
	}
	// The verified object necessarily carries the client_id claim; pin it to the authenticated
	// registration so later parsing cannot resolve a different client. | 已校验对象必然携带
	// client_id 声明；将其固定为已认证注册，避免后续解析到其他客户端。
	params.Set("client_id", client.ID)
	return params, nil
}
