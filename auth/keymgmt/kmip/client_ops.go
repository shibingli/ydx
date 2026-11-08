package kmip

import (
	"context"

	"github.com/shibingli/ydx/errs"
)

// requestPayload is any typed KMIP request payload. | requestPayload 是任意类型化的 KMIP 请求负载。
type requestPayload interface {
	// Item encodes the payload into its TTLV structure. | Item 把负载编码为其 TTLV 结构。
	Item() (Item, error)
}

// versionedRequestPayload is a request payload that can select the wire shape for a protocol version. |
// versionedRequestPayload 是能够按协议版本选择线格式的请求负载。
type versionedRequestPayload interface {
	// ItemForVersion encodes the payload using the wire shape of version. | ItemForVersion 使用 version 的线格式编码负载。
	ItemForVersion(ProtocolVersion) (Item, error)
}

// decodeForVersion binds a version-aware decoder to one protocol version. | decodeForVersion 把版本感知解码器绑定到
// 一个协议版本。
func decodeForVersion[T any](version ProtocolVersion, decode func(Item, ProtocolVersion) (T, error)) func(Item) (T, error) {
	return func(item Item) (T, error) {
		return decode(item, version)
	}
}

// call encodes one request, sends it as a single-item batch and decodes the response payload. |
// call 编码一个请求，作为单项批处理发送，并解码响应负载。
func call[T any](c *Client, ctx context.Context, operation Operation, request requestPayload, decode func(Item) (T, error)) (T, error) {
	var zero T
	var payload Item
	var err error
	if versioned, ok := request.(versionedRequestPayload); ok {
		payload, err = versioned.ItemForVersion(c.cfg.ProtocolVersion)
	} else {
		payload, err = request.Item()
	}
	if err != nil {
		return zero, err
	}
	response, err := c.Do(ctx, RequestBatchItem{Operation: operation, Payload: payload})
	if err != nil {
		return zero, err
	}
	if len(response.BatchItems) != 1 {
		return zero, errs.Detail(ErrMalformed, "expected one response batch item, got %d | 期望一个响应批处理项，实际 %d", len(response.BatchItems), len(response.BatchItems))
	}
	item := response.BatchItems[0]
	if err := item.Err(); err != nil {
		return zero, err
	}
	if item.Payload.Type == 0 {
		return zero, errs.Detail(ErrMalformed, "response batch item has no payload | 响应批处理项没有负载")
	}
	return decode(item.Payload)
}

// Create sends a Create request. | Create 发送 Create 请求。
func (c *Client) Create(ctx context.Context, request CreateRequest) (CreateResponse, error) {
	return call(c, ctx, OpCreate, request, decodeForVersion(c.cfg.ProtocolVersion, DecodeCreateResponseForVersion))
}

// CreateKeyPair sends a Create Key Pair request. | CreateKeyPair 发送 Create Key Pair 请求。
func (c *Client) CreateKeyPair(ctx context.Context, request CreateKeyPairRequest) (CreateKeyPairResponse, error) {
	return call(c, ctx, OpCreateKeyPair, request, decodeForVersion(c.cfg.ProtocolVersion, DecodeCreateKeyPairResponseForVersion))
}

// Register sends a Register request. | Register 发送 Register 请求。
func (c *Client) Register(ctx context.Context, request RegisterRequest) (RegisterResponse, error) {
	return call(c, ctx, OpRegister, request, decodeForVersion(c.cfg.ProtocolVersion, DecodeRegisterResponseForVersion))
}

// Get sends a Get request. | Get 发送 Get 请求。
func (c *Client) Get(ctx context.Context, request GetRequest) (GetResponse, error) {
	return call(c, ctx, OpGet, request, decodeForVersion(c.cfg.ProtocolVersion, DecodeGetResponseForVersion))
}

// GetAttributes sends a Get Attributes request. | GetAttributes 发送 Get Attributes 请求。
func (c *Client) GetAttributes(ctx context.Context, request GetAttributesRequest) (GetAttributesResponse, error) {
	return call(c, ctx, OpGetAttributes, request, decodeForVersion(c.cfg.ProtocolVersion, DecodeGetAttributesResponseForVersion))
}

// GetAttributeList sends a Get Attribute List request. | GetAttributeList 发送 Get Attribute List 请求。
func (c *Client) GetAttributeList(ctx context.Context, request GetAttributeListRequest) (GetAttributeListResponse, error) {
	return call(c, ctx, OpGetAttributeList, request, decodeForVersion(c.cfg.ProtocolVersion, DecodeGetAttributeListResponseForVersion))
}

// Activate sends an Activate request. | Activate 发送 Activate 请求。
func (c *Client) Activate(ctx context.Context, request ActivateRequest) (ActivateResponse, error) {
	return call(c, ctx, OpActivate, request, DecodeActivateResponse)
}

// Revoke sends a Revoke request. | Revoke 发送 Revoke 请求。
func (c *Client) Revoke(ctx context.Context, request RevokeRequest) (RevokeResponse, error) {
	return call(c, ctx, OpRevoke, request, DecodeRevokeResponse)
}

// Destroy sends a Destroy request. | Destroy 发送 Destroy 请求。
func (c *Client) Destroy(ctx context.Context, request DestroyRequest) (DestroyResponse, error) {
	return call(c, ctx, OpDestroy, request, DecodeDestroyResponse)
}

// Locate sends a Locate request. | Locate 发送 Locate 请求。
func (c *Client) Locate(ctx context.Context, request LocateRequest) (LocateResponse, error) {
	return call(c, ctx, OpLocate, request, DecodeLocateResponse)
}

// DeriveKey sends a Derive Key request. | DeriveKey 发送 Derive Key 请求。
func (c *Client) DeriveKey(ctx context.Context, request DeriveKeyRequest) (DeriveKeyResponse, error) {
	return call(c, ctx, OpDeriveKey, request, decodeForVersion(c.cfg.ProtocolVersion, DecodeDeriveKeyResponseForVersion))
}

// Encrypt sends an Encrypt request. | Encrypt 发送 Encrypt 请求。
func (c *Client) Encrypt(ctx context.Context, request EncryptRequest) (EncryptResponse, error) {
	return call(c, ctx, OpEncrypt, request, DecodeEncryptResponse)
}

// Decrypt sends a Decrypt request. | Decrypt 发送 Decrypt 请求。
func (c *Client) Decrypt(ctx context.Context, request DecryptRequest) (DecryptResponse, error) {
	return call(c, ctx, OpDecrypt, request, DecodeDecryptResponse)
}

// Sign sends a Sign request. | Sign 发送 Sign 请求。
func (c *Client) Sign(ctx context.Context, request SignRequest) (SignResponse, error) {
	return call(c, ctx, OpSign, request, DecodeSignResponse)
}

// Verify sends a Signature Verify request. | Verify 发送 Signature Verify 请求。
func (c *Client) Verify(ctx context.Context, request VerifyRequest) (VerifyResponse, error) {
	return call(c, ctx, OpSignatureVerify, request, DecodeVerifyResponse)
}

// MAC sends a MAC request. | MAC 发送 MAC 请求。
func (c *Client) MAC(ctx context.Context, request MACRequest) (MACResponse, error) {
	return call(c, ctx, OpMAC, request, DecodeMACResponse)
}

// MACVerify sends a MAC Verify request. | MACVerify 发送 MAC Verify 请求。
func (c *Client) MACVerify(ctx context.Context, request MACVerifyRequest) (MACVerifyResponse, error) {
	return call(c, ctx, OpMACVerify, request, DecodeMACVerifyResponse)
}

// WrapKey sends a ydx Wrap Key request. | WrapKey 发送 ydx Wrap Key 请求。
func (c *Client) WrapKey(ctx context.Context, request WrapKeyRequest) (WrapKeyResponse, error) {
	return call(c, ctx, OpWrapKey, request, decodeForVersion(c.cfg.ProtocolVersion, DecodeWrapKeyResponseForVersion))
}

// UnwrapKey sends a ydx Unwrap Key request. | UnwrapKey 发送 ydx Unwrap Key 请求。
func (c *Client) UnwrapKey(ctx context.Context, request UnwrapKeyRequest) (UnwrapKeyResponse, error) {
	return call(c, ctx, OpUnwrapKey, request, DecodeUnwrapKeyResponse)
}

// Query sends a Query request. | Query 发送 Query 请求。
func (c *Client) Query(ctx context.Context, request QueryRequest) (QueryResponse, error) {
	return call(c, ctx, OpQuery, request, DecodeQueryResponse)
}

// DiscoverVersions sends a Discover Versions request. | DiscoverVersions 发送 Discover Versions 请求。
func (c *Client) DiscoverVersions(ctx context.Context, request DiscoverVersionsRequest) (DiscoverVersionsResponse, error) {
	return call(c, ctx, OpDiscoverVersions, request, DecodeDiscoverVersionsResponse)
}

// Check sends a Check request. | Check 发送 Check 请求。
func (c *Client) Check(ctx context.Context, request CheckRequest) (CheckResponse, error) {
	return call(c, ctx, OpCheck, request, DecodeCheckResponse)
}
