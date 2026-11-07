package saml

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"strings"
	"time"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
)

// HTTP-Artifact binding constants. | HTTP-Artifact 绑定常量。
const (
	// ArtifactTypeHTTP is the SAML 2.0 type-code 0x0004 artifact. | ArtifactTypeHTTP 是 SAML 2.0
	// 类型码 0x0004 工件。
	ArtifactTypeHTTP uint16 = 0x0004
	// ArtifactSize is the encoded artifact length in bytes. | ArtifactSize 是工件编码后的字节长度。
	ArtifactSize = 44
	// ArtifactEndpointIndexSize is the endpoint index field length in bytes. | ArtifactEndpointIndexSize
	// 是端点索引字段的字节长度。
	ArtifactEndpointIndexSize = 2
	// ArtifactSourceIDSize is the source identifier field length in bytes. | ArtifactSourceIDSize 是
	// 源标识字段的字节长度。
	ArtifactSourceIDSize = 20
	// ArtifactMessageHandleSize is the message handle field length in bytes. | ArtifactMessageHandleSize
	// 是消息句柄字段的字节长度。
	ArtifactMessageHandleSize = 20
	// ArtifactParameter is the HTTP parameter carrying a SAML artifact. | ArtifactParameter 是携带
	// SAML 工件的 HTTP 参数名。
	ArtifactParameter = "SAMLart"
	// DefaultArtifactTTL is the default artifact lifetime. | DefaultArtifactTTL 是默认工件寿命。
	DefaultArtifactTTL = 5 * time.Minute
)

// Artifact is a SAML 2.0 HTTP-Artifact binding artifact of type 0x0004. It carries the endpoint
// index, the 20-byte source identifier issued by the identity provider and the 20-byte message
// handle that identifies the stored protocol message. | Artifact 是 SAML 2.0 HTTP-Artifact 绑定
// 的类型 0x0004 工件。它携带端点索引、身份提供方签发的 20 字节源标识，以及标识所存协议消息的
// 20 字节消息句柄。
type Artifact struct {
	// Type is the artifact type code; the HTTP-Artifact binding uses 0x0004. | Type 是工件类型码；
	// HTTP-Artifact 绑定使用 0x0004。
	Type uint16
	// EndpointIndex selects the issuer's artifact resolution endpoint. | EndpointIndex 选择签发方的
	// 工件解析端点。
	EndpointIndex uint16
	// SourceID identifies the issuing identity provider. | SourceID 标识签发身份提供方。
	SourceID [ArtifactSourceIDSize]byte
	// MessageHandle identifies the stored protocol message. | MessageHandle 标识所存协议消息。
	MessageHandle [ArtifactMessageHandleSize]byte
}

// NewArtifactSourceID returns a cryptographically random source identifier. | NewArtifactSourceID
// 返回密码学随机的源标识。
func NewArtifactSourceID() (sourceID [ArtifactSourceIDSize]byte, err error) {
	if _, err := rand.Read(sourceID[:]); err != nil {
		return sourceID, errs.WrapDetail(err, ErrArtifactInvalid, "random source id | 随机源标识")
	}
	return sourceID, nil
}

// NewArtifact returns a type 0x0004 artifact for sourceID with a cryptographically random message
// handle. | NewArtifact 返回 sourceID 的类型 0x0004 工件，并使用密码学随机的消息句柄。
func NewArtifact(endpointIndex uint16, sourceID [ArtifactSourceIDSize]byte) (*Artifact, error) {
	artifact := &Artifact{
		Type:          ArtifactTypeHTTP,
		EndpointIndex: endpointIndex,
		SourceID:      sourceID,
	}
	if _, err := rand.Read(artifact.MessageHandle[:]); err != nil {
		return nil, errs.WrapDetail(err, ErrArtifactInvalid, "random message handle | 随机消息句柄")
	}
	return artifact, nil
}

// AppendTo appends the 44-byte artifact encoding to dst and returns the extended slice. | AppendTo
// 把 44 字节工件编码追加到 dst 并返回扩展后的切片。
func (a Artifact) AppendTo(dst []byte) []byte {
	var encoded [ArtifactSize]byte
	binary.BigEndian.PutUint16(encoded[0:2], a.Type)
	binary.BigEndian.PutUint16(encoded[2:4], a.EndpointIndex)
	copy(encoded[4:4+ArtifactSourceIDSize], a.SourceID[:])
	copy(encoded[4+ArtifactSourceIDSize:], a.MessageHandle[:])
	return append(dst, encoded[:]...)
}

// Bytes returns the 44-byte artifact encoding. | Bytes 返回 44 字节工件编码。
func (a Artifact) Bytes() []byte { return a.AppendTo(nil) }

// String returns the Base64 SAMLart value. | String 返回 Base64 SAMLart 取值。
func (a Artifact) String() string { return base64.StdEncoding.EncodeToString(a.Bytes()) }

// SameSource reports whether a and b carry the same source identifier, compared in constant time.
// | SameSource 以常量时间报告 a 与 b 是否携带相同的源标识。
func (a Artifact) SameSource(b Artifact) bool {
	return subtle.ConstantTimeCompare(a.SourceID[:], b.SourceID[:]) == 1
}

// sameMessage reports whether a and b carry the same message handle, compared in constant time. |
// sameMessage 以常量时间报告 a 与 b 是否携带相同的消息句柄。
func (a Artifact) sameMessage(b Artifact) bool {
	return subtle.ConstantTimeCompare(a.MessageHandle[:], b.MessageHandle[:]) == 1
}

// storeKey returns the store lookup key, which covers the type, source identifier and message
// handle but not the endpoint index. | storeKey 返回存储查找键，覆盖类型、源标识与消息句柄，但
// 不包含端点索引。
func (a Artifact) storeKey() string {
	var key [ArtifactSize - ArtifactEndpointIndexSize]byte
	binary.BigEndian.PutUint16(key[0:2], a.Type)
	copy(key[2:2+ArtifactSourceIDSize], a.SourceID[:])
	copy(key[2+ArtifactSourceIDSize:], a.MessageHandle[:])
	return string(key[:])
}

// EncodeArtifact returns the Base64 SAMLart value of artifact. | EncodeArtifact 返回工件的 Base64
// SAMLart 取值。
func EncodeArtifact(artifact Artifact) string { return artifact.String() }

// DecodeArtifact parses a Base64-encoded type 0x0004 artifact. Surrounding whitespace and missing
// padding are tolerated; the decoded value must be exactly 44 bytes with type 0x0004. | DecodeArtifact
// 解析 Base64 编码的类型 0x0004 工件。容忍首尾空白与缺失填充；解码值必须恰好为 44 字节且类型为
// 0x0004。
func DecodeArtifact(value string) (*Artifact, error) {
	compact := strings.TrimSpace(value)
	if compact == "" {
		return nil, errs.Detail(ErrArtifactInvalid, "artifact is empty | 工件为空")
	}
	decoded, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(compact)
	}
	if err != nil {
		return nil, errs.WrapDetail(err, ErrArtifactInvalid, "artifact encoding | 工件编码")
	}
	if len(decoded) != ArtifactSize {
		return nil, errs.Detail(ErrArtifactInvalid, "artifact length %d | 工件长度 %d", len(decoded), len(decoded))
	}
	artifact := &Artifact{
		Type:          binary.BigEndian.Uint16(decoded[0:2]),
		EndpointIndex: binary.BigEndian.Uint16(decoded[2:4]),
	}
	copy(artifact.SourceID[:], decoded[4:4+ArtifactSourceIDSize])
	copy(artifact.MessageHandle[:], decoded[4+ArtifactSourceIDSize:ArtifactSize])
	if artifact.Type != ArtifactTypeHTTP {
		return nil, errs.Detail(ErrArtifactInvalid, "artifact type 0x%04x | 工件类型 0x%04x", artifact.Type, artifact.Type)
	}
	return artifact, nil
}
