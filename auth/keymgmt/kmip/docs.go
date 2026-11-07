// Package kmip implements the OASIS Key Management Interoperability Protocol (KMIP) 1.4 wire protocol together with a
// TTLV codec, typed message payloads, a TLS server and a memory object store. KMIP 2.0 payload shapes are supported
// for the implemented operations.
//
// | Package kmip 实现 OASIS 密钥管理互操作协议（KMIP）1.4 线协议，并提供 TTLV 编解码、类型化消息负载、
// TLS 服务器与内存对象存储。已实现的操作同时支持 KMIP 2.0 负载结构。
//
// # Scope boundaries | 范围边界
//
// The request header selects the payload shape: 1.4 uses Template-Attribute, while 2.0 uses Attributes and Attribute
// References. Servers dispatch by the request header version and clients encode and decode with their configured
// version. Discover Versions advertises 2.0 and 1.4. Operations or tags with no 2.0 representation return
// ErrUnsupported instead of a malformed payload. The JWK key format is supported for symmetric, RSA, EC, Ed25519 and
// X25519 keys; SM2 keys cannot be represented as JWK and return ErrUnsupported. Destroy keeps a tombstone whose key
// material has been erased, so a later Get reports Illegal Operation rather than Item Not Found. A Client never
// reconnects automatically.
//
// | 请求头选择负载结构：1.4 使用 Template-Attribute，2.0 使用 Attributes 与 Attribute Reference。服务器按请求头版本
// 分派，客户端按配置版本编解码。Discover Versions 通告 2.0 与 1.4。没有 2.0 表示的操作或标签返回 ErrUnsupported，
// 而不是生成非法负载。JWK 密钥格式支持对称、RSA、EC、Ed25519 与 X25519 密钥；SM2 密钥无法表示为 JWK，返回
// ErrUnsupported。Destroy 保留密钥材料已擦除的墓碑，因此之后的 Get 报告非法操作而不是对象不存在。Client 不会自动
// 重连。
//
// # Wire format | 线格式
//
// Every message is a TTLV structure with an eight-byte header (three-byte tag, one-byte type, four-byte length)
// followed by an eight-byte-aligned value. Structures nest; unknown tags are preserved when decoding. The
// encoder emits canonical zero padding and the decoder rejects non-canonical padding, oversized values,
// excessive nesting and excessive item counts. | 每条消息都是带八字节头的 TTLV 结构（三字节标签、一字节类型、
// 四字节长度），值按八字节对齐。结构可嵌套；解码时保留未知标签。编码器输出规范零填充，解码器拒绝非规范填充、
// 超长值、过深嵌套与过多项。
//
// # Messages | 消息
//
// RequestMessage and ResponseMessage carry a header and one or more batch items. EncodeRequest and DecodeRequest
// convert messages to and from bytes; the WithLimits variants accept custom resource limits. Typed payloads such as
// CreateRequest, GetResponse and EncryptRequest encode themselves with their Item methods. | RequestMessage 与
// ResponseMessage 携带请求头和一到多个批处理项。EncodeRequest 与 DecodeRequest 在消息与字节之间转换；
// WithLimits 变体接受自定义资源限制。CreateRequest、GetResponse、EncryptRequest 等类型化负载通过 Item 方法编码自身。
//
// # Server | 服务器
//
// NewServer builds a Server backed by a Store; MemoryStore is the default. A production listener requires TLS,
// optionally with client certificates, and can enforce authorization per batch item through an Authorizer. Batch
// items always execute serially. The Stop, Undo and Continue error-continuation policies are supported; Undo restores
// the store snapshot taken before the batch, marks prior items Operation Undone and drops their payloads. The server
// implements Create, Create Key Pair, Register, Get, Get Attributes, Get Attribute List, Activate, Revoke,
// Destroy, Locate, Derive Key, Encrypt, Decrypt, Sign, Signature Verify, MAC, MAC Verify, Query, Discover Versions
// and Check, plus the ydx Wrap Key and Unwrap Key extensions. It supports AES/SM4 block ciphers (GCM by default,
// CBC, CTR, CFB and OFB), RSA and ECDSA signatures, Ed25519, HMAC-SHA-256/384/512, SM2 and SM3 through ydx/guomi,
// and Raw, Transparent, PKCS#1, PKCS#8, X.509, SEC1 and JWK key formats. | NewServer 构造由 Store 支持的 Server，
// 默认使用 MemoryStore。生产监听器要求 TLS，可选要求客户端证书，并可通过 Authorizer 对每个批处理项授权。
// 服务器实现 Create、Create Key Pair、Register、Get、Get Attributes、Get Attribute List、Activate、Revoke、
// Destroy、Locate、Derive Key、Encrypt、Decrypt、Sign、Signature Verify、MAC、MAC Verify、Query、Discover
// Versions 与 Check，以及 ydx 的 Wrap Key 与 Unwrap Key 扩展。它通过 ydx/guomi 支持 AES/SM4 分组密码
// （默认 GCM，另有 CBC、CTR、CFB 与 OFB）、RSA 与 ECDSA 签名、Ed25519、HMAC-SHA-256/384/512、SM2 与 SM3，
// 以及 Raw、Transparent、PKCS#1、PKCS#8、X.509、SEC1 与 JWK 密钥格式。
//
// # Client | 客户端
//
// DialContext establishes a TCP or TLS connection and returns a Client. The Client serializes requests on one
// connection, exposes typed methods for every server operation (Create, Get, Activate, Encrypt, WrapKey, ...), and
// returns the decoded response payload. A Client does not reconnect automatically; dial a new one after a
// transport error. | DialContext 建立 TCP 或 TLS 连接并返回 Client。Client 在单条连接上串行发送请求，
// 为服务器支持的每个操作（Create、Get、Activate、Encrypt、WrapKey 等）提供类型化方法，并返回解码后的
// 响应负载。Client 不会自动重连；传输错误后应重新拨号。
//
// # Security | 安全
//
// TLS is mandatory for ListenAndServe unless AllowPlaintext is explicitly set for tests. Request size, depth and
// item count are bounded, key material is never logged, intermediate padded plaintext and server-side encoded
// buffers are zeroized, MAC comparisons are constant time, and non-extractable objects cannot be exported. A client
// cannot zeroize a response buffer while decoded payloads alias it; callers should clear returned key material with
// Object.Zeroize and treat decrypted plaintext as caller-owned. | 除非测试显式
// 设置 AllowPlaintext，否则 ListenAndServe 必须使用 TLS。请求长度、深度与项数受限，绝不记录密钥材料，中间填充明文与
// 服务器端编码缓冲区会被清零，MAC 比较使用常量时间，不可导出对象无法导出。客户端无法在解码负载仍引用响应缓冲区时
// 清零该缓冲区；调用方应通过 Object.Zeroize 清除返回的密钥材料，并把解密明文视为调用方所有。
//
// # Errors | 错误
//
// Failures are sentinel errors from ydx/errs. Batch item failures carry a *ResultError with the KMIP result status,
// reason and message; errors.Is maps the reason onto the corresponding sentinel. | 失败使用 ydx/errs 的哨兵错误。
// 批处理项失败携带包含 KMIP 结果状态、原因与消息的 *ResultError；errors.Is 把原因映射到对应哨兵。
package kmip
