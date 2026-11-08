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
// References. Only KMIP 1.4 and 2.0 are accepted; 1.0 through 1.3 are declared for reference but rejected with
// ErrUnsupported. Servers dispatch by the request header version and clients encode and decode with their configured
// version. Discover Versions advertises 2.0 and 1.4. Operations or tags with no 2.0 representation return
// ErrUnsupported instead of a malformed payload. Export is a 1.4-only operation: it is served for 1.4 requests and
// returns ErrUnsupported for 2.0, where Get replaces it. The JWK key format is supported for symmetric, RSA, EC,
// Ed25519 and X25519 keys; SM2 keys cannot be represented as JWK and return ErrUnsupported. Destroy keeps a tombstone
// whose key material has been erased, so a later Get reports Illegal Operation rather than Item Not Found. Batch Undo
// keeps a per-batch inverse-operation journal rather than a full-store snapshot: before each mutation the server
// records the affected object's complete previous state (key material, attributes, lifecycle state, dates and any
// destroyed tombstone), or the identifier of a newly created object. On failure the journal is replayed in reverse
// order, deleting created objects and restoring updated or deleted ones. The journal is isolated to one request
// message, batches are serialized per server, it is cleared after every batch, and MaxUndoLogBytes bounds its memory;
// an over-budget mutation fails with ErrUndoLogLimit before it is applied. A Client reconnects lazily; see the Client
// section.
//
// | 请求头选择负载结构：1.4 使用 Template-Attribute，2.0 使用 Attributes 与 Attribute Reference。仅接受 KMIP 1.4
// 与 2.0；1.0 至 1.3 仅作参考声明，返回 ErrUnsupported。服务器按请求头版本分派，客户端按配置版本编解码。
// Discover Versions 通告 2.0 与 1.4。没有 2.0 表示的操作或标签返回 ErrUnsupported，而不是生成非法负载。
// Export 是仅限 1.4 的操作：对 1.4 请求提供服务，对 2.0 返回 ErrUnsupported，2.0 中由 Get 替代。JWK 密钥格式
// 支持对称、RSA、EC、Ed25519 与 X25519 密钥；SM2 密钥无法表示为 JWK，返回 ErrUnsupported。Destroy 保留密钥
// 材料已擦除的墓碑，因此之后的 Get 报告非法操作而不是对象不存在。批处理 Undo 使用每批逆操作日志而不是完整
// 存储快照：每次变更前，服务器记录受影响对象的完整先前状态（密钥材料、属性、生命周期状态、日期与销毁墓碑），
// 或记录新建对象的标识符。失败时按逆序重放日志，删除新建对象并恢复被更新或删除的对象。日志隔离在单个请求消息
// 内，服务器串行执行批处理，每批结束后清空；MaxUndoLogBytes 限制其内存，超预算的变更在应用前以
// ErrUndoLogLimit 失败。Client 采用惰性重连，见 Client 一节。
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
// items always execute serially. The Stop, Undo and Continue error-continuation policies are supported; Undo replays
// the per-batch inverse-operation journal, marks prior items Operation Undone and drops their payloads. The server
// implements Create, Create Key Pair, Register, Get, Get Attributes, Get Attribute List, Activate, Revoke,
// Destroy, Export, Locate, Derive Key, Encrypt, Decrypt, Sign, Signature Verify, MAC, MAC Verify, Query, Discover
// Versions and Check, plus the ydx Wrap Key and Unwrap Key extensions. Export is available for KMIP 1.4 and is
// rejected with ErrUnsupported for KMIP 2.0. It supports AES/SM4 block ciphers (GCM by default,
// CBC, CTR, CFB and OFB), RSA and ECDSA signatures, Ed25519, HMAC-SHA-256/384/512, SM2 and SM3 through ydx/guomi,
// and Raw, Transparent, PKCS#1, PKCS#8, X.509, SEC1 and JWK key formats. | NewServer 构造由 Store 支持的 Server，
// 默认使用 MemoryStore。生产监听器要求 TLS，可选要求客户端证书，并可通过 Authorizer 对每个批处理项授权。
// 服务器实现 Create、Create Key Pair、Register、Get、Get Attributes、Get Attribute List、Activate、Revoke、
// Destroy、Export、Locate、Derive Key、Encrypt、Decrypt、Sign、Signature Verify、MAC、MAC Verify、Query、
// Discover Versions 与 Check，以及 ydx 的 Wrap Key 与 Unwrap Key 扩展。Export 在 KMIP 1.4 可用，对 KMIP 2.0
// 以 ErrUnsupported 拒绝。它通过 ydx/guomi 支持 AES/SM4 分组密码
// （默认 GCM，另有 CBC、CTR、CFB 与 OFB）、RSA 与 ECDSA 签名、Ed25519、HMAC-SHA-256/384/512、SM2 与 SM3，
// 以及 Raw、Transparent、PKCS#1、PKCS#8、X.509、SEC1 与 JWK 密钥格式。
//
// # Client | 客户端
//
// DialContext establishes a TCP or TLS connection and returns a Client. The Client serializes requests on one
// connection, exposes typed methods for every server operation (Create, Get, Export, Activate, Encrypt, WrapKey, ...),
// and returns the decoded response payload. A Client reconnects lazily: after a transport failure it drops the broken
// connection and the next request dials a fresh one. The failed request is returned to the caller and never replayed,
// because it may already have been written; for mutating operations a transport error therefore means the outcome is
// unknown. Close is permanent and disables reconnection. | DialContext 建立 TCP 或 TLS 连接并返回 Client。Client
// 在单条连接上串行发送请求，为服务器支持的每个操作（Create、Get、Export、Activate、Encrypt、WrapKey 等）提供
// 类型化方法，并返回解码后的响应负载。Client 采用惰性重连：传输失败后丢弃损坏的连接，下一个请求重新拨号。
// 失败的请求返回给调用方且绝不重放，因为它可能已经写入；因此对变更类操作而言，传输错误表示结果未知。Close 是
// 永久性的，会禁用重连。
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
