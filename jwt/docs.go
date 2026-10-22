// Package jwt implements JWT (RFC 7519) signing, verification and HTTP middleware,
// with a validation path that never reflects and never builds a map of the claims.
// | Package jwt 实现 JWT（RFC 7519）的签发、校验与 HTTP 中间件，其校验路径既不使用反射，
// 也不构造声明 map。
//
// The design follows the framework rule that a decision about a claim must be taken on
// the bytes that were signed. Parse never decodes the payload into map[string]any: it
// scans the decoded payload bytes with the hand-written scanner in scan.go, so exp / nbf
// / iat / iss / aud / sub are validated against exactly the bytes the signature covers.
// | 本设计遵循框架约定：关于声明的判定必须落在被签名的字节上。Parse 绝不把载荷解码成
// map[string]any，而是用 scan.go 中手写的扫描器读取解码后的载荷字节，因此 exp / nbf / iat /
// iss / aud / sub 校验的正是签名所覆盖的那份字节。
//
// Supported algorithms | 受支持的算法：
//
//	HS256 HS384 HS512  HMAC with SHA-2 | HMAC + SHA-2
//	RS256 RS384 RS512  RSASSA-PKCS1-v1_5
//	PS256 PS384 PS512  RSASSA-PSS
//	ES256 ES384 ES512  ECDSA
//	EdDSA              Ed25519
//
// "none" is never accepted, and a key from the wrong family is rejected with
// ErrSignatureInvalid, which closes the classic algorithm-confusion attack. | 永不接受
// "none"；密钥族不符一律以 ErrSignatureInvalid 拒绝，从而封堵经典的算法混淆攻击。
//
// Both middleware entry points share the same token lookup and Parse path: Middleware
// stores the token in a router.Ctx, while HTTPMiddleware stores it in the request
// context for plain net/http servers. | 两个中间件入口共享同一套 token 提取与 Parse 路径：
// Middleware 把 token 存入 router.Ctx，HTTPMiddleware 为原生 net/http 服务端把它存入请求上下文。
//
// Typical usage | 典型用法：
//
//	r.Use(jwt.Middleware(jwt.MiddlewareOptions{KeyFunc: keyFn}))
//
//	// plain net/http | 原生 net/http
//	handler := jwt.HTTPMiddleware(jwt.HTTPMiddlewareOptions{KeyFunc: keyFn})(mux)
package jwt
