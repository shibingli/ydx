// Package kms is a self-contained key management service: NIST SP 800-57 key lifecycle, envelope
// encryption, authenticated encryption, digital signatures, key wrapping, HKDF derivation and an
// audited HTTP API with YD router and net/http entry points. | kms 包是自包含的密钥管理服务：
// NIST SP 800-57 密钥生命周期、信封加密、认证加密、数字签名、密钥包装、HKDF 派生，以及同时提供
// YD 路由与 net/http 入口的审计 HTTP API。
//
// # Key lifecycle | 密钥生命周期
//
// Keys are created in StatePreActive and must be activated before use. The transition graph is:
// pre-active → active/deactivated/compromised/pending-deletion; active → deactivated/compromised/
// pending-deletion; deactivated → compromised/destroyed/pending-deletion; compromised → destroyed/
// pending-deletion; pending-deletion → destroyed. Destroyed is terminal and erases material. | 密钥
// 创建为 StatePreActive，使用前必须激活。转换图为：pre-active → active/deactivated/compromised/
// pending-deletion；active → deactivated/compromised/pending-deletion；deactivated → compromised/
// destroyed/pending-deletion；compromised → destroyed/pending-deletion；pending-deletion → destroyed。
// destroyed 为终态并擦除材料。
//
// # Supported algorithms | 支持的算法
//
// AES-128/192/256-GCM, ChaCha20-Poly1305 and SM4-GCM for symmetric encryption; RSA 2048/3072/4096
// with PKCS#1 v1.5 or PSS; ECDSA P-256/P-384/P-521; Ed25519; and SM2. Symmetric keys also wrap keys,
// generate data keys and derive keys with HKDF-SHA256. | 对称加密支持 AES-128/192/256-GCM、
// ChaCha20-Poly1305 与 SM4-GCM；签名支持 RSA 2048/3072/4096（PKCS#1 v1.5 或 PSS）、ECDSA
// P-256/P-384/P-521、Ed25519 与 SM2。对称密钥还可包装密钥、生成数据密钥，并用 HKDF-SHA256 派生密钥。
//
// # Ciphertext format | 密文格式
//
// Encrypt returns a KMS1 blob: magic "KMS1"[4] | format version 1[1] | AEAD id[1] | key ID length
// [2, big endian] | key ID | key version[4, big endian] | nonce length 12[1] | nonce[12] |
// ciphertext+tag. The whole header and optional caller AAD are authenticated. WrapKey and
// GenerateDataKey return the same layout with magic "KMSW". Envelope.MarshalBinary returns "KMSE"[4]
// | version[1] | key ID length[2] | key ID | key version[4] | wrapped key length[2] | wrapped key |
// nonce length[1] | nonce[12] | AES-256-GCM ciphertext. | Encrypt 返回 KMS1 数据块：魔数 "KMS1"[4] |
// 格式版本 1[1] | AEAD 编号[1] | 密钥 ID 长度[2，大端] | 密钥 ID | 密钥版本[4，大端] | nonce 长度
// 12[1] | nonce[12] | 密文+标签。整个头部与可选调用方 AAD 都受认证。WrapKey 与 GenerateDataKey
// 返回相同布局，魔数为 "KMSW"。Envelope.MarshalBinary 返回 "KMSE"[4] | 版本[1] | 密钥 ID 长度[2] |
// 密钥 ID | 密钥版本[4] | 包装密钥长度[2] | 包装密钥 | nonce 长度[1] | nonce[12] | AES-256-GCM 密文。
//
// # Security properties | 安全属性
//
// Every AEAD encryption uses a fresh 96-bit crypto/rand nonce; the service rejects a repeated nonce
// before use. Private export is denied unless the key is Exportable and ExportPolicy.AllowPrivate is
// set. Material can be wrapped at rest with Config.RootKey, Config.Passphrase or a custom Wrapper.
// Set Config.RequireAtRestEncryption to reject construction with ErrInvalidConfig when none of those
// is configured; the service never derives an ephemeral wrapping key implicitly. New and its alias
// NewService enforce the same rule, and Service.AtRestEnabled reports whether wrapping is active.
// Audit events never contain plaintext, material, passphrases or wrapped DEKs. | 每次 AEAD 加密都使用
// 新的 96 位 crypto/rand nonce；服务在使用前拒绝重复 nonce。除非密钥为 Exportable 且
// ExportPolicy.AllowPrivate 已开启，否则拒绝私钥导出。可通过 Config.RootKey、
// Config.Passphrase 或自定义 Wrapper 静态包装材料。设置 Config.RequireAtRestEncryption 后，若三者
// 均未配置，构建会返回 ErrInvalidConfig；服务绝不会隐式派生临时包装密钥。New 及其别名 NewService
// 执行相同规则，Service.AtRestEnabled 报告包装是否生效。审计事件绝不包含明文、材料、口令或已包装
// DEK。
//
// # At-rest format | 静态包装格式
//
// Passphrase wrapping writes a versioned KMSM2 blob: magic "KMSM2"[5] | KDF id[1] | iterations[4,
// big endian] | key length[2, big endian] | salt length[1] | salt | nonce[12] | ciphertext+tag; the
// header is authenticated as AAD. Every write draws a fresh random salt, and unwrap uses the
// persisted iteration count and key length after bounds checks, so tampered parameters are rejected.
// The first KMSM1 format (fixed salt, no header) remains decryptable. Rewrap converts one wrapped
// blob between wrappers, and Service.RewrapAtRest rotates every wrapped key while keeping the old
// wrapper as a read fallback if a partial rotation fails. | 口令包装写入带版本的 KMSM2 数据块：
// 魔数 "KMSM2"[5] | KDF 编号[1] | 迭代次数[4，大端] | 密钥长度[2，大端] | 盐长度[1] | 盐 | nonce[12] |
// 密文+标签；头部作为 AAD 参与认证。每次写入都使用新的随机盐，解包在边界检查后使用持久化的迭代次数与
// 密钥长度，因此被篡改的参数会被拒绝。最早的 KMSM1 格式（固定盐、无头部）仍可解密。Rewrap 在包装器
// 之间转换单个数据块，Service.RewrapAtRest 轮换所有已包装密钥，并在部分轮换失败时保留旧包装器作为
// 读取回退。
//
// # YD router usage | YD 路由用法
//
//	store := kms.NewMemoryStore()
//	service, err := kms.New(kms.Config{Store: store})
//	if err != nil {
//		return err
//	}
//	server, err := kms.NewServer(service, kms.ServerConfig{})
//	if err != nil {
//		return err
//	}
//	r := router.New()
//	server.Register(r, "/kms")
//	// POST /kms/keys, POST /kms/keys/:id/activate, POST /kms/encrypt, ...
//
// # net/http usage | net/http 用法
//
//	mux := http.NewServeMux()
//	mux.Handle("/kms/", http.StripPrefix("/kms", server.HTTPHandler("")))
//	// or mount directly: mux.Handle("/kms/", server.HTTPHandler("/kms"))
//
// The HTTP API uses ydx/json and ydx/base64, sets Cache-Control: no-store, and limits request
// bodies to 1 MiB by default. ServerConfig.AllowedOrigins and AllowedHosts bound cross-origin
// callers and Host headers; RequireSameOrigin (implied by CookieAuth) rejects state-changing browser
// requests without a same-origin Origin or Sec-Fetch-Site header, and CSRFCheck adds token
// validation. Leaving these fields empty keeps the permissive pre-existing behavior. | HTTP API 使用
// ydx/json 与 ydx/base64，设置 Cache-Control: no-store，并默认把请求体限制为 1 MiB。
// ServerConfig.AllowedOrigins 与 AllowedHosts 约束跨域调用方与 Host 头；RequireSameOrigin
// （CookieAuth 会隐含开启）拒绝缺少同源 Origin 或 Sec-Fetch-Site 头的状态变更浏览器请求，
// CSRFCheck 可追加令牌校验。上述字段留空时保持原有的宽松行为。
package kms
