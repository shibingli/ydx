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
// bodies to 1 MiB by default. | HTTP API 使用 ydx/json 与 ydx/base64，设置 Cache-Control: no-store，
// 并默认把请求体限制为 1 MiB。
package kms
