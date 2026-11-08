package ldap

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"hash"
	"strconv"
	"strings"

	ydbase64 "github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
)

const (
	// SASLMechanismPlain is the RFC 4616 PLAIN mechanism. | SASLMechanismPlain 是 RFC 4616 PLAIN 机制。
	SASLMechanismPlain = "PLAIN"
	// SASLMechanismExternal is the RFC 4422 EXTERNAL mechanism. | SASLMechanismExternal 是 RFC 4422 EXTERNAL 机制。
	SASLMechanismExternal = "EXTERNAL"
	// SASLMechanismSCRAMSHA256 is the RFC 7677 SCRAM-SHA-256 mechanism. | SASLMechanismSCRAMSHA256 是 RFC 7677 SCRAM-SHA-256 机制。
	SASLMechanismSCRAMSHA256 = "SCRAM-SHA-256"
	// SASLMechanismSCRAMSHA512 is the RFC 7677-style SCRAM-SHA-512 mechanism. | SASLMechanismSCRAMSHA512 是 SCRAM-SHA-512 机制。
	SASLMechanismSCRAMSHA512 = "SCRAM-SHA-512"
)

// SCRAMOptions configures a SCRAM-SHA-256 or SCRAM-SHA-512 bind. | SCRAMOptions
// 配置 SCRAM-SHA-256 或 SCRAM-SHA-512 绑定。
type SCRAMOptions struct {
	// Username is the authentication identity. | Username 是认证身份。
	Username string
	// Password is the authentication secret. | Password 是认证密钥。
	Password string
	// AuthzID optionally requests a different authorization identity. | AuthzID
	// 可选地请求不同的授权身份。
	AuthzID string
	// Mechanism is SCRAM-SHA-256, SCRAM-SHA-512, or a -PLUS variant. Empty selects
	// SCRAM-SHA-256. | Mechanism 是 SCRAM-SHA-256、SCRAM-SHA-512 或 -PLUS 变体。空值选择
	// SCRAM-SHA-256。
	Mechanism string
	// ChannelBinding enables tls-server-end-point channel binding and uses the
	// matching -PLUS mechanism. | ChannelBinding 启用 tls-server-end-point 通道绑定并使用
	// 对应的 -PLUS 机制。
	ChannelBinding bool
}

// BindSASLPlain authenticates with RFC 4616 PLAIN. Empty passwords are rejected
// before any network I/O. When Config.RequireSASLPlainTLS is set, the bind is
// rejected unless the connection is TLS-protected. | BindSASLPlain 使用 RFC 4616
// PLAIN 认证。空口令会在任何网络 I/O 之前被拒绝。启用 Config.RequireSASLPlainTLS 后，
// 除非连接受 TLS 保护，否则绑定会被拒绝。
func (c *Client) BindSASLPlain(ctx context.Context, username, password string) error {
	return c.BindSASLPlainAuthzID(ctx, "", username, password)
}

// BindSASLPlainAuthzID authenticates with RFC 4616 PLAIN and an authorization
// identity. When Config.RequireSASLPlainTLS is set, the bind is rejected unless
// the connection is TLS-protected. | BindSASLPlainAuthzID 使用 RFC 4616 PLAIN 与授权
// 身份认证。启用 Config.RequireSASLPlainTLS 后，除非连接受 TLS 保护，否则绑定会被拒绝。
func (c *Client) BindSASLPlainAuthzID(ctx context.Context, authzID, username, password string) error {
	if password == "" {
		return ErrEmptyPassword
	}
	if username == "" {
		return errs.Detail(ErrSASL, "PLAIN username is empty | PLAIN 用户名为空")
	}
	if strings.IndexByte(authzID, 0) >= 0 || strings.IndexByte(username, 0) >= 0 || strings.IndexByte(password, 0) >= 0 {
		return errs.Detail(ErrSASL, "PLAIN credentials contain NUL | PLAIN 凭据包含 NUL")
	}
	release, err := c.acquire(ctx, false)
	if err != nil {
		return err
	}
	defer release()
	if err := c.performSASLPlainLocked(ctx, authzID, username, password); err != nil {
		c.auth = nil
		return err
	}
	c.auth = &authState{kind: authPlain, authzID: authzID, authcid: username, password: password}
	return nil
}

// BindSASLExternal authenticates with RFC 4422 EXTERNAL over a TLS-protected
// connection. The optional argument is the requested authorization identity. | BindSASLExternal
// 在 TLS 保护的连接上使用 RFC 4422 EXTERNAL 认证。可选参数是请求的授权身份。
func (c *Client) BindSASLExternal(ctx context.Context, authzID ...string) error {
	if len(authzID) > 1 {
		return errs.Detail(ErrInvalidConfig, "EXTERNAL accepts at most one authzID | EXTERNAL 最多接受一个 authzID")
	}
	var identity string
	if len(authzID) == 1 {
		identity = authzID[0]
	}
	if strings.IndexByte(identity, 0) >= 0 {
		return errs.Detail(ErrSASL, "EXTERNAL authzID contains NUL | EXTERNAL authzID 包含 NUL")
	}
	release, err := c.acquire(ctx, false)
	if err != nil {
		return err
	}
	defer release()
	if !c.conn.secure {
		return ErrTLSRequired
	}
	if err := c.performSASLExternalLocked(ctx, identity); err != nil {
		c.auth = nil
		return err
	}
	c.auth = &authState{kind: authExternal, authzID: identity}
	return nil
}

// BindSCRAM authenticates with SCRAM-SHA-256 or SCRAM-SHA-512. | BindSCRAM 使用
// SCRAM-SHA-256 或 SCRAM-SHA-512 认证。
func (c *Client) BindSCRAM(ctx context.Context, options SCRAMOptions) error {
	if options.Username == "" {
		return errs.Detail(ErrSCRAM, "SCRAM username is empty | SCRAM 用户名为空")
	}
	if options.Password == "" {
		return ErrEmptyPassword
	}
	if strings.IndexByte(options.Username, 0) >= 0 || strings.IndexByte(options.Password, 0) >= 0 || strings.IndexByte(options.AuthzID, 0) >= 0 {
		return errs.Detail(ErrSCRAM, "SCRAM credentials contain NUL | SCRAM 凭据包含 NUL")
	}
	if _, _, _, err := scramParameters(options); err != nil {
		return err
	}
	release, err := c.acquire(ctx, false)
	if err != nil {
		return err
	}
	defer release()
	if err := c.performSCRAMLocked(ctx, options); err != nil {
		c.auth = nil
		return err
	}
	c.auth = &authState{kind: authSCRAM, scram: options}
	return nil
}

// BindSCRAM256 authenticates with SCRAM-SHA-256. | BindSCRAM256 使用 SCRAM-SHA-256 认证。
func (c *Client) BindSCRAM256(ctx context.Context, username, password string) error {
	return c.BindSCRAM(ctx, SCRAMOptions{Username: username, Password: password, Mechanism: SASLMechanismSCRAMSHA256})
}

// BindSCRAM512 authenticates with SCRAM-SHA-512. | BindSCRAM512 使用 SCRAM-SHA-512 认证。
func (c *Client) BindSCRAM512(ctx context.Context, username, password string) error {
	return c.BindSCRAM(ctx, SCRAMOptions{Username: username, Password: password, Mechanism: SASLMechanismSCRAMSHA512})
}

// saslBindLocked sends one SASL BindRequest with an empty bind DN. | saslBindLocked
// 发送一条绑定 DN 为空的 SASL BindRequest。
func (c *Client) saslBindLocked(ctx context.Context, mechanism string, credentials []byte) (*BindResponse, error) {
	message, err := c.exchangeLocked(ctx, &BindRequest{
		Version:        3,
		Authentication: SASLAuthentication{Mechanism: mechanism, Credentials: credentials},
	}, nil)
	if err != nil {
		return nil, err
	}
	response, ok := message.Op.(*BindResponse)
	if !ok {
		c.invalidateConnLocked()
		return nil, errs.Detail(ErrUnexpectedResponse, "SASL bind returned %T | SASL 绑定返回 %T", message.Op, message.Op)
	}
	return response, nil
}

// performSASLPlainLocked performs one PLAIN exchange without changing replay
// state. It refuses to send credentials when Config.RequireSASLPlainTLS is set
// and the transport is not TLS-protected, which also covers authentication
// replay after a reconnect. | performSASLPlainLocked 执行一次 PLAIN 交换且不改变重放
// 状态。启用 Config.RequireSASLPlainTLS 且传输未受 TLS 保护时，它拒绝发送凭据；重连后的认证
// 重放同样受此保护。
func (c *Client) performSASLPlainLocked(ctx context.Context, authzID, username, password string) error {
	if c.cfg.RequireSASLPlainTLS && (c.conn == nil || !c.conn.secure) {
		return ErrTLSRequired
	}
	credentials := make([]byte, 0, len(authzID)+len(username)+len(password)+2)
	credentials = append(credentials, authzID...)
	credentials = append(credentials, 0)
	credentials = append(credentials, username...)
	credentials = append(credentials, 0)
	credentials = append(credentials, password...)
	response, err := c.saslBindLocked(ctx, SASLMechanismPlain, credentials)
	if err != nil {
		return err
	}
	if response.Result.Code != ResultSuccess {
		return newResultError("SASL PLAIN bind", response.Result)
	}
	return nil
}

// performSASLExternalLocked performs EXTERNAL and allows one server challenge.
// | performSASLExternalLocked 执行 EXTERNAL 并允许一次服务端挑战。
func (c *Client) performSASLExternalLocked(ctx context.Context, authzID string) error {
	credentials := []byte(authzID)
	for attempt := 0; attempt < 2; attempt++ {
		response, err := c.saslBindLocked(ctx, SASLMechanismExternal, credentials)
		if err != nil {
			return err
		}
		if response.Result.Code == ResultSuccess {
			return nil
		}
		if response.Result.Code != ResultSASLBindInProgress || attempt == 1 {
			return newResultError("SASL EXTERNAL bind", response.Result)
		}
	}
	return errs.Detail(ErrSASL, "EXTERNAL exchange did not complete | EXTERNAL 交换未完成")
}

// scramParameters validates options and selects the mechanism and hash. | scramParameters
// 校验选项并选择机制与哈希。
func scramParameters(options SCRAMOptions) (mechanism string, newHash func() hash.Hash, hashSize int, err error) {
	name := options.Mechanism
	if name == "" {
		name = SASLMechanismSCRAMSHA256
	}
	upper := strings.ToUpper(name)
	plus := strings.HasSuffix(upper, "-PLUS")
	base := strings.TrimSuffix(upper, "-PLUS")
	switch base {
	case SASLMechanismSCRAMSHA256:
		newHash = sha256.New
		hashSize = sha256.Size
	case SASLMechanismSCRAMSHA512:
		newHash = sha512.New
		hashSize = sha512.Size
	default:
		return "", nil, 0, errs.Detail(ErrSCRAM, "unsupported SCRAM mechanism %q | 不支持的 SCRAM 机制 %q", name, name)
	}
	if options.ChannelBinding && !plus {
		upper += "-PLUS"
	}
	if plus && !options.ChannelBinding {
		return "", nil, 0, errs.Detail(ErrSCRAM, "SCRAM -PLUS requires channel binding | SCRAM -PLUS 需要通道绑定")
	}
	return upper, newHash, hashSize, nil
}

// performSCRAMLocked performs a complete SCRAM exchange without changing replay
// state. | performSCRAMLocked 执行完整 SCRAM 交换且不改变重放状态。
func (c *Client) performSCRAMLocked(ctx context.Context, options SCRAMOptions) error {
	mechanism, newHash, hashSize, err := scramParameters(options)
	if err != nil {
		return err
	}
	bindingData, gs2Header, err := c.scramChannelBinding(options)
	if err != nil {
		return err
	}
	nonceBytes := make([]byte, 24)
	if _, err := rand.Read(nonceBytes); err != nil {
		return errs.WrapDetail(err, ErrSCRAM, "cannot generate SCRAM nonce | 无法生成 SCRAM 随机数")
	}
	clientNonce := ydbase64.RawStdEncoding.EncodeToString(nonceBytes)
	clientFirstBare := "n=" + escapeSCRAMName(options.Username) + ",r=" + clientNonce
	clientFirst := gs2Header + clientFirstBare
	response, err := c.saslBindLocked(ctx, mechanism, []byte(clientFirst))
	if err != nil {
		return err
	}
	if response.Result.Code != ResultSASLBindInProgress {
		if response.Result.Code == ResultSuccess {
			return errs.Detail(ErrSCRAM, "server completed SCRAM without a challenge | 服务端未挑战即完成 SCRAM")
		}
		return newResultError("SCRAM bind", response.Result)
	}
	serverFirst := string(response.ServerSASLCredentials)
	if serverFirst == "" {
		return errs.Detail(ErrSCRAM, "server-first message is empty | server-first 消息为空")
	}
	serverNonce, salt, iterations, err := parseSCRAMServerFirst(serverFirst, clientNonce)
	if err != nil {
		return err
	}
	saltedPassword, err := pbkdf2Key(newHash, options.Password, salt, iterations, hashSize)
	if err != nil {
		return errs.WrapDetail(err, ErrSCRAM, "SCRAM key derivation failed | SCRAM 密钥派生失败")
	}
	clientKey := hmacBytes(newHash, saltedPassword, []byte("Client Key"))
	storedKey := hashBytes(newHash, clientKey)
	cbindInput := make([]byte, 0, len(gs2Header)+len(bindingData))
	cbindInput = append(cbindInput, gs2Header...)
	cbindInput = append(cbindInput, bindingData...)
	cbindBase64 := ydbase64.StdEncoding.EncodeToString(cbindInput)
	withoutProof := "c=" + cbindBase64 + ",r=" + serverNonce
	authMessage := clientFirstBare + "," + serverFirst + "," + withoutProof
	clientSignature := hmacBytes(newHash, storedKey, []byte(authMessage))
	proof := make([]byte, len(clientKey))
	for i := range clientKey {
		proof[i] = clientKey[i] ^ clientSignature[i]
	}
	serverKey := hmacBytes(newHash, saltedPassword, []byte("Server Key"))
	expectedServerSignature := hmacBytes(newHash, serverKey, []byte(authMessage))
	final := withoutProof + ",p=" + ydbase64.StdEncoding.EncodeToString(proof)
	response, err = c.saslBindLocked(ctx, mechanism, []byte(final))
	if err != nil {
		return err
	}
	if response.Result.Code != ResultSuccess {
		return newResultError("SCRAM bind", response.Result)
	}
	serverFinal := string(response.ServerSASLCredentials)
	if serverFinal == "" {
		return errs.Detail(ErrSCRAM, "server-final message is empty | server-final 消息为空")
	}
	serverSignature, err := parseSCRAMServerFinal(serverFinal)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(serverSignature, expectedServerSignature) != 1 {
		return errs.Detail(ErrSCRAM, "server signature verification failed | 服务端签名校验失败")
	}
	return nil
}

// scramChannelBinding computes tls-server-end-point data and the GS2 header. | scramChannelBinding
// 计算 tls-server-end-point 数据与 GS2 头。
func (c *Client) scramChannelBinding(options SCRAMOptions) ([]byte, string, error) {
	if !options.ChannelBinding {
		header := "n,"
		if options.AuthzID != "" {
			header += "a=" + escapeSCRAMName(options.AuthzID) + ","
		} else {
			header += ","
		}
		return nil, header, nil
	}
	if c.conn == nil || !c.conn.secure {
		return nil, "", ErrTLSRequired
	}
	certificates := c.conn.tlsState.PeerCertificates
	if len(certificates) == 0 {
		return nil, "", errs.Detail(ErrSASL, "TLS connection has no peer certificate | TLS 连接没有对端证书")
	}
	bindingData, err := tlsServerEndPoint(certificates[0])
	if err != nil {
		return nil, "", err
	}
	gs2Header := "p=tls-server-end-point,"
	if options.AuthzID != "" {
		gs2Header += "a=" + escapeSCRAMName(options.AuthzID) + ","
	} else {
		gs2Header += ","
	}
	return bindingData, gs2Header, nil
}

// tlsServerEndPoint hashes a certificate for RFC 5929 tls-server-end-point
// channel binding, upgrading MD5 and SHA-1 signatures to SHA-256. | tlsServerEndPoint
// 为 RFC 5929 tls-server-end-point 通道绑定计算证书哈希，并把 MD5 与 SHA-1 签名升级为 SHA-256。
func tlsServerEndPoint(certificate *x509.Certificate) ([]byte, error) {
	if certificate == nil || len(certificate.Raw) == 0 {
		return nil, errs.Detail(ErrSASL, "peer certificate is empty | 对端证书为空")
	}
	var algorithm crypto.Hash
	switch certificate.SignatureAlgorithm {
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384:
		algorithm = crypto.SHA384
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
		algorithm = crypto.SHA512
	default:
		algorithm = crypto.SHA256
	}
	if !algorithm.Available() {
		algorithm = crypto.SHA256
	}
	hasher := algorithm.New()
	_, _ = hasher.Write(certificate.Raw)
	return hasher.Sum(nil), nil
}

// parseSCRAMServerFirst parses r, s and i, validates the nonce, and rejects
// mandatory extensions the client cannot honor. | parseSCRAMServerFirst 解析 r、s 与
// i，校验随机数，并拒绝客户端无法满足的强制扩展。
func parseSCRAMServerFirst(message, clientNonce string) (string, []byte, int, error) {
	values := make(map[string]string)
	for _, field := range strings.Split(message, ",") {
		if len(field) < 2 || field[1] != '=' {
			return "", nil, 0, errs.Detail(ErrSCRAM, "malformed server-first field | server-first 字段格式错误")
		}
		key := field[:1]
		if key == "m" {
			return "", nil, 0, errs.Detail(ErrSCRAM, "unsupported mandatory SCRAM extension | 不支持的 SCRAM 强制扩展")
		}
		if _, duplicate := values[key]; duplicate {
			return "", nil, 0, errs.Detail(ErrSCRAM, "duplicate server-first attribute %q | server-first 属性 %q 重复", key, key)
		}
		values[key] = field[2:]
	}
	serverNonce := values["r"]
	if !strings.HasPrefix(serverNonce, clientNonce) || len(serverNonce) <= len(clientNonce) {
		return "", nil, 0, errs.Detail(ErrSCRAM, "server nonce does not extend client nonce | 服务端随机数未扩展客户端随机数")
	}
	saltText := values["s"]
	if saltText == "" {
		return "", nil, 0, errs.Detail(ErrSCRAM, "server-first salt is empty | server-first 盐为空")
	}
	salt, err := ydbase64.StdEncoding.DecodeString(saltText)
	if err != nil {
		return "", nil, 0, errs.WrapDetail(err, ErrSCRAM, "invalid SCRAM salt | SCRAM 盐非法")
	}
	iterations, err := strconv.Atoi(values["i"])
	if err != nil || iterations <= 0 || iterations > 10_000_000 {
		return "", nil, 0, errs.Detail(ErrSCRAM, "invalid SCRAM iteration count | SCRAM 迭代次数非法")
	}
	return serverNonce, salt, iterations, nil
}

// parseSCRAMServerFinal parses a v or e server-final message. | parseSCRAMServerFinal
// 解析 v 或 e 的 server-final 消息。
func parseSCRAMServerFinal(message string) ([]byte, error) {
	field := message
	if index := strings.IndexByte(field, ','); index >= 0 {
		field = field[:index]
	}
	if len(field) >= 2 && field[:2] == "e=" {
		return nil, errs.Detail(ErrSCRAM, "server rejected SCRAM authentication: %s | 服务端拒绝 SCRAM 认证：%s", field[2:], field[2:])
	}
	if len(field) < 2 || field[:2] != "v=" {
		return nil, errs.Detail(ErrSCRAM, "server-final message lacks v | server-final 消息缺少 v")
	}
	signature, err := ydbase64.StdEncoding.DecodeString(field[2:])
	if err != nil {
		return nil, errs.WrapDetail(err, ErrSCRAM, "invalid server signature encoding | 服务端签名编码非法")
	}
	return signature, nil
}

// escapeSCRAMName applies the RFC 5802 '=' and ',' escaping. | escapeSCRAMName 应用
// RFC 5802 的 '=' 与 ',' 转义。
func escapeSCRAMName(value string) string {
	value = strings.ReplaceAll(value, "=", "=3D")
	return strings.ReplaceAll(value, ",", "=2C")
}

// hashBytes returns newHash(data). | hashBytes 返回 newHash(data)。
func hashBytes(newHash func() hash.Hash, data []byte) []byte {
	hasher := newHash()
	_, _ = hasher.Write(data)
	return hasher.Sum(nil)
}

// hmacBytes computes HMAC in the selected hash. | hmacBytes 使用所选哈希计算 HMAC。
func hmacBytes(newHash func() hash.Hash, key, data []byte) []byte {
	mac := hmac.New(newHash, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

// pbkdf2Key derives a SCRAM salted password. | pbkdf2Key 派生 SCRAM 加盐口令。
func pbkdf2Key(newHash func() hash.Hash, password string, salt []byte, iterations, keyLength int) ([]byte, error) {
	return pbkdf2.Key(newHash, password, salt, iterations, keyLength)
}
