package kerberos

import (
	"time"

	"github.com/shibingli/ydx/errs"
)

// Protocol constants assigned by RFC 4120 through RFC 4757. | RFC 4120 至 RFC 4757
// 分配的协议常量。
const (
	// PVNO is the Kerberos protocol version. | PVNO 是 Kerberos 协议版本。
	PVNO = 5

	// MessageTypeASReq is AS-REQ. | MessageTypeASReq 是 AS-REQ。
	MessageTypeASReq = 10
	// MessageTypeASRep is AS-REP. | MessageTypeASRep 是 AS-REP。
	MessageTypeASRep = 11
	// MessageTypeTGSReq is TGS-REQ. | MessageTypeTGSReq 是 TGS-REQ。
	MessageTypeTGSReq = 12
	// MessageTypeTGSRep is TGS-REP. | MessageTypeTGSRep 是 TGS-REP。
	MessageTypeTGSRep = 13
	// MessageTypeAPReq is AP-REQ. | MessageTypeAPReq 是 AP-REQ。
	MessageTypeAPReq = 14
	// MessageTypeAPRep is AP-REP. | MessageTypeAPRep 是 AP-REP。
	MessageTypeAPRep = 15
	// MessageTypeKRBError is KRB-ERROR. | MessageTypeKRBError 是 KRB-ERROR。
	MessageTypeKRBError = 30

	// ETypeAES128CTS HMAC SHA1 96 is aes128-cts-hmac-sha1-96 (17). | ETypeAES128CTS 是
	// aes128-cts-hmac-sha1-96（17）。
	ETypeAES128CTS = 17
	// ETypeAES256CTS HMAC SHA1 96 is aes256-cts-hmac-sha1-96 (18). | ETypeAES256CTS 是
	// aes256-cts-hmac-sha1-96（18）。
	ETypeAES256CTS = 18
	// ETypeRC4HMAC is rc4-hmac (23). | ETypeRC4HMAC 是 rc4-hmac（23）。
	ETypeRC4HMAC = 23

	// ChecksumTypeHMACSHA1AES128 is hmac-sha1-96-aes128 (15). | ChecksumTypeHMACSHA1AES128
	// 是 hmac-sha1-96-aes128（15）。
	ChecksumTypeHMACSHA1AES128 = 15
	// ChecksumTypeHMACSHA1AES256 is hmac-sha1-96-aes256 (16). | ChecksumTypeHMACSHA1AES256
	// 是 hmac-sha1-96-aes256（16）。
	ChecksumTypeHMACSHA1AES256 = 16
	// ChecksumTypeHMACMD5 is the rc4-hmac keyed checksum (-138). | ChecksumTypeHMACMD5 是
	// rc4-hmac 密钥校验和（-138）。
	ChecksumTypeHMACMD5 = -138
	// ChecksumTypeGSSAPI is the RFC 4121 authenticator checksum (0x8003). | ChecksumTypeGSSAPI
	// 是 RFC 4121 认证器校验和（0x8003）。
	ChecksumTypeGSSAPI = 0x8003

	// PADataTypeTGSReq is PA-TGS-REQ (1). | PADataTypeTGSReq 是 PA-TGS-REQ（1）。
	PADataTypeTGSReq = 1
	// PADataTypeEncTimestamp is PA-ENC-TIMESTAMP (2). | PADataTypeEncTimestamp 是 PA-ENC-TIMESTAMP（2）。
	PADataTypeEncTimestamp = 2
	// PADataTypePWSSalt is PA-PW-SALT (3). | PADataTypePWSSalt 是 PA-PW-SALT（3）。
	PADataTypePWSSalt = 3
	// PADataTypeETypeInfo is PA-ETYPE-INFO (11). | PADataTypeETypeInfo 是 PA-ETYPE-INFO（11）。
	PADataTypeETypeInfo = 11
	// PADataTypeETypeInfo2 is PA-ETYPE-INFO2 (19). | PADataTypeETypeInfo2 是 PA-ETYPE-INFO2（19）。
	PADataTypeETypeInfo2 = 19

	// NameTypeUnknown is KRB_NT_UNKNOWN. | NameTypeUnknown 是 KRB_NT_UNKNOWN。
	NameTypeUnknown = 0
	// NameTypePrincipal is KRB_NT_PRINCIPAL. | NameTypePrincipal 是 KRB_NT_PRINCIPAL。
	NameTypePrincipal = 1
	// NameTypeSRVInst is KRB_NT_SRV_INST. | NameTypeSRVInst 是 KRB_NT_SRV_INST。
	NameTypeSRVInst = 2
	// NameTypeSRVHST is KRB_NT_SRV_HST. | NameTypeSRVHST 是 KRB_NT_SRV_HST。
	NameTypeSRVHST = 3
	// NameTypeSRVXHST is KRB_NT_SRV_XHST. | NameTypeSRVXHST 是 KRB_NT_SRV_XHST。
	NameTypeSRVXHST = 4
	// NameTypeEnterprise is KRB_NT_ENTERPRISE. | NameTypeEnterprise 是 KRB_NT_ENTERPRISE。
	NameTypeEnterprise = 10
)

// KDC options, expressed as KerberosFlags bit masks. | KDC 选项，以 KerberosFlags 位掩码表示。
const (
	// KDCOptionForwardable requests a forwardable ticket. | KDCOptionForwardable 请求可转发票据。
	KDCOptionForwardable KDCOptions = 1 << 1
	// KDCOptionForwarded marks a forwarded ticket. | KDCOptionForwarded 标记已转发票据。
	KDCOptionForwarded KDCOptions = 1 << 2
	// KDCOptionProxiable requests a proxiable ticket. | KDCOptionProxiable 请求可代理票据。
	KDCOptionProxiable KDCOptions = 1 << 3
	// KDCOptionProxy marks a proxy ticket. | KDCOptionProxy 标记代理票据。
	KDCOptionProxy KDCOptions = 1 << 4
	// KDCOptionAllowPostdate permits a postdated ticket. | KDCOptionAllowPostdate 允许后日期票据。
	KDCOptionAllowPostdate KDCOptions = 1 << 5
	// KDCOptionPostdated requests a postdated ticket. | KDCOptionPostdated 请求后日期票据。
	KDCOptionPostdated KDCOptions = 1 << 6
	// KDCOptionRenewable requests a renewable ticket. | KDCOptionRenewable 请求可续期票据。
	KDCOptionRenewable KDCOptions = 1 << 8
	// KDCOptionDisableTransitedCheck disables transited-policy checking. | KDCOptionDisableTransitedCheck 关闭域间路径检查。
	KDCOptionDisableTransitedCheck KDCOptions = 1 << 26
	// KDCOptionRenewableOK accepts a renewable ticket with otherwise insufficient life. | KDCOptionRenewableOK 接受寿命不足但可续期的票据。
	KDCOptionRenewableOK KDCOptions = 1 << 27
	// KDCOptionEncTicketInSKey requests user-to-user encryption. | KDCOptionEncTicketInSKey 请求 user-to-user 加密。
	KDCOptionEncTicketInSKey KDCOptions = 1 << 28
	// KDCOptionRenew renews an existing ticket. | KDCOptionRenew 续期现有票据。
	KDCOptionRenew KDCOptions = 1 << 30
	// KDCOptionValidate validates a postdated ticket. | KDCOptionValidate 校验后日期票据。
	KDCOptionValidate KDCOptions = 1 << 31
)

// Ticket flags, expressed as KerberosFlags bit masks. | 票据标志，以 KerberosFlags 位掩码表示。
const (
	// TicketFlagForwardable marks a forwardable ticket. | TicketFlagForwardable 标记可转发票据。
	TicketFlagForwardable TicketFlags = 1 << 1
	// TicketFlagForwarded marks a forwarded ticket. | TicketFlagForwarded 标记已转发票据。
	TicketFlagForwarded TicketFlags = 1 << 2
	// TicketFlagProxiable marks a proxiable ticket. | TicketFlagProxiable 标记可代理票据。
	TicketFlagProxiable TicketFlags = 1 << 3
	// TicketFlagProxy marks a proxy ticket. | TicketFlagProxy 标记代理票据。
	TicketFlagProxy TicketFlags = 1 << 4
	// TicketFlagMayPostdate marks a ticket that may be postdated. | TicketFlagMayPostdate 标记可后日期票据。
	TicketFlagMayPostdate TicketFlags = 1 << 5
	// TicketFlagPostdated marks a postdated ticket. | TicketFlagPostdated 标记后日期票据。
	TicketFlagPostdated TicketFlags = 1 << 6
	// TicketFlagInvalid marks an invalid ticket. | TicketFlagInvalid 标记无效票据。
	TicketFlagInvalid TicketFlags = 1 << 7
	// TicketFlagRenewable marks a renewable ticket. | TicketFlagRenewable 标记可续期票据。
	TicketFlagRenewable TicketFlags = 1 << 8
	// TicketFlagInitial marks a ticket obtained directly by AS exchange. | TicketFlagInitial 标记由 AS 交换直接获得的票据。
	TicketFlagInitial TicketFlags = 1 << 9
	// TicketFlagPreAuthent marks a pre-authenticated ticket. | TicketFlagPreAuthent 标记已预认证票据。
	TicketFlagPreAuthent TicketFlags = 1 << 10
	// TicketFlagHWAuthent marks a hardware-authenticated ticket. | TicketFlagHWAuthent 标记硬件认证票据。
	TicketFlagHWAuthent TicketFlags = 1 << 11
	// TicketFlagTransitedPolicyChecked marks a checked transited path. | TicketFlagTransitedPolicyChecked 标记已检查域间路径。
	TicketFlagTransitedPolicyChecked TicketFlags = 1 << 12
	// TicketFlagOKAsDelegate marks a ticket suitable for delegation. | TicketFlagOKAsDelegate 标记可用于委派的票据。
	TicketFlagOKAsDelegate TicketFlags = 1 << 13
)

// AP options, expressed as KerberosFlags bit masks. | AP 选项，以 KerberosFlags 位掩码表示。
const (
	// APOptionUseSessionKey requests user-to-user authentication. | APOptionUseSessionKey 请求 user-to-user 认证。
	APOptionUseSessionKey APOptions = 1 << 1
	// APOptionMutualRequired requires an AP-REP response. | APOptionMutualRequired 要求 AP-REP 响应。
	APOptionMutualRequired APOptions = 1 << 2
)

// KDCOptions is the KDCOptions KerberosFlags bitmap. | KDCOptions 是 KDCOptions
// KerberosFlags 位图。
type KDCOptions uint32

// Has reports whether every bit in flag is set. | Has 报告 flag 中的每个位是否都已设置。
func (o KDCOptions) Has(flag KDCOptions) bool { return o&flag == flag }

// Set turns on flag. | Set 打开 flag。
func (o *KDCOptions) Set(flag KDCOptions) {
	if o != nil {
		*o |= flag
	}
}

// Clear turns off flag. | Clear 关闭 flag。
func (o *KDCOptions) Clear(flag KDCOptions) {
	if o != nil {
		*o &^= flag
	}
}

// TicketFlags is the TicketFlags KerberosFlags bitmap. | TicketFlags 是 TicketFlags
// KerberosFlags 位图。
type TicketFlags uint32

// Has reports whether every bit in flag is set. | Has 报告 flag 中的每个位是否都已设置。
func (f TicketFlags) Has(flag TicketFlags) bool { return f&flag == flag }

// Set turns on flag. | Set 打开 flag。
func (f *TicketFlags) Set(flag TicketFlags) {
	if f != nil {
		*f |= flag
	}
}

// Clear turns off flag. | Clear 关闭 flag。
func (f *TicketFlags) Clear(flag TicketFlags) {
	if f != nil {
		*f &^= flag
	}
}

// APOptions is the APOptions KerberosFlags bitmap. | APOptions 是 APOptions
// KerberosFlags 位图。
type APOptions uint32

// Has reports whether every bit in flag is set. | Has 报告 flag 中的每个位是否都已设置。
func (o APOptions) Has(flag APOptions) bool { return o&flag == flag }

// Set turns on flag. | Set 打开 flag。
func (o *APOptions) Set(flag APOptions) {
	if o != nil {
		*o |= flag
	}
}

// Clear turns off flag. | Clear 关闭 flag。
func (o *APOptions) Clear(flag APOptions) {
	if o != nil {
		*o &^= flag
	}
}

// KerberosTime is an RFC 4120 KerberosTime. The zero value means "field absent"
// in optional positions. | KerberosTime 是 RFC 4120 KerberosTime。零值在可选位置表示
// “字段缺失”。
type KerberosTime struct {
	time.Time
}

// NewKerberosTime converts a time.Time to a KerberosTime truncated to whole
// seconds in UTC. | NewKerberosTime 把 time.Time 转换为 UTC 整秒的 KerberosTime。
func NewKerberosTime(value time.Time) KerberosTime {
	return KerberosTime{Time: value.UTC().Truncate(time.Second)}
}

// IsZero reports whether the value is absent. | IsZero 报告值是否缺失。
func (t KerberosTime) IsZero() bool { return t.Time.IsZero() }

// UTC returns the value in UTC. | UTC 返回 UTC 时间。
func (t KerberosTime) UTC() KerberosTime { return KerberosTime{Time: t.Time.UTC()} }

// UnmarshalText parses RFC 4120 GeneralizedTime text. | UnmarshalText 解析 RFC 4120
// GeneralizedTime 文本。
func (t *KerberosTime) UnmarshalText(text []byte) error {
	if t == nil {
		return errs.Detail(ErrTime, "nil KerberosTime receiver | KerberosTime 接收者为空")
	}
	parsed, err := readGeneralizedTime(text)
	if err != nil {
		return err
	}
	t.Time = parsed
	return nil
}

// MarshalText renders RFC 4120 GeneralizedTime text. | MarshalText 渲染 RFC 4120
// GeneralizedTime 文本。
func (t KerberosTime) MarshalText() ([]byte, error) {
	if t.IsZero() {
		return []byte{}, nil
	}
	return []byte(t.UTC().Format("20060102150405Z")), nil
}

// PrincipalName is an RFC 4120 PrincipalName. | PrincipalName 是 RFC 4120 PrincipalName。
type PrincipalName struct {
	// NameType is the principal name type. | NameType 是主体名称类型。
	NameType int32
	// NameString holds the principal components. | NameString 保存主体各组成部分。
	NameString []string
}

// NewPrincipalName builds a principal from its name type and components. | NewPrincipalName
// 用名称类型与组成部分构建主体。
func NewPrincipalName(nameType int32, components ...string) PrincipalName {
	return PrincipalName{NameType: nameType, NameString: append([]string(nil), components...)}
}

// String renders the components joined by a slash without a realm. | String 用斜杠连接
// 各组成部分，不包含 realm。
func (p PrincipalName) String() string {
	result := ""
	for i, component := range p.NameString {
		if i > 0 {
			result += "/"
		}
		result += component
	}
	return result
}

// Equal reports whether two principals have the same type and components. | Equal 报告
// 两个主体的类型与组成部分是否相同。
func (p PrincipalName) Equal(other PrincipalName) bool {
	if p.NameType != other.NameType || len(p.NameString) != len(other.NameString) {
		return false
	}
	for i := range p.NameString {
		if p.NameString[i] != other.NameString[i] {
			return false
		}
	}
	return true
}

// EncryptionKey is an RFC 4120 EncryptionKey. | EncryptionKey 是 RFC 4120 EncryptionKey。
type EncryptionKey struct {
	// KeyType is the encryption type number. | KeyType 是加密类型编号。
	KeyType int32
	// KeyValue is the protocol key. | KeyValue 是协议密钥。
	KeyValue []byte
}

// EncryptedData is an RFC 4120 EncryptedData. | EncryptedData 是 RFC 4120 EncryptedData。
type EncryptedData struct {
	// EType is the encryption type number. | EType 是加密类型编号。
	EType int32
	// KVNO is the key version number; zero means the field is absent. | KVNO 是密钥版本号；
	// 零表示字段缺失。
	KVNO int32
	// Cipher is the ciphertext. | Cipher 是密文。
	Cipher []byte
}

// Checksum is an RFC 4120 Checksum. | Checksum 是 RFC 4120 Checksum。
type Checksum struct {
	// CksumType is the checksum type number. | CksumType 是校验和类型编号。
	CksumType int32
	// Checksum holds the checksum octets. | Checksum 保存校验和字节。
	Checksum []byte
}

// HostAddress is an RFC 4120 HostAddress. | HostAddress 是 RFC 4120 HostAddress。
type HostAddress struct {
	// AddrType is the address type, for example 2 for IPv4. | AddrType 是地址类型，例如
	// IPv4 为 2。
	AddrType int32
	// Address holds the address octets. | Address 保存地址字节。
	Address []byte
}

// Ticket is an RFC 4120 Ticket. | Ticket 是 RFC 4120 Ticket。
type Ticket struct {
	// TktVNO is the ticket format version. | TktVNO 是票据格式版本。
	TktVNO int32
	// Realm is the server realm. | Realm 是服务端 realm。
	Realm string
	// SName is the server principal. | SName 是服务端主体。
	SName PrincipalName
	// EncPart is the encrypted EncTicketPart. | EncPart 是加密的 EncTicketPart。
	EncPart EncryptedData
}

// Authenticator is an RFC 4120 Authenticator. | Authenticator 是 RFC 4120 Authenticator。
type Authenticator struct {
	// AuthenticatorVNO is the authenticator format version. | AuthenticatorVNO 是认证器格式版本。
	AuthenticatorVNO int32
	// CRealm is the client realm. | CRealm 是客户端 realm。
	CRealm string
	// CName is the client principal. | CName 是客户端主体。
	CName PrincipalName
	// Cksum is the optional authenticator checksum. | Cksum 是可选认证器校验和。
	Cksum *Checksum
	// CUSec is the client microsecond field. | CUSec 是客户端微秒字段。
	CUSec int32
	// CTime is the client time. | CTime 是客户端时间。
	CTime KerberosTime
	// SubKey is the optional authenticator subkey. | SubKey 是可选认证器子密钥。
	SubKey *EncryptionKey
	// SeqNumber is the optional initial sequence number. | SeqNumber 是可选初始序列号。
	SeqNumber *uint32
	// AuthorizationData is the optional typed authorization data. | AuthorizationData 是
	// 可选带类型的授权数据。
	AuthorizationData []TypedData
}

// TransitedEncoding is an RFC 4120 TransitedEncoding. | TransitedEncoding 是 RFC 4120
// TransitedEncoding。
type TransitedEncoding struct {
	// TrType is the transited encoding type. | TrType 是域间路径编码类型。
	TrType int32
	// Contents holds the encoded transited realms. | Contents 保存编码后的域间 realm。
	Contents []byte
}

// TypedData is one RFC 4120 AuthorizationData element. | TypedData 是一个 RFC 4120
// AuthorizationData 元素。
type TypedData struct {
	// DataType is the authorization data type. | DataType 是授权数据类型。
	DataType int32
	// DataValue holds the authorization data octets. | DataValue 保存授权数据字节。
	DataValue []byte
}

// EncTicketPart is the decrypted body of a Ticket. | EncTicketPart 是 Ticket 解密后的主体。
type EncTicketPart struct {
	// Flags are the ticket flags. | Flags 是票据标志。
	Flags TicketFlags
	// Key is the session key. | Key 是会话密钥。
	Key EncryptionKey
	// CRealm is the client realm. | CRealm 是客户端 realm。
	CRealm string
	// CName is the client principal. | CName 是客户端主体。
	CName PrincipalName
	// Transited records the transited realms. | Transited 记录经过的 realm。
	Transited TransitedEncoding
	// AuthTime is the authentication time. | AuthTime 是认证时间。
	AuthTime KerberosTime
	// StartTime is the optional start time. | StartTime 是可选生效时间。
	StartTime *KerberosTime
	// EndTime is the expiry time. | EndTime 是过期时间。
	EndTime KerberosTime
	// RenewTill is the optional renewal deadline. | RenewTill 是可选续期期限。
	RenewTill *KerberosTime
	// CAddr is the optional client address list. | CAddr 是可选客户端地址列表。
	CAddr []HostAddress
	// AuthorizationData is the optional authorization data. | AuthorizationData 是可选授权数据。
	AuthorizationData []TypedData
}

// LastReq is one RFC 4120 LastReq element. | LastReq 是一个 RFC 4120 LastReq 元素。
type LastReq struct {
	// LRType is the last-request type. | LRType 是最后请求类型。
	LRType int32
	// LRValue is the last-request time. | LRValue 是最后请求时间。
	LRValue KerberosTime
}

// EncKDCRepPart is the decrypted body of an AS-REP or TGS-REP. | EncKDCRepPart 是
// AS-REP 或 TGS-REP 解密后的主体。
type EncKDCRepPart struct {
	// Key is the session key for the returned ticket. | Key 是返回票据的会话密钥。
	Key EncryptionKey
	// LastReq lists the last-request records. | LastReq 列出最后请求记录。
	LastReq []LastReq
	// Nonce echoes the request nonce. | Nonce 回显请求 nonce。
	Nonce uint32
	// KeyExpiration is the optional key expiry time. | KeyExpiration 是可选密钥过期时间。
	KeyExpiration *KerberosTime
	// Flags are the ticket flags. | Flags 是票据标志。
	Flags TicketFlags
	// AuthTime is the authentication time. | AuthTime 是认证时间。
	AuthTime KerberosTime
	// StartTime is the optional start time. | StartTime 是可选生效时间。
	StartTime *KerberosTime
	// EndTime is the expiry time. | EndTime 是过期时间。
	EndTime KerberosTime
	// RenewTill is the optional renewal deadline. | RenewTill 是可选续期期限。
	RenewTill *KerberosTime
	// SRealm is the server realm. | SRealm 是服务端 realm。
	SRealm string
	// SName is the server principal. | SName 是服务端主体。
	SName PrincipalName
	// CAddr is the optional client address list. | CAddr 是可选客户端地址列表。
	CAddr []HostAddress
}

// EncAPRepPart is the decrypted body of an AP-REP. | EncAPRepPart 是 AP-REP 解密后的主体。
type EncAPRepPart struct {
	// CTime echoes the client time from the authenticator. | CTime 回显认证器中的客户端时间。
	CTime KerberosTime
	// CUSec echoes the client microsecond field. | CUSec 回显客户端微秒字段。
	CUSec int32
	// SubKey is the optional acceptor subkey. | SubKey 是可选接受方子密钥。
	SubKey *EncryptionKey
	// SeqNumber is the optional acceptor sequence number. | SeqNumber 是可选接受方序列号。
	SeqNumber *uint32
}

// PAData is one RFC 4120 PA-DATA element. | PAData 是一个 RFC 4120 PA-DATA 元素。
type PAData struct {
	// PADataType is the pre-authentication data type. | PADataType 是预认证数据类型。
	PADataType int32
	// PADataValue is the encoded pre-authentication value. | PADataValue 是编码后的预认证值。
	PADataValue []byte
}

// PAEncTSEnc is the PA-ENC-TIMESTAMP plaintext. | PAEncTSEnc 是 PA-ENC-TIMESTAMP 明文。
type PAEncTSEnc struct {
	// PATimestamp is the client timestamp. | PATimestamp 是客户端时间戳。
	PATimestamp KerberosTime
	// PAUSec is the optional microsecond field. | PAUSec 是可选微秒字段。
	PAUSec *int32
}

// ETypeInfo2Entry is one PA-ETYPE-INFO2 entry. | ETypeInfo2Entry 是一个 PA-ETYPE-INFO2 条目。
type ETypeInfo2Entry struct {
	// EType is the encryption type number. | EType 是加密类型编号。
	EType int32
	// Salt is the optional string-to-key salt. | Salt 是可选 string-to-key 盐。
	Salt *string
	// S2KParams is the optional string-to-key parameter block. | S2KParams 是可选
	// string-to-key 参数块。
	S2KParams []byte
}

// appendPrincipalName encodes a PrincipalName. | appendPrincipalName 编码 PrincipalName。
func appendPrincipalName(dst []byte, principal PrincipalName) []byte {
	components := make([][]byte, 0, len(principal.NameString))
	for _, component := range principal.NameString {
		components = append(components, derAppendGeneralString(nil, component))
	}
	name := derAppendSequence(nil, components...)
	return derAppendSequence(dst,
		appendIntContext(nil, 0, principal.NameType),
		derAppendContext(nil, 1, name),
	)
}

// parsePrincipalName decodes a PrincipalName from an explicit context field. | parsePrincipalName
// 从显式上下文字段解码 PrincipalName。
func parsePrincipalName(content []byte) (PrincipalName, error) {
	body, err := sequenceContent(content)
	if err != nil {
		return PrincipalName{}, err
	}
	var principal PrincipalName
	seenType, seenName := false, false
	r := newDERReader(body)
	for r.remaining() > 0 {
		tag, value, err := r.next()
		if err != nil {
			return principal, err
		}
		switch tag {
		case 0xA0:
			if seenType {
				return principal, errASN1("duplicate principal name type | 重复的主体名称类型")
			}
			number, err := readContextInt32(value)
			if err != nil {
				return principal, err
			}
			principal.NameType = number
			seenType = true
		case 0xA1:
			if seenName {
				return principal, errASN1("duplicate principal name components | 重复的主体名组成部分")
			}
			list, err := sequenceContent(value)
			if err != nil {
				return principal, err
			}
			lr := newDERReader(list)
			for lr.remaining() > 0 {
				component, err := readString(lr)
				if err != nil {
					return principal, err
				}
				principal.NameString = append(principal.NameString, component)
			}
			seenName = true
		default:
			return principal, errASN1("unexpected principal field 0x%02x | 意外的主体字段 0x%02x", tag, tag)
		}
	}
	if !seenType || !seenName {
		return principal, errASN1("principal name is missing required fields | 主体名缺少必需字段")
	}
	return principal, nil
}

// appendEncryptionKey encodes an EncryptionKey. | appendEncryptionKey 编码 EncryptionKey。
func appendEncryptionKey(dst []byte, key EncryptionKey) []byte {
	return derAppendSequence(dst,
		appendIntContext(nil, 0, key.KeyType),
		appendOctetsContext(nil, 1, key.KeyValue),
	)
}

// parseEncryptionKey decodes an EncryptionKey. | parseEncryptionKey 解码 EncryptionKey。
func parseEncryptionKey(content []byte) (EncryptionKey, error) {
	body, err := sequenceContent(content)
	if err != nil {
		return EncryptionKey{}, err
	}
	var key EncryptionKey
	seenType, seenValue := false, false
	r := newDERReader(body)
	for r.remaining() > 0 {
		tag, value, err := r.next()
		if err != nil {
			return key, err
		}
		switch tag {
		case 0xA0:
			number, err := readContextInt32(value)
			if err != nil {
				return key, err
			}
			key.KeyType = number
			seenType = true
		case 0xA1:
			key.KeyValue, err = readContextOctets(value)
			if err != nil {
				return key, err
			}
			seenValue = true
		default:
			return key, errASN1("unexpected encryption key field 0x%02x | 意外的加密密钥字段 0x%02x", tag, tag)
		}
	}
	if !seenType || !seenValue {
		return key, errASN1("encryption key is missing required fields | 加密密钥缺少必需字段")
	}
	return key, nil
}

// appendEncryptedData encodes an EncryptedData. | appendEncryptedData 编码 EncryptedData。
func appendEncryptedData(dst []byte, data EncryptedData) []byte {
	parts := [][]byte{appendIntContext(nil, 0, data.EType)}
	if data.KVNO != 0 {
		parts = append(parts, appendIntContext(nil, 1, data.KVNO))
	}
	parts = append(parts, appendOctetsContext(nil, 2, data.Cipher))
	return derAppendSequence(dst, parts...)
}

// parseEncryptedData decodes an EncryptedData. | parseEncryptedData 解码 EncryptedData。
func parseEncryptedData(content []byte) (EncryptedData, error) {
	body, err := sequenceContent(content)
	if err != nil {
		return EncryptedData{}, err
	}
	var data EncryptedData
	seenType, seenCipher := false, false
	r := newDERReader(body)
	for r.remaining() > 0 {
		tag, value, err := r.next()
		if err != nil {
			return data, err
		}
		switch tag {
		case 0xA0:
			number, err := readContextInt32(value)
			if err != nil {
				return data, err
			}
			data.EType = number
			seenType = true
		case 0xA1:
			number, err := readContextInt32(value)
			if err != nil {
				return data, err
			}
			data.KVNO = number
		case 0xA2:
			data.Cipher, err = readContextOctets(value)
			if err != nil {
				return data, err
			}
			seenCipher = true
		default:
			return data, errASN1("unexpected encrypted data field 0x%02x | 意外的加密数据字段 0x%02x", tag, tag)
		}
	}
	if !seenType || !seenCipher {
		return data, errASN1("encrypted data is missing required fields | 加密数据缺少必需字段")
	}
	return data, nil
}

// appendChecksum encodes a Checksum. | appendChecksum 编码 Checksum。
func appendChecksum(dst []byte, checksum Checksum) []byte {
	return derAppendSequence(dst,
		appendIntContext(nil, 0, checksum.CksumType),
		appendOctetsContext(nil, 1, checksum.Checksum),
	)
}

// parseChecksum decodes a Checksum. | parseChecksum 解码 Checksum。
func parseChecksum(content []byte) (Checksum, error) {
	body, err := sequenceContent(content)
	if err != nil {
		return Checksum{}, err
	}
	var checksum Checksum
	seenType, seenValue := false, false
	r := newDERReader(body)
	for r.remaining() > 0 {
		tag, value, err := r.next()
		if err != nil {
			return checksum, err
		}
		switch tag {
		case 0xA0:
			number, err := readContextInt32(value)
			if err != nil {
				return checksum, err
			}
			checksum.CksumType = number
			seenType = true
		case 0xA1:
			checksum.Checksum, err = readContextOctets(value)
			if err != nil {
				return checksum, err
			}
			seenValue = true
		default:
			return checksum, errASN1("unexpected checksum field 0x%02x | 意外的校验和字段 0x%02x", tag, tag)
		}
	}
	if !seenType || !seenValue {
		return checksum, errASN1("checksum is missing required fields | 校验和缺少必需字段")
	}
	return checksum, nil
}

// appendHostAddress encodes a HostAddress. | appendHostAddress 编码 HostAddress。
func appendHostAddress(dst []byte, address HostAddress) []byte {
	return derAppendSequence(dst,
		appendIntContext(nil, 0, address.AddrType),
		appendOctetsContext(nil, 1, address.Address),
	)
}

// parseHostAddress decodes a HostAddress. | parseHostAddress 解码 HostAddress。
func parseHostAddress(content []byte) (HostAddress, error) {
	var address HostAddress
	seenType, seenValue := false, false
	r := newDERReader(content)
	for r.remaining() > 0 {
		tag, value, err := r.next()
		if err != nil {
			return address, err
		}
		switch tag {
		case 0xA0:
			number, err := readContextInt32(value)
			if err != nil {
				return address, err
			}
			address.AddrType = number
			seenType = true
		case 0xA1:
			address.Address, err = readContextOctets(value)
			if err != nil {
				return address, err
			}
			seenValue = true
		default:
			return address, errASN1("unexpected host address field 0x%02x | 意外的主机地址字段 0x%02x", tag, tag)
		}
	}
	if !seenType || !seenValue {
		return address, errASN1("host address is missing required fields | 主机地址缺少必需字段")
	}
	return address, nil
}

// appendHostAddresses encodes a SEQUENCE OF HostAddress. | appendHostAddresses 编码
// SEQUENCE OF HostAddress。
func appendHostAddresses(dst []byte, addresses []HostAddress) []byte {
	parts := make([][]byte, 0, len(addresses))
	for _, address := range addresses {
		parts = append(parts, appendHostAddress(nil, address))
	}
	return derAppendSequence(dst, parts...)
}

// parseHostAddresses decodes a SEQUENCE OF HostAddress. | parseHostAddresses 解码
// SEQUENCE OF HostAddress。
func parseHostAddresses(content []byte) ([]HostAddress, error) {
	body, err := sequenceContent(content)
	if err != nil {
		return nil, err
	}
	r := newDERReader(body)
	var addresses []HostAddress
	for r.remaining() > 0 {
		entry, err := r.expect(derTagSequence)
		if err != nil {
			return nil, err
		}
		address, err := parseHostAddress(entry)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

// appendTransitedEncoding encodes a TransitedEncoding. | appendTransitedEncoding 编码
// TransitedEncoding。
func appendTransitedEncoding(dst []byte, transited TransitedEncoding) []byte {
	return derAppendSequence(dst,
		appendIntContext(nil, 0, transited.TrType),
		appendOctetsContext(nil, 1, transited.Contents),
	)
}

// parseTransitedEncoding decodes a TransitedEncoding. | parseTransitedEncoding 解码
// TransitedEncoding。
func parseTransitedEncoding(content []byte) (TransitedEncoding, error) {
	body, err := sequenceContent(content)
	if err != nil {
		return TransitedEncoding{}, err
	}
	var transited TransitedEncoding
	seenType, seenContents := false, false
	r := newDERReader(body)
	for r.remaining() > 0 {
		tag, value, err := r.next()
		if err != nil {
			return transited, err
		}
		switch tag {
		case 0xA0:
			number, err := readContextInt32(value)
			if err != nil {
				return transited, err
			}
			transited.TrType = number
			seenType = true
		case 0xA1:
			transited.Contents, err = readContextOctets(value)
			if err != nil {
				return transited, err
			}
			seenContents = true
		default:
			return transited, errASN1("unexpected transited field 0x%02x | 意外的域间路径字段 0x%02x", tag, tag)
		}
	}
	if !seenType || !seenContents {
		return transited, errASN1("transited encoding is missing required fields | 域间路径编码缺少必需字段")
	}
	return transited, nil
}

// appendAuthorizationData encodes AuthorizationData. | appendAuthorizationData 编码
// AuthorizationData。
func appendAuthorizationData(dst []byte, data []TypedData) []byte {
	parts := make([][]byte, 0, len(data))
	for _, item := range data {
		parts = append(parts, derAppendSequence(nil,
			appendIntContext(nil, 0, item.DataType),
			appendOctetsContext(nil, 1, item.DataValue),
		))
	}
	return derAppendSequence(dst, parts...)
}

// parseAuthorizationData decodes AuthorizationData. | parseAuthorizationData 解码
// AuthorizationData。
func parseAuthorizationData(content []byte) ([]TypedData, error) {
	body, err := sequenceContent(content)
	if err != nil {
		return nil, err
	}
	r := newDERReader(body)
	var data []TypedData
	for r.remaining() > 0 {
		entry, err := r.expect(derTagSequence)
		if err != nil {
			return nil, err
		}
		var item TypedData
		seenType, seenValue := false, false
		ir := newDERReader(entry)
		for ir.remaining() > 0 {
			tag, value, err := ir.next()
			if err != nil {
				return nil, err
			}
			switch tag {
			case 0xA0:
				number, err := readContextInt32(value)
				if err != nil {
					return nil, err
				}
				item.DataType = number
				seenType = true
			case 0xA1:
				item.DataValue, err = readContextOctets(value)
				if err != nil {
					return nil, err
				}
				seenValue = true
			default:
				return nil, errASN1("unexpected authorization data field 0x%02x | 意外的授权数据字段 0x%02x", tag, tag)
			}
		}
		if !seenType || !seenValue {
			return nil, errASN1("authorization data is missing required fields | 授权数据缺少必需字段")
		}
		data = append(data, item)
	}
	return data, nil
}

// appendTicket encodes a Ticket. | appendTicket 编码 Ticket。
func appendTicket(dst []byte, ticket Ticket) []byte {
	body := derAppendSequence(nil,
		appendIntContext(nil, 0, ticket.TktVNO),
		appendStringContext(nil, 1, ticket.Realm),
		derAppendContext(nil, 2, appendPrincipalName(nil, ticket.SName)),
		derAppendContext(nil, 3, appendEncryptedData(nil, ticket.EncPart)),
	)
	return derAppendApplication(dst, 1, body)
}

// parseTicket decodes a Ticket. | parseTicket 解码 Ticket。
func parseTicket(data []byte) (Ticket, error) {
	content, err := applicationContent(data, 1)
	if err != nil {
		return Ticket{}, err
	}
	var ticket Ticket
	seen := [4]bool{}
	r := newDERReader(content)
	for r.remaining() > 0 {
		tag, value, err := r.next()
		if err != nil {
			return Ticket{}, err
		}
		if tag < 0xA0 || tag > 0xA3 {
			return Ticket{}, errASN1("unexpected ticket field 0x%02x | 意外的票据字段 0x%02x", tag, tag)
		}
		index := int(tag - 0xA0)
		if seen[index] {
			return Ticket{}, errASN1("duplicate ticket field 0x%02x | 重复的票据字段 0x%02x", tag, tag)
		}
		seen[index] = true
		switch tag {
		case 0xA0:
			number, err := readContextInt32(value)
			if err != nil {
				return Ticket{}, err
			}
			ticket.TktVNO = number
		case 0xA1:
			ticket.Realm, err = readContextString(value)
			if err != nil {
				return Ticket{}, err
			}
		case 0xA2:
			ticket.SName, err = parsePrincipalName(value)
			if err != nil {
				return Ticket{}, err
			}
		case 0xA3:
			ticket.EncPart, err = parseEncryptedData(value)
			if err != nil {
				return Ticket{}, err
			}
		}
	}
	for i, present := range seen {
		if !present {
			return Ticket{}, errASN1("ticket is missing field %d | 票据缺少字段 %d", i, i)
		}
	}
	return ticket, nil
}

// appendAuthenticator encodes an Authenticator. | appendAuthenticator 编码 Authenticator。
func appendAuthenticator(dst []byte, authenticator Authenticator) []byte {
	parts := [][]byte{
		appendIntContext(nil, 0, authenticator.AuthenticatorVNO),
		appendStringContext(nil, 1, authenticator.CRealm),
		derAppendContext(nil, 2, appendPrincipalName(nil, authenticator.CName)),
	}
	if authenticator.Cksum != nil {
		parts = append(parts, derAppendContext(nil, 3, appendChecksum(nil, *authenticator.Cksum)))
	}
	parts = append(parts, appendIntContext(nil, 4, authenticator.CUSec))
	parts = append(parts, appendTimeContext(nil, 5, authenticator.CTime.Time))
	if authenticator.SubKey != nil {
		parts = append(parts, derAppendContext(nil, 6, appendEncryptionKey(nil, *authenticator.SubKey)))
	}
	if authenticator.SeqNumber != nil {
		parts = append(parts, appendUintContext(nil, 7, *authenticator.SeqNumber))
	}
	if authenticator.AuthorizationData != nil {
		parts = append(parts, derAppendContext(nil, 8, appendAuthorizationData(nil, authenticator.AuthorizationData)))
	}
	body := derAppendSequence(nil, parts...)
	return derAppendApplication(dst, 2, body)
}

// parseAuthenticator decodes an Authenticator. | parseAuthenticator 解码 Authenticator。
func parseAuthenticator(data []byte) (Authenticator, error) {
	content, err := applicationContent(data, 2)
	if err != nil {
		return Authenticator{}, err
	}
	var authenticator Authenticator
	seen := [9]bool{}
	r := newDERReader(content)
	for r.remaining() > 0 {
		tag, value, err := r.next()
		if err != nil {
			return Authenticator{}, err
		}
		if tag < 0xA0 || tag > 0xA8 {
			return Authenticator{}, errASN1("unexpected authenticator field 0x%02x | 意外的认证器字段 0x%02x", tag, tag)
		}
		index := int(tag - 0xA0)
		if seen[index] {
			return Authenticator{}, errASN1("duplicate authenticator field 0x%02x | 重复的认证器字段 0x%02x", tag, tag)
		}
		seen[index] = true
		switch tag {
		case 0xA0:
			number, err := readContextInt32(value)
			if err != nil {
				return Authenticator{}, err
			}
			authenticator.AuthenticatorVNO = number
		case 0xA1:
			authenticator.CRealm, err = readContextString(value)
			if err != nil {
				return Authenticator{}, err
			}
		case 0xA2:
			authenticator.CName, err = parsePrincipalName(value)
			if err != nil {
				return Authenticator{}, err
			}
		case 0xA3:
			checksum, err := parseChecksum(value)
			if err != nil {
				return Authenticator{}, err
			}
			authenticator.Cksum = &checksum
		case 0xA4:
			number, err := readContextInt32(value)
			if err != nil {
				return Authenticator{}, err
			}
			authenticator.CUSec = number
		case 0xA5:
			parsed, err := readContextGeneralizedTime(value)
			if err != nil {
				return Authenticator{}, err
			}
			authenticator.CTime = NewKerberosTime(parsed)
		case 0xA6:
			key, err := parseEncryptionKey(value)
			if err != nil {
				return Authenticator{}, err
			}
			authenticator.SubKey = &key
		case 0xA7:
			number, err := readContextUint32(value)
			if err != nil {
				return Authenticator{}, err
			}
			authenticator.SeqNumber = &number
		case 0xA8:
			items, err := parseAuthorizationData(value)
			if err != nil {
				return Authenticator{}, err
			}
			authenticator.AuthorizationData = items
		}
	}
	required := []int{0, 1, 2, 4, 5}
	for _, index := range required {
		if !seen[index] {
			return Authenticator{}, errASN1("authenticator is missing field %d | 认证器缺少字段 %d", index, index)
		}
	}
	return authenticator, nil
}

// appendEncTicketPart encodes an EncTicketPart with its APPLICATION 3 tag. | appendEncTicketPart
// 编码带 APPLICATION 3 标签的 EncTicketPart。
func appendEncTicketPart(part EncTicketPart) []byte {
	parts := [][]byte{
		appendFlagsContext(nil, 0, uint32(part.Flags)),
		derAppendContext(nil, 1, appendEncryptionKey(nil, part.Key)),
		appendStringContext(nil, 2, part.CRealm),
		derAppendContext(nil, 3, appendPrincipalName(nil, part.CName)),
		derAppendContext(nil, 4, appendTransitedEncoding(nil, part.Transited)),
		appendTimeContext(nil, 5, part.AuthTime.Time),
	}
	if part.StartTime != nil {
		parts = append(parts, appendTimeContext(nil, 6, part.StartTime.Time))
	}
	parts = append(parts, appendTimeContext(nil, 7, part.EndTime.Time))
	if part.RenewTill != nil {
		parts = append(parts, appendTimeContext(nil, 8, part.RenewTill.Time))
	}
	if part.CAddr != nil {
		parts = append(parts, derAppendContext(nil, 9, appendHostAddresses(nil, part.CAddr)))
	}
	if part.AuthorizationData != nil {
		parts = append(parts, derAppendContext(nil, 10, appendAuthorizationData(nil, part.AuthorizationData)))
	}
	return derAppendApplication(nil, 3, derAppendSequence(nil, parts...))
}

// parseEncTicketPart decodes an EncTicketPart. | parseEncTicketPart 解码 EncTicketPart。
func parseEncTicketPart(data []byte) (EncTicketPart, error) {
	content, err := applicationContent(data, 3)
	if err != nil {
		return EncTicketPart{}, err
	}
	var part EncTicketPart
	seen := [11]bool{}
	r := newDERReader(content)
	for r.remaining() > 0 {
		tag, value, err := r.next()
		if err != nil {
			return EncTicketPart{}, err
		}
		if tag < 0xA0 || tag > 0xAA {
			return EncTicketPart{}, errASN1("unexpected EncTicketPart field 0x%02x | 意外的 EncTicketPart 字段 0x%02x", tag, tag)
		}
		index := int(tag - 0xA0)
		if seen[index] {
			return EncTicketPart{}, errASN1("duplicate EncTicketPart field 0x%02x | 重复的 EncTicketPart 字段 0x%02x", tag, tag)
		}
		seen[index] = true
		switch tag {
		case 0xA0:
			flags, err := readContextKerberosFlags(value)
			if err != nil {
				return EncTicketPart{}, err
			}
			part.Flags = TicketFlags(flags)
		case 0xA1:
			part.Key, err = parseEncryptionKey(value)
			if err != nil {
				return EncTicketPart{}, err
			}
		case 0xA2:
			part.CRealm, err = readContextString(value)
			if err != nil {
				return EncTicketPart{}, err
			}
		case 0xA3:
			part.CName, err = parsePrincipalName(value)
			if err != nil {
				return EncTicketPart{}, err
			}
		case 0xA4:
			part.Transited, err = parseTransitedEncoding(value)
			if err != nil {
				return EncTicketPart{}, err
			}
		case 0xA5:
			parsed, err := readContextGeneralizedTime(value)
			if err != nil {
				return EncTicketPart{}, err
			}
			part.AuthTime = NewKerberosTime(parsed)
		case 0xA6:
			parsed, err := readContextGeneralizedTime(value)
			if err != nil {
				return EncTicketPart{}, err
			}
			start := NewKerberosTime(parsed)
			part.StartTime = &start
		case 0xA7:
			parsed, err := readContextGeneralizedTime(value)
			if err != nil {
				return EncTicketPart{}, err
			}
			part.EndTime = NewKerberosTime(parsed)
		case 0xA8:
			parsed, err := readContextGeneralizedTime(value)
			if err != nil {
				return EncTicketPart{}, err
			}
			renew := NewKerberosTime(parsed)
			part.RenewTill = &renew
		case 0xA9:
			part.CAddr, err = parseHostAddresses(value)
			if err != nil {
				return EncTicketPart{}, err
			}
		case 0xAA:
			part.AuthorizationData, err = parseAuthorizationData(value)
			if err != nil {
				return EncTicketPart{}, err
			}
		}
	}
	required := []int{0, 1, 2, 3, 4, 5, 7}
	for _, index := range required {
		if !seen[index] {
			return EncTicketPart{}, errASN1("EncTicketPart is missing field %d | EncTicketPart 缺少字段 %d", index, index)
		}
	}
	return part, nil
}

// appendEncAPRepPart encodes an EncAPRepPart with its APPLICATION 27 tag. | appendEncAPRepPart
// 编码带 APPLICATION 27 标签的 EncAPRepPart。
func appendEncAPRepPart(part EncAPRepPart) []byte {
	parts := [][]byte{
		appendTimeContext(nil, 0, part.CTime.Time),
		appendIntContext(nil, 1, part.CUSec),
	}
	if part.SubKey != nil {
		parts = append(parts, derAppendContext(nil, 2, appendEncryptionKey(nil, *part.SubKey)))
	}
	if part.SeqNumber != nil {
		parts = append(parts, appendUintContext(nil, 3, *part.SeqNumber))
	}
	return derAppendApplication(nil, 27, derAppendSequence(nil, parts...))
}

// parseEncAPRepPart decodes an EncAPRepPart. | parseEncAPRepPart 解码 EncAPRepPart。
func parseEncAPRepPart(data []byte) (EncAPRepPart, error) {
	content, err := applicationContent(data, 27)
	if err != nil {
		return EncAPRepPart{}, err
	}
	var part EncAPRepPart
	seen := [4]bool{}
	r := newDERReader(content)
	for r.remaining() > 0 {
		tag, value, err := r.next()
		if err != nil {
			return EncAPRepPart{}, err
		}
		if tag < 0xA0 || tag > 0xA3 {
			return EncAPRepPart{}, errASN1("unexpected EncAPRepPart field 0x%02x | 意外的 EncAPRepPart 字段 0x%02x", tag, tag)
		}
		index := int(tag - 0xA0)
		if seen[index] {
			return EncAPRepPart{}, errASN1("duplicate EncAPRepPart field 0x%02x | 重复的 EncAPRepPart 字段 0x%02x", tag, tag)
		}
		seen[index] = true
		switch tag {
		case 0xA0:
			parsed, err := readContextGeneralizedTime(value)
			if err != nil {
				return EncAPRepPart{}, err
			}
			part.CTime = NewKerberosTime(parsed)
		case 0xA1:
			number, err := readContextInt32(value)
			if err != nil {
				return EncAPRepPart{}, err
			}
			part.CUSec = number
		case 0xA2:
			key, err := parseEncryptionKey(value)
			if err != nil {
				return EncAPRepPart{}, err
			}
			part.SubKey = &key
		case 0xA3:
			number, err := readContextUint32(value)
			if err != nil {
				return EncAPRepPart{}, err
			}
			part.SeqNumber = &number
		}
	}
	if !seen[0] || !seen[1] {
		return EncAPRepPart{}, errASN1("EncAPRepPart is missing required fields | EncAPRepPart 缺少必需字段")
	}
	return part, nil
}

// appendEncKDCRepPart encodes an EncKDCRepPart for AS-REP (25) or TGS-REP (26). | appendEncKDCRepPart
// 为 AS-REP（25）或 TGS-REP（26）编码 EncKDCRepPart。
func appendEncKDCRepPart(part EncKDCRepPart, application int) []byte {
	lastReq := make([][]byte, 0, len(part.LastReq))
	for _, item := range part.LastReq {
		lastReq = append(lastReq, derAppendSequence(nil,
			appendIntContext(nil, 0, item.LRType),
			appendTimeContext(nil, 1, item.LRValue.Time),
		))
	}
	parts := [][]byte{
		derAppendContext(nil, 0, appendEncryptionKey(nil, part.Key)),
		derAppendContext(nil, 1, derAppendSequence(nil, lastReq...)),
		appendUintContext(nil, 2, part.Nonce),
	}
	if part.KeyExpiration != nil {
		parts = append(parts, appendTimeContext(nil, 3, part.KeyExpiration.Time))
	}
	parts = append(parts,
		appendFlagsContext(nil, 4, uint32(part.Flags)),
		appendTimeContext(nil, 5, part.AuthTime.Time),
	)
	if part.StartTime != nil {
		parts = append(parts, appendTimeContext(nil, 6, part.StartTime.Time))
	}
	parts = append(parts, appendTimeContext(nil, 7, part.EndTime.Time))
	if part.RenewTill != nil {
		parts = append(parts, appendTimeContext(nil, 8, part.RenewTill.Time))
	}
	parts = append(parts,
		appendStringContext(nil, 9, part.SRealm),
		derAppendContext(nil, 10, appendPrincipalName(nil, part.SName)),
	)
	if part.CAddr != nil {
		parts = append(parts, derAppendContext(nil, 11, appendHostAddresses(nil, part.CAddr)))
	}
	return derAppendApplication(nil, application, derAppendSequence(nil, parts...))
}

// parseEncKDCRepPart decodes an EncKDCRepPart. MIT krb5 encodes both
// EncASRepPart and EncTGSRepPart with application tag 26 for backwards
// compatibility and accepts either tag on decode, so both application tags are
// accepted here as well. | parseEncKDCRepPart 解码 EncKDCRepPart。MIT krb5 为向后
// 兼容把 EncASRepPart 与 EncTGSRepPart 都用应用标签 26 编码，并在解码时接受任一标签，
// 因此这里同样接受两个应用标签。
func parseEncKDCRepPart(data []byte, application int) (EncKDCRepPart, error) {
	content, err := applicationContent(data, application)
	if err != nil {
		alternate := 0
		switch application {
		case 25:
			alternate = 26
		case 26:
			alternate = 25
		}
		if alternate == 0 {
			return EncKDCRepPart{}, err
		}
		content, err = applicationContent(data, alternate)
		if err != nil {
			return EncKDCRepPart{}, err
		}
	}
	var part EncKDCRepPart
	seen := [12]bool{}
	r := newDERReader(content)
	for r.remaining() > 0 {
		tag, value, err := r.next()
		if err != nil {
			return EncKDCRepPart{}, err
		}
		if tag < 0xA0 || tag > 0xAB {
			return EncKDCRepPart{}, errASN1("unexpected EncKDCRepPart field 0x%02x | 意外的 EncKDCRepPart 字段 0x%02x", tag, tag)
		}
		index := int(tag - 0xA0)
		if seen[index] {
			return EncKDCRepPart{}, errASN1("duplicate EncKDCRepPart field 0x%02x | 重复的 EncKDCRepPart 字段 0x%02x", tag, tag)
		}
		seen[index] = true
		switch tag {
		case 0xA0:
			part.Key, err = parseEncryptionKey(value)
			if err != nil {
				return EncKDCRepPart{}, err
			}
		case 0xA1:
			body, err := sequenceContent(value)
			if err != nil {
				return EncKDCRepPart{}, err
			}
			lr := newDERReader(body)
			for lr.remaining() > 0 {
				entry, err := lr.expect(derTagSequence)
				if err != nil {
					return EncKDCRepPart{}, err
				}
				var item LastReq
				itemSeen := [2]bool{}
				er := newDERReader(entry)
				for er.remaining() > 0 {
					ftag, fvalue, err := er.next()
					if err != nil {
						return EncKDCRepPart{}, err
					}
					switch ftag {
					case 0xA0:
						number, err := readContextInt32(fvalue)
						if err != nil {
							return EncKDCRepPart{}, err
						}
						item.LRType = number
						itemSeen[0] = true
					case 0xA1:
						parsed, err := readContextGeneralizedTime(fvalue)
						if err != nil {
							return EncKDCRepPart{}, err
						}
						item.LRValue = NewKerberosTime(parsed)
						itemSeen[1] = true
					default:
						return EncKDCRepPart{}, errASN1("unexpected LastReq field 0x%02x | 意外的 LastReq 字段 0x%02x", ftag, ftag)
					}
				}
				if !itemSeen[0] || !itemSeen[1] {
					return EncKDCRepPart{}, errASN1("LastReq is missing required fields | LastReq 缺少必需字段")
				}
				part.LastReq = append(part.LastReq, item)
			}
		case 0xA2:
			number, err := readContextUint32(value)
			if err != nil {
				return EncKDCRepPart{}, err
			}
			part.Nonce = number
		case 0xA3:
			parsed, err := readContextGeneralizedTime(value)
			if err != nil {
				return EncKDCRepPart{}, err
			}
			expiration := NewKerberosTime(parsed)
			part.KeyExpiration = &expiration
		case 0xA4:
			flags, err := readContextKerberosFlags(value)
			if err != nil {
				return EncKDCRepPart{}, err
			}
			part.Flags = TicketFlags(flags)
		case 0xA5:
			parsed, err := readContextGeneralizedTime(value)
			if err != nil {
				return EncKDCRepPart{}, err
			}
			part.AuthTime = NewKerberosTime(parsed)
		case 0xA6:
			parsed, err := readContextGeneralizedTime(value)
			if err != nil {
				return EncKDCRepPart{}, err
			}
			start := NewKerberosTime(parsed)
			part.StartTime = &start
		case 0xA7:
			parsed, err := readContextGeneralizedTime(value)
			if err != nil {
				return EncKDCRepPart{}, err
			}
			part.EndTime = NewKerberosTime(parsed)
		case 0xA8:
			parsed, err := readContextGeneralizedTime(value)
			if err != nil {
				return EncKDCRepPart{}, err
			}
			renew := NewKerberosTime(parsed)
			part.RenewTill = &renew
		case 0xA9:
			part.SRealm, err = readContextString(value)
			if err != nil {
				return EncKDCRepPart{}, err
			}
		case 0xAA:
			part.SName, err = parsePrincipalName(value)
			if err != nil {
				return EncKDCRepPart{}, err
			}
		case 0xAB:
			part.CAddr, err = parseHostAddresses(value)
			if err != nil {
				return EncKDCRepPart{}, err
			}
		}
	}
	required := []int{0, 1, 2, 4, 5, 7, 9, 10}
	for _, index := range required {
		if !seen[index] {
			return EncKDCRepPart{}, errASN1("EncKDCRepPart is missing field %d | EncKDCRepPart 缺少字段 %d", index, index)
		}
	}
	return part, nil
}

// appendPAData encodes PA-DATA. | appendPAData 编码 PA-DATA。
func appendPAData(dst []byte, data PAData) []byte {
	return derAppendSequence(dst,
		appendIntContext(nil, 1, data.PADataType),
		appendOctetsContext(nil, 2, data.PADataValue),
	)
}

// parsePAData decodes PA-DATA. | parsePAData 解码 PA-DATA。
func parsePAData(content []byte) (PAData, error) {
	var data PAData
	seenType, seenValue := false, false
	r := newDERReader(content)
	for r.remaining() > 0 {
		tag, value, err := r.next()
		if err != nil {
			return data, err
		}
		switch tag {
		case 0xA1:
			number, err := readContextInt32(value)
			if err != nil {
				return data, err
			}
			data.PADataType = number
			seenType = true
		case 0xA2:
			data.PADataValue, err = readContextOctets(value)
			if err != nil {
				return data, err
			}
			seenValue = true
		default:
			return data, errASN1("unexpected PA-DATA field 0x%02x | 意外的 PA-DATA 字段 0x%02x", tag, tag)
		}
	}
	if !seenType || !seenValue {
		return data, errASN1("PA-DATA is missing required fields | PA-DATA 缺少必需字段")
	}
	return data, nil
}

// marshalPAEncTSEnc encodes PA-ENC-TIMESTAMP plaintext. | marshalPAEncTSEnc 编码
// PA-ENC-TIMESTAMP 明文。
func marshalPAEncTSEnc(timestamp PAEncTSEnc) []byte {
	parts := [][]byte{appendTimeContext(nil, 0, timestamp.PATimestamp.Time)}
	if timestamp.PAUSec != nil {
		parts = append(parts, appendIntContext(nil, 1, *timestamp.PAUSec))
	}
	return derAppendSequence(nil, parts...)
}

// parsePAEncTSEnc decodes PA-ENC-TIMESTAMP plaintext. | parsePAEncTSEnc 解码
// PA-ENC-TIMESTAMP 明文。
func parsePAEncTSEnc(data []byte) (PAEncTSEnc, error) {
	content, err := sequenceContent(data)
	if err != nil {
		return PAEncTSEnc{}, err
	}
	var timestamp PAEncTSEnc
	seenTime := false
	r := newDERReader(content)
	for r.remaining() > 0 {
		tag, value, err := r.next()
		if err != nil {
			return timestamp, err
		}
		switch tag {
		case 0xA0:
			parsed, err := readContextGeneralizedTime(value)
			if err != nil {
				return timestamp, err
			}
			timestamp.PATimestamp = NewKerberosTime(parsed)
			seenTime = true
		case 0xA1:
			number, err := readContextInt32(value)
			if err != nil {
				return timestamp, err
			}
			timestamp.PAUSec = &number
		default:
			return timestamp, errASN1("unexpected PA-ENC-TS field 0x%02x | 意外的 PA-ENC-TS 字段 0x%02x", tag, tag)
		}
	}
	if !seenTime {
		return timestamp, errASN1("PA-ENC-TS is missing its timestamp | PA-ENC-TS 缺少时间戳")
	}
	return timestamp, nil
}

// parseETypeInfo2 decodes a SEQUENCE OF ETYPE-INFO2-ENTRY. | parseETypeInfo2 解码
// SEQUENCE OF ETYPE-INFO2-ENTRY。
func parseETypeInfo2(data []byte) ([]ETypeInfo2Entry, error) {
	content, err := sequenceContent(data)
	if err != nil {
		return nil, err
	}
	r := newDERReader(content)
	var entries []ETypeInfo2Entry
	for r.remaining() > 0 {
		entry, err := r.expect(derTagSequence)
		if err != nil {
			return nil, err
		}
		var item ETypeInfo2Entry
		seenType := false
		ir := newDERReader(entry)
		for ir.remaining() > 0 {
			tag, value, err := ir.next()
			if err != nil {
				return nil, err
			}
			switch tag {
			case 0xA0:
				number, err := readContextInt32(value)
				if err != nil {
					return nil, err
				}
				item.EType = number
				seenType = true
			case 0xA1:
				salt, err := readContextString(value)
				if err != nil {
					return nil, err
				}
				item.Salt = &salt
			case 0xA2:
				item.S2KParams, err = readContextOctets(value)
				if err != nil {
					return nil, err
				}
			default:
				return nil, errASN1("unexpected ETYPE-INFO2 field 0x%02x | 意外的 ETYPE-INFO2 字段 0x%02x", tag, tag)
			}
		}
		if !seenType {
			return nil, errASN1("ETYPE-INFO2 entry is missing its enctype | ETYPE-INFO2 条目缺少加密类型")
		}
		entries = append(entries, item)
	}
	return entries, nil
}

// supportsEType reports whether list contains etype. | supportsEType 报告 list 是否包含 etype。
func supportsEType(list []int32, etype int32) bool {
	for _, item := range list {
		if item == etype {
			return true
		}
	}
	return false
}
