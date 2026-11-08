package radius

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/shibingli/ydx/errs"
)

// AttributeType is a RADIUS attribute type number. | AttributeType 是 RADIUS 属性类型号。
type AttributeType uint8

// Standard RADIUS attribute types. | 标准 RADIUS 属性类型。
const (
	// AttrUserName is the login name (RFC 2865 section 5.1). | AttrUserName 是登录名（RFC 2865 第 5.1 节）。
	AttrUserName AttributeType = 1
	// AttrUserPassword is the PAP-hidden password (RFC 2865 section 5.2). | AttrUserPassword 是 PAP 隐藏的口令（RFC 2865 第 5.2 节）。
	AttrUserPassword AttributeType = 2
	// AttrCHAPPassword is the CHAP identifier and response (RFC 2865 section 5.3). | AttrCHAPPassword 是 CHAP 标识与响应（RFC 2865 第 5.3 节）。
	AttrCHAPPassword AttributeType = 3
	// AttrNASIPAddress is the NAS IPv4 address (RFC 2865 section 5.4). | AttrNASIPAddress 是 NAS 的 IPv4 地址（RFC 2865 第 5.4 节）。
	AttrNASIPAddress AttributeType = 4
	// AttrNASPort is the physical NAS port (RFC 2865 section 5.5). | AttrNASPort 是 NAS 的物理端口（RFC 2865 第 5.5 节）。
	AttrNASPort AttributeType = 5
	// AttrServiceType is the requested service (RFC 2865 section 5.6). | AttrServiceType 是请求的服务（RFC 2865 第 5.6 节）。
	AttrServiceType AttributeType = 6
	// AttrFramedProtocol is the framing protocol (RFC 2865 section 5.7). | AttrFramedProtocol 是成帧协议（RFC 2865 第 5.7 节）。
	AttrFramedProtocol AttributeType = 7
	// AttrFramedIPAddress is the address assigned to the user (RFC 2865 section 5.8). | AttrFramedIPAddress 是分配给用户的地址（RFC 2865 第 5.8 节）。
	AttrFramedIPAddress AttributeType = 8
	// AttrFilterID is an access-list name (RFC 2865 section 5.11). | AttrFilterID 是访问控制列表名称（RFC 2865 第 5.11 节）。
	AttrFilterID AttributeType = 11
	// AttrFramedMTU is the maximum transmission unit (RFC 2865 section 5.12). | AttrFramedMTU 是最大传输单元（RFC 2865 第 5.12 节）。
	AttrFramedMTU AttributeType = 12
	// AttrLoginIPHost is a login host address (RFC 2865 section 5.14). | AttrLoginIPHost 是登录主机地址（RFC 2865 第 5.14 节）。
	AttrLoginIPHost AttributeType = 14
	// AttrReplyMessage is a human-readable message (RFC 2865 section 5.18). | AttrReplyMessage 是人类可读消息（RFC 2865 第 5.18 节）。
	AttrReplyMessage AttributeType = 18
	// AttrState is opaque server state echoed by the client (RFC 2865 section 5.24). | AttrState 是服务器不透明状态，由客户端回显（RFC 2865 第 5.24 节）。
	AttrState AttributeType = 24
	// AttrClass is an opaque value echoed in accounting requests (RFC 2865 section 5.25). | AttrClass 是不透明值，在计费请求中回显（RFC 2865 第 5.25 节）。
	AttrClass AttributeType = 25
	// AttrVendorSpecific carries vendor sub-attributes (RFC 2865 section 5.26). | AttrVendorSpecific 携带厂商子属性（RFC 2865 第 5.26 节）。
	AttrVendorSpecific AttributeType = 26
	// AttrSessionTimeout is the maximum session duration in seconds (RFC 2865 section 5.27). | AttrSessionTimeout 是会话最长持续时间（秒）（RFC 2865 第 5.27 节）。
	AttrSessionTimeout AttributeType = 27
	// AttrIdleTimeout is the maximum idle time in seconds (RFC 2865 section 5.28). | AttrIdleTimeout 是最大空闲时间（秒）（RFC 2865 第 5.28 节）。
	AttrIdleTimeout AttributeType = 28
	// AttrTerminationAction selects the action at session end (RFC 2865 section 5.29). | AttrTerminationAction 选择会话结束时的动作（RFC 2865 第 5.29 节）。
	AttrTerminationAction AttributeType = 29
	// AttrCalledStationID identifies the called station (RFC 2865 section 5.30). | AttrCalledStationID 标识被叫站点（RFC 2865 第 5.30 节）。
	AttrCalledStationID AttributeType = 30
	// AttrCallingStationID identifies the calling station (RFC 2865 section 5.31). | AttrCallingStationID 标识主叫站点（RFC 2865 第 5.31 节）。
	AttrCallingStationID AttributeType = 31
	// AttrNASIdentifier is a NAS name (RFC 2865 section 5.32). | AttrNASIdentifier 是 NAS 名称（RFC 2865 第 5.32 节）。
	AttrNASIdentifier AttributeType = 32
	// AttrProxyState is opaque proxy state (RFC 2865 section 5.33). | AttrProxyState 是不透明代理状态（RFC 2865 第 5.33 节）。
	AttrProxyState AttributeType = 33
	// AttrAcctStatusType is the accounting event type (RFC 2866 section 5.1). | AttrAcctStatusType 是计费事件类型（RFC 2866 第 5.1 节）。
	AttrAcctStatusType AttributeType = 40
	// AttrAcctDelayTime is the seconds the request was delayed (RFC 2866 section 5.2). | AttrAcctDelayTime 是请求被延迟的秒数（RFC 2866 第 5.2 节）。
	AttrAcctDelayTime AttributeType = 41
	// AttrAcctInputOctets is the received octet count (RFC 2866 section 5.3). | AttrAcctInputOctets 是接收的八位组计数（RFC 2866 第 5.3 节）。
	AttrAcctInputOctets AttributeType = 42
	// AttrAcctOutputOctets is the sent octet count (RFC 2866 section 5.4). | AttrAcctOutputOctets 是发送的八位组计数（RFC 2866 第 5.4 节）。
	AttrAcctOutputOctets AttributeType = 43
	// AttrAcctSessionID is the accounting session identifier (RFC 2866 section 5.5). | AttrAcctSessionID 是计费会话标识（RFC 2866 第 5.5 节）。
	AttrAcctSessionID AttributeType = 44
	// AttrAcctAuthentic reports how the user was authenticated (RFC 2866 section 5.6). | AttrAcctAuthentic 表示用户的认证方式（RFC 2866 第 5.6 节）。
	AttrAcctAuthentic AttributeType = 45
	// AttrAcctSessionTime is the session duration in seconds (RFC 2866 section 5.7). | AttrAcctSessionTime 是会话持续时间（秒）（RFC 2866 第 5.7 节）。
	AttrAcctSessionTime AttributeType = 46
	// AttrAcctInputPackets is the received packet count (RFC 2866 section 5.8). | AttrAcctInputPackets 是接收的报文计数（RFC 2866 第 5.8 节）。
	AttrAcctInputPackets AttributeType = 47
	// AttrAcctOutputPackets is the sent packet count (RFC 2866 section 5.9). | AttrAcctOutputPackets 是发送的报文计数（RFC 2866 第 5.9 节）。
	AttrAcctOutputPackets AttributeType = 48
	// AttrAcctTerminateCause is the session termination reason (RFC 2866 section 5.10). | AttrAcctTerminateCause 是会话终止原因（RFC 2866 第 5.10 节）。
	AttrAcctTerminateCause AttributeType = 49
	// AttrAcctMultiSessionID links related sessions (RFC 2866 section 5.11). | AttrAcctMultiSessionID 关联相关会话（RFC 2866 第 5.11 节）。
	AttrAcctMultiSessionID AttributeType = 50
	// AttrAcctLinkCount is the number of links in a multilink session (RFC 2866 section 5.12). | AttrAcctLinkCount 是多链路会话的链路数（RFC 2866 第 5.12 节）。
	AttrAcctLinkCount AttributeType = 51
	// AttrAcctInputGigawords counts 2^32-octet input units (RFC 2869 section 5.1). | AttrAcctInputGigawords 统计 2^32 字节单位的输入量（RFC 2869 第 5.1 节）。
	AttrAcctInputGigawords AttributeType = 52
	// AttrAcctOutputGigawords counts 2^32-octet output units (RFC 2869 section 5.2). | AttrAcctOutputGigawords 统计 2^32 字节单位的输出量（RFC 2869 第 5.2 节）。
	AttrAcctOutputGigawords AttributeType = 53
	// AttrEventTimestamp is the event time in Unix seconds (RFC 2869 section 5.3). | AttrEventTimestamp 是 Unix 秒表示的事件时间（RFC 2869 第 5.3 节）。
	AttrEventTimestamp AttributeType = 55
	// AttrCHAPChallenge is the CHAP challenge (RFC 2865 section 5.40). | AttrCHAPChallenge 是 CHAP 挑战（RFC 2865 第 5.40 节）。
	AttrCHAPChallenge AttributeType = 60
	// AttrNASPortType is the physical port type (RFC 2865 section 5.41). | AttrNASPortType 是物理端口类型（RFC 2865 第 5.41 节）。
	AttrNASPortType AttributeType = 61
	// AttrPortLimit is the maximum number of ports (RFC 2865 section 5.42). | AttrPortLimit 是端口数上限（RFC 2865 第 5.42 节）。
	AttrPortLimit AttributeType = 62
	// AttrTunnelType is the tunnel protocol (RFC 2868 section 3.1). | AttrTunnelType 是隧道协议（RFC 2868 第 3.1 节）。
	AttrTunnelType AttributeType = 64
	// AttrTunnelMediumType is the tunnel medium (RFC 2868 section 3.2). | AttrTunnelMediumType 是隧道介质（RFC 2868 第 3.2 节）。
	AttrTunnelMediumType AttributeType = 65
	// AttrEAPMessage carries an EAP packet (RFC 2869 section 5.13). | AttrEAPMessage 携带 EAP 报文（RFC 2869 第 5.13 节）。
	AttrEAPMessage AttributeType = 79
	// AttrMessageAuthenticator authenticates the packet with HMAC-MD5 (RFC 3579 section 3.2). | AttrMessageAuthenticator 用 HMAC-MD5 认证报文（RFC 3579 第 3.2 节）。
	AttrMessageAuthenticator AttributeType = 80
	// AttrTunnelPrivateGroupID is the tunnel private group (RFC 2868 section 3.3). | AttrTunnelPrivateGroupID 是隧道私有组（RFC 2868 第 3.3 节）。
	AttrTunnelPrivateGroupID AttributeType = 81
	// AttrErrorCause classifies a CoA-NAK or Disconnect-NAK (RFC 5176 section 3.5). | AttrErrorCause
	// 对 CoA-NAK 或 Disconnect-NAK 进行分类（RFC 5176 第 3.5 节）。
	AttrErrorCause AttributeType = 101
)

// Vendor identifiers used by the package. | 包使用的厂商标识。
const (
	// VendorCisco is the Cisco Systems vendor identifier. | VendorCisco 是 Cisco Systems 的厂商标识。
	VendorCisco uint32 = 9
	// VendorMicrosoft is the Microsoft vendor identifier. | VendorMicrosoft 是 Microsoft 的厂商标识。
	VendorMicrosoft uint32 = 311
)

// Microsoft vendor sub-attribute types (RFC 2548). | Microsoft 厂商子属性类型（RFC 2548）。
const (
	// VendorMSCHAPResponse is MS-CHAP-Response. | VendorMSCHAPResponse 是 MS-CHAP-Response。
	VendorMSCHAPResponse uint8 = 1
	// VendorMSCHAPError is MS-CHAP-Error. | VendorMSCHAPError 是 MS-CHAP-Error。
	VendorMSCHAPError uint8 = 2
	// VendorMSMPPEPolicy is MS-MPPE-Encryption-Policy (RFC 2548 section 2.4.4). | VendorMSMPPEPolicy 是 MS-MPPE-Encryption-Policy（RFC 2548 第 2.4.4 节）。
	VendorMSMPPEPolicy uint8 = 7
	// VendorMSMPPETypes is MS-MPPE-Encryption-Types (RFC 2548 section 2.4.5). | VendorMSMPPETypes 是 MS-MPPE-Encryption-Types（RFC 2548 第 2.4.5 节）。
	VendorMSMPPETypes uint8 = 8
	// VendorMSCHAPDomain is MS-CHAP-Domain. | VendorMSCHAPDomain 是 MS-CHAP-Domain。
	VendorMSCHAPDomain uint8 = 10
	// VendorMSCHAPChallenge is MS-CHAP-Challenge. | VendorMSCHAPChallenge 是 MS-CHAP-Challenge。
	VendorMSCHAPChallenge uint8 = 11
	// VendorMSCHAPMPPEKeys is MS-CHAP-MPPE-Keys. | VendorMSCHAPMPPEKeys 是 MS-CHAP-MPPE-Keys。
	VendorMSCHAPMPPEKeys uint8 = 12
	// VendorMSMPPESendKey is MS-MPPE-Send-Key (RFC 2548 section 2.4.2). | VendorMSMPPESendKey 是 MS-MPPE-Send-Key（RFC 2548 第 2.4.2 节）。
	VendorMSMPPESendKey uint8 = 16
	// VendorMSMPPERecvKey is MS-MPPE-Recv-Key (RFC 2548 section 2.4.3). | VendorMSMPPERecvKey 是 MS-MPPE-Recv-Key（RFC 2548 第 2.4.3 节）。
	VendorMSMPPERecvKey uint8 = 17
	// VendorMSCHAP2Response is MS-CHAP2-Response (RFC 2548 section 2.3.2). | VendorMSCHAP2Response 是 MS-CHAP2-Response（RFC 2548 第 2.3.2 节）。
	VendorMSCHAP2Response uint8 = 25
	// VendorMSCHAP2Success is MS-CHAP2-Success (RFC 2548 section 2.3.3). | VendorMSCHAP2Success 是 MS-CHAP2-Success（RFC 2548 第 2.3.3 节）。
	VendorMSCHAP2Success uint8 = 26
	// VendorMSCHAP2CPW is MS-CHAP2-CPW (RFC 2548 section 2.3.4). | VendorMSCHAP2CPW 是 MS-CHAP2-CPW（RFC 2548 第 2.3.4 节）。
	VendorMSCHAP2CPW uint8 = 27
	// VendorMSPrimaryDNSServer is MS-Primary-DNS-Server (RFC 2548 section 2.7.6). | VendorMSPrimaryDNSServer 是 MS-Primary-DNS-Server（RFC 2548 第 2.7.6 节）。
	VendorMSPrimaryDNSServer uint8 = 28
	// VendorMSSecondaryDNSServer is MS-Secondary-DNS-Server (RFC 2548 section 2.7.7). | VendorMSSecondaryDNSServer 是 MS-Secondary-DNS-Server（RFC 2548 第 2.7.7 节）。
	VendorMSSecondaryDNSServer uint8 = 29
	// VendorMSPrimaryNBNSServer is MS-Primary-NBNS-Server (RFC 2548 section 2.7.8). | VendorMSPrimaryNBNSServer 是 MS-Primary-NBNS-Server（RFC 2548 第 2.7.8 节）。
	VendorMSPrimaryNBNSServer uint8 = 30
	// VendorMSSecondaryNBNSServer is MS-Secondary-NBNS-Server (RFC 2548 section 2.7.9). | VendorMSSecondaryNBNSServer 是 MS-Secondary-NBNS-Server（RFC 2548 第 2.7.9 节）。
	VendorMSSecondaryNBNSServer uint8 = 31
)

// Cisco vendor sub-attribute types. | Cisco 厂商子属性类型。
const (
	// VendorCiscoAVPair is Cisco-AVPair. | VendorCiscoAVPair 是 Cisco-AVPair。
	VendorCiscoAVPair uint8 = 1
	// VendorCiscoNASPort is Cisco-NAS-Port. | VendorCiscoNASPort 是 Cisco-NAS-Port。
	VendorCiscoNASPort uint8 = 2
)

// Attribute is one RADIUS attribute and its value. | Attribute 是一个 RADIUS 属性及其值。
//
// For standard attributes Type and Value carry the TLV payload. For a decoded Vendor-Specific
// (type 26) attribute, VendorID and VendorType identify the sub-attribute and Value holds the
// sub-attribute value. Value is owned by the attribute; callers may read it but should not mutate
// it while sharing the attribute. | 对标准属性，Type 与 Value 携带 TLV 负载。对已解码的
// Vendor-Specific（类型 26）属性，VendorID 与 VendorType 标识子属性，Value 保存子属性值。
// Value 归属性所有；调用方可读取，但在共享属性时不应修改。
type Attribute struct {
	// Value is the attribute value; for vendor attributes it is the sub-attribute value. | Value
	// 是属性值；对厂商属性则是子属性值。
	Value []byte
	// VendorID is the vendor identifier for a Vendor-Specific sub-attribute. | VendorID 是
	// Vendor-Specific 子属性的厂商标识。
	VendorID uint32
	// Type is the attribute type number. | Type 是属性类型号。
	Type AttributeType
	// VendorType is the vendor sub-attribute type. | VendorType 是厂商子属性类型。
	VendorType uint8
	// raw marks an unparsed Vendor-Specific payload preserved verbatim in Value. | raw 标记
	// Value 中原样保留的未解析 Vendor-Specific 负载。
	raw bool
}

// NewAttribute returns an attribute with a copied value. | NewAttribute 返回带值副本的属性。
func NewAttribute(t AttributeType, value []byte) Attribute {
	return Attribute{Type: t, Value: append([]byte(nil), value...)}
}

// NewVendorAttribute returns a Vendor-Specific sub-attribute with a copied value. | NewVendorAttribute
// 返回带值副本的 Vendor-Specific 子属性。
func NewVendorAttribute(vendorID uint32, vendorType uint8, value []byte) Attribute {
	return Attribute{
		Type:       AttrVendorSpecific,
		Value:      append([]byte(nil), value...),
		VendorID:   vendorID,
		VendorType: vendorType,
	}
}

// IsVendor reports whether the attribute is a Vendor-Specific attribute. | IsVendor 报告属性是否为 Vendor-Specific。
func (a Attribute) IsVendor() bool {
	return a.Type == AttrVendorSpecific
}

// Bytes returns the raw attribute value without copying. | Bytes 返回属性原始值，不复制。
func (a Attribute) Bytes() []byte {
	return a.Value
}

// String returns the attribute value as a string. | String 以字符串返回属性值。
func (a Attribute) String() string {
	return string(a.Value)
}

// Uint32 decodes the value as a big-endian 32-bit integer. | Uint32 将值解码为大端 32 位整数。
func (a Attribute) Uint32() (uint32, bool) {
	if len(a.Value) != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(a.Value), true
}

// IPv4 decodes the value as an IPv4 address. | IPv4 将值解码为 IPv4 地址。
func (a Attribute) IPv4() (net.IP, bool) {
	if len(a.Value) != net.IPv4len {
		return nil, false
	}
	ip := make(net.IP, net.IPv4len)
	copy(ip, a.Value)
	return ip, true
}

// UnixTime decodes the value as seconds since the Unix epoch. | UnixTime 将值解码为 Unix 纪元以来的秒数。
func (a Attribute) UnixTime() (time.Time, bool) {
	sec, ok := a.Uint32()
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(sec), 0).UTC(), true
}

// TaggedUint32 decodes an RFC 2868 tagged 32-bit value. A four-octet value is untagged and
// reported with tag zero; a five-octet value carries a leading tag. | TaggedUint32 解码 RFC 2868
// 带标签的 32 位值。四字节值无标签并以标签零返回；五字节值带有前导标签。
func (a Attribute) TaggedUint32() (tag uint8, value uint32, ok bool) {
	switch len(a.Value) {
	case 4:
		return 0, binary.BigEndian.Uint32(a.Value), true
	case 5:
		return a.Value[0], binary.BigEndian.Uint32(a.Value[1:]), true
	default:
		return 0, 0, false
	}
}

// TaggedString decodes an RFC 2868 tagged string. A leading octet in the range 0x00-0x1F is
// treated as a tag; otherwise the whole value is untagged. | TaggedString 解码 RFC 2868 带标签
// 字符串。首位在 0x00-0x1F 范围内的字节视为标签；否则整个值无标签。
func (a Attribute) TaggedString() (tag uint8, value string) {
	if len(a.Value) > 1 && a.Value[0] <= 0x1f {
		return a.Value[0], string(a.Value[1:])
	}
	return 0, string(a.Value)
}

// Attributes is an ordered RADIUS attribute list. | Attributes 是有序的 RADIUS 属性列表。
type Attributes []Attribute

// Clone returns a deep copy of the attribute list. | Clone 返回属性列表的深拷贝。
func (a Attributes) Clone() Attributes {
	if a == nil {
		return nil
	}
	out := make(Attributes, len(a))
	for i, attr := range a {
		out[i] = Attribute{
			Type:       attr.Type,
			Value:      append([]byte(nil), attr.Value...),
			VendorID:   attr.VendorID,
			VendorType: attr.VendorType,
			raw:        attr.raw,
		}
	}
	return out
}

// Get returns the first attribute of type t. | Get 返回类型为 t 的第一个属性。
func (a Attributes) Get(t AttributeType) (Attribute, bool) {
	for _, attr := range a {
		if attr.Type == t {
			return attr, true
		}
	}
	return Attribute{}, false
}

// GetAll returns every attribute of type t in wire order. | GetAll 按线序返回类型为 t 的全部属性。
func (a Attributes) GetAll(t AttributeType) []Attribute {
	var out []Attribute
	for _, attr := range a {
		if attr.Type == t {
			out = append(out, attr)
		}
	}
	return out
}

// Strings returns every value of type t as a string. | Strings 返回类型为 t 的全部字符串值。
func (a Attributes) Strings(t AttributeType) []string {
	attrs := a.GetAll(t)
	if len(attrs) == 0 {
		return nil
	}
	out := make([]string, len(attrs))
	for i, attr := range attrs {
		out[i] = string(attr.Value)
	}
	return out
}

// Uint32 returns the first value of type t decoded as a big-endian integer. | Uint32 返回类型为 t
// 的第一个值，按大端整数解码。
func (a Attributes) Uint32(t AttributeType) (uint32, bool) {
	attr, ok := a.Get(t)
	if !ok {
		return 0, false
	}
	return attr.Uint32()
}

// IP returns the first value of type t decoded as an IPv4 address. | IP 返回类型为 t 的第一个值，
// 按 IPv4 地址解码。
func (a Attributes) IP(t AttributeType) (net.IP, bool) {
	attr, ok := a.Get(t)
	if !ok {
		return nil, false
	}
	return attr.IPv4()
}

// Vendor returns the first sub-attribute matching vendorID and vendorType. | Vendor 返回首个匹配
// vendorID 与 vendorType 的子属性。
func (a Attributes) Vendor(vendorID uint32, vendorType uint8) (Attribute, bool) {
	for _, attr := range a {
		if attr.Type == AttrVendorSpecific && attr.VendorID == vendorID && attr.VendorType == vendorType {
			return attr, true
		}
	}
	return Attribute{}, false
}

// VendorAll returns every sub-attribute matching vendorID and vendorType. | VendorAll 返回全部匹配
// vendorID 与 vendorType 的子属性。
func (a Attributes) VendorAll(vendorID uint32, vendorType uint8) []Attribute {
	var out []Attribute
	for _, attr := range a {
		if attr.Type == AttrVendorSpecific && attr.VendorID == vendorID && attr.VendorType == vendorType {
			out = append(out, attr)
		}
	}
	return out
}

// Add appends an attribute with a copied value. | Add 追加带值副本的属性。
func (a *Attributes) Add(t AttributeType, value []byte) {
	*a = append(*a, NewAttribute(t, value))
}

// AddString appends a string-valued attribute. | AddString 追加字符串值属性。
func (a *Attributes) AddString(t AttributeType, value string) {
	a.Add(t, []byte(value))
}

// AddUint32 appends a big-endian 32-bit integer attribute. | AddUint32 追加大端 32 位整数属性。
func (a *Attributes) AddUint32(t AttributeType, value uint32) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], value)
	a.Add(t, buf[:])
}

// AddIPv4 appends an IPv4 address attribute. | AddIPv4 追加 IPv4 地址属性。
func (a *Attributes) AddIPv4(t AttributeType, ip net.IP) error {
	v4 := ip.To4()
	if v4 == nil {
		return errs.Detail(ErrInvalidAttribute, "attribute %d requires an IPv4 address", uint8(t))
	}
	a.Add(t, v4)
	return nil
}

// AddVendor appends a Vendor-Specific sub-attribute with a copied value. | AddVendor 追加带值副本的
// Vendor-Specific 子属性。
func (a *Attributes) AddVendor(vendorID uint32, vendorType uint8, value []byte) {
	*a = append(*a, NewVendorAttribute(vendorID, vendorType, value))
}

// AddVendorString appends a string-valued vendor sub-attribute. | AddVendorString 追加字符串值的厂商子属性。
func (a *Attributes) AddVendorString(vendorID uint32, vendorType uint8, value string) {
	a.AddVendor(vendorID, vendorType, []byte(value))
}

// AddVendorUint32 appends a big-endian 32-bit vendor sub-attribute. | AddVendorUint32 追加大端
// 32 位整数的厂商子属性。
func (a *Attributes) AddVendorUint32(vendorID uint32, vendorType uint8, value uint32) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], value)
	a.AddVendor(vendorID, vendorType, buf[:])
}

// Remove deletes every attribute of type t. | Remove 删除类型为 t 的全部属性。
func (a *Attributes) Remove(t AttributeType) {
	out := (*a)[:0]
	for _, attr := range *a {
		if attr.Type != t {
			out = append(out, attr)
		}
	}
	*a = out
}

// Set replaces every attribute of type t with a single copied value. | Set 用单个值副本替换类型
// 为 t 的全部属性。
func (a *Attributes) Set(t AttributeType, value []byte) {
	a.Remove(t)
	a.Add(t, value)
}

// AddNamed appends an attribute identified by a dictionary name. Vendor attributes are added as
// Vendor-Specific sub-attributes. | AddNamed 追加由字典名称标识的属性。厂商属性以 Vendor-Specific
// 子属性追加。
func (a *Attributes) AddNamed(d *Dictionary, name string, value []byte) error {
	if d == nil {
		return errs.Detail(ErrInvalidAttribute, "dictionary is required for named attribute %q", name)
	}
	def, ok := d.Lookup(name)
	if !ok {
		return errs.Detail(ErrInvalidAttribute, "unknown attribute %q", name)
	}
	if def.VendorID != 0 {
		a.AddVendor(def.VendorID, def.VendorType, value)
		return nil
	}
	a.Add(def.Type, value)
	return nil
}

// Named returns the first attribute identified by a dictionary name. | Named 返回由字典名称标识的
// 第一个属性。
func (a Attributes) Named(d *Dictionary, name string) (Attribute, bool) {
	if d == nil {
		return Attribute{}, false
	}
	def, ok := d.Lookup(name)
	if !ok {
		return Attribute{}, false
	}
	if def.VendorID != 0 {
		return a.Vendor(def.VendorID, def.VendorType)
	}
	return a.Get(def.Type)
}
