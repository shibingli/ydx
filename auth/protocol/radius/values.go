package radius

import "strconv"

// ServiceType is the RFC 2865 Service-Type value. | ServiceType 是 RFC 2865 Service-Type 值。
type ServiceType uint32

// Service-Type values. | Service-Type 取值。
const (
	// ServiceTypeLogin requests a login service. | ServiceTypeLogin 请求登录服务。
	ServiceTypeLogin ServiceType = 1
	// ServiceTypeFramed requests a framed service. | ServiceTypeFramed 请求成帧服务。
	ServiceTypeFramed ServiceType = 2
	// ServiceTypeCallbackLogin requests callback login. | ServiceTypeCallbackLogin 请求回拨登录。
	ServiceTypeCallbackLogin ServiceType = 3
	// ServiceTypeCallbackFramed requests callback framed service. | ServiceTypeCallbackFramed 请求回拨成帧服务。
	ServiceTypeCallbackFramed ServiceType = 4
	// ServiceTypeOutbound requests an outbound service. | ServiceTypeOutbound 请求出站服务。
	ServiceTypeOutbound ServiceType = 5
	// ServiceTypeAdministrative requests administrative access. | ServiceTypeAdministrative 请求管理访问。
	ServiceTypeAdministrative ServiceType = 6
	// ServiceTypeNASPrompt requests a NAS prompt. | ServiceTypeNASPrompt 请求 NAS 提示符。
	ServiceTypeNASPrompt ServiceType = 7
	// ServiceTypeAuthenticateOnly requests authentication without authorization. | ServiceTypeAuthenticateOnly 仅请求认证而不授权。
	ServiceTypeAuthenticateOnly ServiceType = 8
	// ServiceTypeCallbackNASPrompt requests callback NAS prompt. | ServiceTypeCallbackNASPrompt 请求回拨 NAS 提示符。
	ServiceTypeCallbackNASPrompt ServiceType = 9
	// ServiceTypeCallCheck requests a call check. | ServiceTypeCallCheck 请求呼叫检查。
	ServiceTypeCallCheck ServiceType = 10
	// ServiceTypeCallbackAdministrative requests callback administrative access. | ServiceTypeCallbackAdministrative 请求回拨管理访问。
	ServiceTypeCallbackAdministrative ServiceType = 11
)

// FramedProtocol is the RFC 2865 Framed-Protocol value. | FramedProtocol 是 RFC 2865 Framed-Protocol 值。
type FramedProtocol uint32

// Framed-Protocol values. | Framed-Protocol 取值。
const (
	// FramedProtocolPPP selects PPP framing. | FramedProtocolPPP 选择 PPP 成帧。
	FramedProtocolPPP FramedProtocol = 1
	// FramedProtocolSLIP selects SLIP framing. | FramedProtocolSLIP 选择 SLIP 成帧。
	FramedProtocolSLIP FramedProtocol = 2
	// FramedProtocolARAP selects ARAP framing. | FramedProtocolARAP 选择 ARAP 成帧。
	FramedProtocolARAP FramedProtocol = 3
	// FramedProtocolGandalf selects Gandalf framing. | FramedProtocolGandalf 选择 Gandalf 成帧。
	FramedProtocolGandalf FramedProtocol = 4
	// FramedProtocolXylogicsIPXSLIP selects Xylogics IPX/SLIP framing. | FramedProtocolXylogicsIPXSLIP 选择 Xylogics IPX/SLIP 成帧。
	FramedProtocolXylogicsIPXSLIP FramedProtocol = 5
	// FramedProtocolX75Synchronous selects X.75 synchronous framing. | FramedProtocolX75Synchronous 选择 X.75 同步成帧。
	FramedProtocolX75Synchronous FramedProtocol = 6
)

// AcctStatusType is the RFC 2866 Acct-Status-Type value. | AcctStatusType 是 RFC 2866 Acct-Status-Type 值。
type AcctStatusType uint32

// Acct-Status-Type values. | Acct-Status-Type 取值。
const (
	// AcctStatusStart marks the start of a session. | AcctStatusStart 标记会话开始。
	AcctStatusStart AcctStatusType = 1
	// AcctStatusStop marks the end of a session. | AcctStatusStop 标记会话结束。
	AcctStatusStop AcctStatusType = 2
	// AcctStatusInterimUpdate marks an interim update. | AcctStatusInterimUpdate 标记中间更新。
	AcctStatusInterimUpdate AcctStatusType = 3
	// AcctStatusAccountingOn marks the NAS coming online. | AcctStatusAccountingOn 标记 NAS 上线。
	AcctStatusAccountingOn AcctStatusType = 7
	// AcctStatusAccountingOff marks the NAS going offline. | AcctStatusAccountingOff 标记 NAS 下线。
	AcctStatusAccountingOff AcctStatusType = 8
)

// AcctAuthentic is the RFC 2866 Acct-Authentic value. | AcctAuthentic 是 RFC 2866 Acct-Authentic 值。
type AcctAuthentic uint32

// Acct-Authentic values. | Acct-Authentic 取值。
const (
	// AcctAuthenticRADIUS reports RADIUS authentication. | AcctAuthenticRADIUS 表示 RADIUS 认证。
	AcctAuthenticRADIUS AcctAuthentic = 1
	// AcctAuthenticLocal reports local authentication. | AcctAuthenticLocal 表示本地认证。
	AcctAuthenticLocal AcctAuthentic = 2
	// AcctAuthenticRemote reports remote authentication. | AcctAuthenticRemote 表示远程认证。
	AcctAuthenticRemote AcctAuthentic = 3
)

// AcctTerminateCause is the RFC 2866 Acct-Terminate-Cause value. | AcctTerminateCause 是 RFC 2866 Acct-Terminate-Cause 值。
type AcctTerminateCause uint32

// Acct-Terminate-Cause values. | Acct-Terminate-Cause 取值。
const (
	// AcctTerminateUserRequest reports a user-requested termination. | AcctTerminateUserRequest 表示用户请求终止。
	AcctTerminateUserRequest AcctTerminateCause = 1
	// AcctTerminateLostCarrier reports a lost carrier. | AcctTerminateLostCarrier 表示载波丢失。
	AcctTerminateLostCarrier AcctTerminateCause = 2
	// AcctTerminateLostService reports a lost service. | AcctTerminateLostService 表示服务丢失。
	AcctTerminateLostService AcctTerminateCause = 3
	// AcctTerminateIdleTimeout reports an idle timeout. | AcctTerminateIdleTimeout 表示空闲超时。
	AcctTerminateIdleTimeout AcctTerminateCause = 4
	// AcctTerminateSessionTimeout reports a session timeout. | AcctTerminateSessionTimeout 表示会话超时。
	AcctTerminateSessionTimeout AcctTerminateCause = 5
	// AcctTerminateAdminReset reports an administrative reset. | AcctTerminateAdminReset 表示管理重置。
	AcctTerminateAdminReset AcctTerminateCause = 6
	// AcctTerminateAdminReboot reports an administrative reboot. | AcctTerminateAdminReboot 表示管理重启。
	AcctTerminateAdminReboot AcctTerminateCause = 7
	// AcctTerminatePortError reports a port error. | AcctTerminatePortError 表示端口错误。
	AcctTerminatePortError AcctTerminateCause = 8
	// AcctTerminateNASError reports a NAS error. | AcctTerminateNASError 表示 NAS 错误。
	AcctTerminateNASError AcctTerminateCause = 9
	// AcctTerminateNASRequest reports a NAS-requested termination. | AcctTerminateNASRequest 表示 NAS 请求终止。
	AcctTerminateNASRequest AcctTerminateCause = 10
	// AcctTerminateNASReboot reports a NAS reboot. | AcctTerminateNASReboot 表示 NAS 重启。
	AcctTerminateNASReboot AcctTerminateCause = 11
	// AcctTerminatePortUnneeded reports an unneeded port. | AcctTerminatePortUnneeded 表示端口不再需要。
	AcctTerminatePortUnneeded AcctTerminateCause = 12
	// AcctTerminatePortPreempted reports a preempted port. | AcctTerminatePortPreempted 表示端口被抢占。
	AcctTerminatePortPreempted AcctTerminateCause = 13
	// AcctTerminatePortSuspended reports a suspended port. | AcctTerminatePortSuspended 表示端口被挂起。
	AcctTerminatePortSuspended AcctTerminateCause = 14
	// AcctTerminateServiceUnavailable reports an unavailable service. | AcctTerminateServiceUnavailable 表示服务不可用。
	AcctTerminateServiceUnavailable AcctTerminateCause = 15
	// AcctTerminateCallback reports a callback termination. | AcctTerminateCallback 表示回拨终止。
	AcctTerminateCallback AcctTerminateCause = 16
	// AcctTerminateUserError reports a user error. | AcctTerminateUserError 表示用户错误。
	AcctTerminateUserError AcctTerminateCause = 17
	// AcctTerminateHostRequest reports a host-requested termination. | AcctTerminateHostRequest 表示主机请求终止。
	AcctTerminateHostRequest AcctTerminateCause = 18
)

// NASPortType is the RFC 2865 NAS-Port-Type value. | NASPortType 是 RFC 2865 NAS-Port-Type 值。
type NASPortType uint32

// NAS-Port-Type values. | NAS-Port-Type 取值。
const (
	// NASPortTypeAsync is an asynchronous port. | NASPortTypeAsync 是异步端口。
	NASPortTypeAsync NASPortType = 0
	// NASPortTypeSync is a synchronous port. | NASPortTypeSync 是同步端口。
	NASPortTypeSync NASPortType = 1
	// NASPortTypeISDNSync is a synchronous ISDN port. | NASPortTypeISDNSync 是同步 ISDN 端口。
	NASPortTypeISDNSync NASPortType = 2
	// NASPortTypeISDNAsyncV120 is an ISDN V.120 port. | NASPortTypeISDNAsyncV120 是 ISDN V.120 端口。
	NASPortTypeISDNAsyncV120 NASPortType = 3
	// NASPortTypeISDNAsyncV110 is an ISDN V.110 port. | NASPortTypeISDNAsyncV110 是 ISDN V.110 端口。
	NASPortTypeISDNAsyncV110 NASPortType = 4
	// NASPortTypeVirtual is a virtual port. | NASPortTypeVirtual 是虚拟端口。
	NASPortTypeVirtual NASPortType = 5
	// NASPortTypePIAFS is a PIAFS port. | NASPortTypePIAFS 是 PIAFS 端口。
	NASPortTypePIAFS NASPortType = 6
	// NASPortTypeHDLCClearChannel is an HDLC clear-channel port. | NASPortTypeHDLCClearChannel 是 HDLC 清信道端口。
	NASPortTypeHDLCClearChannel NASPortType = 7
	// NASPortTypeX25 is an X.25 port. | NASPortTypeX25 是 X.25 端口。
	NASPortTypeX25 NASPortType = 8
	// NASPortTypeX75 is an X.75 port. | NASPortTypeX75 是 X.75 端口。
	NASPortTypeX75 NASPortType = 9
	// NASPortTypeG3Fax is a G.3 fax port. | NASPortTypeG3Fax 是 G.3 传真端口。
	NASPortTypeG3Fax NASPortType = 10
	// NASPortTypeSDSL is an SDSL port. | NASPortTypeSDSL 是 SDSL 端口。
	NASPortTypeSDSL NASPortType = 11
	// NASPortTypeADSLDCAP is an ADSL CAP port. | NASPortTypeADSLDCAP 是 ADSL CAP 端口。
	NASPortTypeADSLDCAP NASPortType = 12
	// NASPortTypeADSLDDMT is an ADSL DMT port. | NASPortTypeADSLDDMT 是 ADSL DMT 端口。
	NASPortTypeADSLDDMT NASPortType = 13
	// NASPortTypeIDSL is an IDSL port. | NASPortTypeIDSL 是 IDSL 端口。
	NASPortTypeIDSL NASPortType = 14
	// NASPortTypeEthernet is an Ethernet port. | NASPortTypeEthernet 是以太网端口。
	NASPortTypeEthernet NASPortType = 15
	// NASPortTypeXDSL is an xDSL port. | NASPortTypeXDSL 是 xDSL 端口。
	NASPortTypeXDSL NASPortType = 16
	// NASPortTypeCable is a cable modem port. | NASPortTypeCable 是电缆调制解调器端口。
	NASPortTypeCable NASPortType = 17
	// NASPortTypeWirelessOther is another wireless port. | NASPortTypeWirelessOther 是其它无线端口。
	NASPortTypeWirelessOther NASPortType = 18
	// NASPortTypeWirelessIEEE80211 is an IEEE 802.11 wireless port. | NASPortTypeWirelessIEEE80211 是 IEEE 802.11 无线端口。
	NASPortTypeWirelessIEEE80211 NASPortType = 19
)

// TunnelType is the RFC 2868 Tunnel-Type value. | TunnelType 是 RFC 2868 Tunnel-Type 值。
type TunnelType uint32

// Tunnel-Type values. | Tunnel-Type 取值。
const (
	// TunnelTypePPTP is PPTP. | TunnelTypePPTP 是 PPTP。
	TunnelTypePPTP TunnelType = 1
	// TunnelTypeL2F is L2F. | TunnelTypeL2F 是 L2F。
	TunnelTypeL2F TunnelType = 2
	// TunnelTypeL2TP is L2TP. | TunnelTypeL2TP 是 L2TP。
	TunnelTypeL2TP TunnelType = 3
	// TunnelTypeATMP is ATMP. | TunnelTypeATMP 是 ATMP。
	TunnelTypeATMP TunnelType = 4
	// TunnelTypeVTP is VTP. | TunnelTypeVTP 是 VTP。
	TunnelTypeVTP TunnelType = 5
	// TunnelTypeAH is AH. | TunnelTypeAH 是 AH。
	TunnelTypeAH TunnelType = 6
	// TunnelTypeIPIP is IP-in-IP. | TunnelTypeIPIP 是 IP-in-IP。
	TunnelTypeIPIP TunnelType = 7
	// TunnelTypeMINIPIP is MIN-IP-IP. | TunnelTypeMINIPIP 是 MIN-IP-IP。
	TunnelTypeMINIPIP TunnelType = 8
	// TunnelTypeESP is ESP. | TunnelTypeESP 是 ESP。
	TunnelTypeESP TunnelType = 9
	// TunnelTypeGRE is GRE. | TunnelTypeGRE 是 GRE。
	TunnelTypeGRE TunnelType = 10
	// TunnelTypeDVS is DVS. | TunnelTypeDVS 是 DVS。
	TunnelTypeDVS TunnelType = 11
	// TunnelTypeIPInIP is IP-in-IP tunneling. | TunnelTypeIPInIP 是 IP-in-IP 隧道。
	TunnelTypeIPInIP TunnelType = 12
	// TunnelTypeVLAN is VLAN. | TunnelTypeVLAN 是 VLAN。
	TunnelTypeVLAN TunnelType = 13
)

// TunnelMediumType is the RFC 2868 Tunnel-Medium-Type value. | TunnelMediumType 是 RFC 2868 Tunnel-Medium-Type 值。
type TunnelMediumType uint32

// Tunnel-Medium-Type values. | Tunnel-Medium-Type 取值。
const (
	// TunnelMediumIPv4 is IPv4. | TunnelMediumIPv4 是 IPv4。
	TunnelMediumIPv4 TunnelMediumType = 1
	// TunnelMediumIPv6 is IPv6. | TunnelMediumIPv6 是 IPv6。
	TunnelMediumIPv6 TunnelMediumType = 2
	// TunnelMediumNSAP is NSAP. | TunnelMediumNSAP 是 NSAP。
	TunnelMediumNSAP TunnelMediumType = 3
	// TunnelMediumHDLC is HDLC. | TunnelMediumHDLC 是 HDLC。
	TunnelMediumHDLC TunnelMediumType = 4
	// TunnelMediumBBN1822 is BBN 1822. | TunnelMediumBBN1822 是 BBN 1822。
	TunnelMediumBBN1822 TunnelMediumType = 5
	// TunnelMediumIEEE802 is IEEE 802. | TunnelMediumIEEE802 是 IEEE 802。
	TunnelMediumIEEE802 TunnelMediumType = 6
	// TunnelMediumE163 is E.163. | TunnelMediumE163 是 E.163。
	TunnelMediumE163 TunnelMediumType = 7
	// TunnelMediumE164 is E.164. | TunnelMediumE164 是 E.164。
	TunnelMediumE164 TunnelMediumType = 8
	// TunnelMediumF69 is F.69. | TunnelMediumF69 是 F.69。
	TunnelMediumF69 TunnelMediumType = 9
	// TunnelMediumX121 is X.121. | TunnelMediumX121 是 X.121。
	TunnelMediumX121 TunnelMediumType = 10
	// TunnelMediumIPX is IPX. | TunnelMediumIPX 是 IPX。
	TunnelMediumIPX TunnelMediumType = 11
	// TunnelMediumAppletalk is AppleTalk. | TunnelMediumAppletalk 是 AppleTalk。
	TunnelMediumAppletalk TunnelMediumType = 12
	// TunnelMediumDecnetIV is DECnet IV. | TunnelMediumDecnetIV 是 DECnet IV。
	TunnelMediumDecnetIV TunnelMediumType = 13
	// TunnelMediumBanyanVines is Banyan Vines. | TunnelMediumBanyanVines 是 Banyan Vines。
	TunnelMediumBanyanVines TunnelMediumType = 14
	// TunnelMediumE164NSAP is E.164 with NSAP. | TunnelMediumE164NSAP 是带 NSAP 的 E.164。
	TunnelMediumE164NSAP TunnelMediumType = 15
)

// TerminationAction is the RFC 2865 Termination-Action value. | TerminationAction 是 RFC 2865 Termination-Action 值。
type TerminationAction uint32

// Termination-Action values. | Termination-Action 取值。
const (
	// TerminationActionDefault terminates the session. | TerminationActionDefault 终止会话。
	TerminationActionDefault TerminationAction = 0
	// TerminationActionRADIUSRequest lets the server decide at session end. | TerminationActionRADIUSRequest 由服务器在会话结束时决定。
	TerminationActionRADIUSRequest TerminationAction = 1
)

// ErrorCause is the RFC 5176 Error-Cause value carried by a CoA-NAK or Disconnect-NAK. | ErrorCause
// 是 CoA-NAK 或 Disconnect-NAK 携带的 RFC 5176 Error-Cause 值。
type ErrorCause uint32

// Error-Cause values assigned by RFC 5176 section 3.5. | RFC 5176 第 3.5 节分配的 Error-Cause 取值。
const (
	// ErrorCauseResidualSessionContextRemoved reports a Disconnect-ACK that removed residual context.
	// | ErrorCauseResidualSessionContextRemoved 表示 Disconnect-ACK 清除了残留上下文。
	ErrorCauseResidualSessionContextRemoved ErrorCause = 201
	// ErrorCauseInvalidEAPPacket reports an ignored invalid EAP packet. RFC 5176 forbids sending it.
	// | ErrorCauseInvalidEAPPacket 表示被忽略的非法 EAP 报文。RFC 5176 禁止发送该值。
	ErrorCauseInvalidEAPPacket ErrorCause = 202
	// ErrorCauseUnsupportedAttribute reports an unsupported attribute. | ErrorCauseUnsupportedAttribute
	// 表示不支持的属性。
	ErrorCauseUnsupportedAttribute ErrorCause = 401
	// ErrorCauseMissingAttribute reports a missing attribute. | ErrorCauseMissingAttribute 表示缺少属性。
	ErrorCauseMissingAttribute ErrorCause = 402
	// ErrorCauseNASIdentificationMismatch reports a NAS identification mismatch. |
	// ErrorCauseNASIdentificationMismatch 表示 NAS 标识不匹配。
	ErrorCauseNASIdentificationMismatch ErrorCause = 403
	// ErrorCauseInvalidRequest reports an invalid request. | ErrorCauseInvalidRequest 表示请求非法。
	ErrorCauseInvalidRequest ErrorCause = 404
	// ErrorCauseUnsupportedService reports an unsupported service. | ErrorCauseUnsupportedService
	// 表示不支持的服务。
	ErrorCauseUnsupportedService ErrorCause = 405
	// ErrorCauseUnsupportedExtension reports an unsupported extension. | ErrorCauseUnsupportedExtension
	// 表示不支持的扩展。
	ErrorCauseUnsupportedExtension ErrorCause = 406
	// ErrorCauseInvalidAttributeValue reports an invalid attribute value. |
	// ErrorCauseInvalidAttributeValue 表示属性值非法。
	ErrorCauseInvalidAttributeValue ErrorCause = 407
	// ErrorCauseAdministrativelyProhibited reports an administrative prohibition. |
	// ErrorCauseAdministrativelyProhibited 表示管理上禁止。
	ErrorCauseAdministrativelyProhibited ErrorCause = 501
	// ErrorCauseRequestNotRoutable reports that a proxy could not route the request. |
	// ErrorCauseRequestNotRoutable 表示代理无法路由请求。
	ErrorCauseRequestNotRoutable ErrorCause = 502
	// ErrorCauseSessionContextNotFound reports that the session does not exist. |
	// ErrorCauseSessionContextNotFound 表示会话不存在。
	ErrorCauseSessionContextNotFound ErrorCause = 503
	// ErrorCauseSessionContextNotRemovable reports that the session cannot be removed. |
	// ErrorCauseSessionContextNotRemovable 表示会话无法移除。
	ErrorCauseSessionContextNotRemovable ErrorCause = 504
	// ErrorCauseOtherProxyProcessingError reports another proxy processing error. |
	// ErrorCauseOtherProxyProcessingError 表示其它代理处理错误。
	ErrorCauseOtherProxyProcessingError ErrorCause = 505
	// ErrorCauseResourcesUnavailable reports unavailable resources. | ErrorCauseResourcesUnavailable
	// 表示资源不可用。
	ErrorCauseResourcesUnavailable ErrorCause = 506
	// ErrorCauseRequestInitiated reports that the request was initiated. | ErrorCauseRequestInitiated
	// 表示请求已发起。
	ErrorCauseRequestInitiated ErrorCause = 507
	// ErrorCauseMultipleSessionSelectionUnsupported reports that selecting multiple sessions is not
	// supported. | ErrorCauseMultipleSessionSelectionUnsupported 表示不支持选择多个会话。
	ErrorCauseMultipleSessionSelectionUnsupported ErrorCause = 508
)

// String returns the RFC 5176 name of the Error-Cause value, or its decimal form when unassigned.
// | String 返回 Error-Cause 值的 RFC 5176 名称；未分配时返回十进制形式。
func (e ErrorCause) String() string {
	switch e {
	case ErrorCauseResidualSessionContextRemoved:
		return "Residual Session Context Removed"
	case ErrorCauseInvalidEAPPacket:
		return "Invalid EAP Packet (Ignored)"
	case ErrorCauseUnsupportedAttribute:
		return "Unsupported Attribute"
	case ErrorCauseMissingAttribute:
		return "Missing Attribute"
	case ErrorCauseNASIdentificationMismatch:
		return "NAS Identification Mismatch"
	case ErrorCauseInvalidRequest:
		return "Invalid Request"
	case ErrorCauseUnsupportedService:
		return "Unsupported Service"
	case ErrorCauseUnsupportedExtension:
		return "Unsupported Extension"
	case ErrorCauseInvalidAttributeValue:
		return "Invalid Attribute Value"
	case ErrorCauseAdministrativelyProhibited:
		return "Administratively Prohibited"
	case ErrorCauseRequestNotRoutable:
		return "Request Not Routable (Proxy)"
	case ErrorCauseSessionContextNotFound:
		return "Session Context Not Found"
	case ErrorCauseSessionContextNotRemovable:
		return "Session Context Not Removable"
	case ErrorCauseOtherProxyProcessingError:
		return "Other Proxy Processing Error"
	case ErrorCauseResourcesUnavailable:
		return "Resources Unavailable"
	case ErrorCauseRequestInitiated:
		return "Request Initiated"
	case ErrorCauseMultipleSessionSelectionUnsupported:
		return "Multiple Session Selection Unsupported"
	default:
		return strconv.FormatUint(uint64(e), 10)
	}
}
