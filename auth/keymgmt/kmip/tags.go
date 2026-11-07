package kmip

import "strings"

// Tag is a 24-bit KMIP TTLV tag. | Tag 是 24 位 KMIP TTLV 标签。
type Tag uint32

// The KMIP tags used by this package. Values are the OASIS-assigned tag numbers. | 本包使用的 KMIP 标签；取值为 OASIS 分配的标签号。
const (
	TagActivationDate                        Tag = 0x420001 // Activation Date | 激活日期
	TagApplicationData                       Tag = 0x420002 // Application Data | 应用数据
	TagApplicationNamespace                  Tag = 0x420003 // Application Namespace | 应用命名空间
	TagApplicationSpecificInformation        Tag = 0x420004 // Application Specific Information | 应用特定信息
	TagArchiveDate                           Tag = 0x420005 // Archive Date | 归档日期
	TagAsynchronousCorrelationValue          Tag = 0x420006 // Asynchronous Correlation Value | 异步关联值
	TagAsynchronousIndicator                 Tag = 0x420007 // Asynchronous Indicator | 异步指示
	TagAttribute                             Tag = 0x420008 // Attribute | 属性
	TagAttributeIndex                        Tag = 0x420009 // Attribute Index | 属性索引
	TagAttributeName                         Tag = 0x42000A // Attribute Name | 属性名
	TagAttributeValue                        Tag = 0x42000B // Attribute Value | 属性值
	TagAuthentication                        Tag = 0x42000C // Authentication | 认证
	TagBatchCount                            Tag = 0x42000D // Batch Count | 批处理计数
	TagBatchErrorContinuationOption          Tag = 0x42000E // Batch Error Continuation Option | 批处理错误继续选项
	TagBatchItem                             Tag = 0x42000F // Batch Item | 批处理项
	TagBatchOrderOption                      Tag = 0x420010 // Batch Order Option | 批处理顺序选项
	TagBlockCipherMode                       Tag = 0x420011 // Block Cipher Mode | 分组密码模式
	TagCancellationResult                    Tag = 0x420012 // Cancellation Result | 取消结果
	TagCertificate                           Tag = 0x420013 // Certificate | 证书
	TagCertificateRequest                    Tag = 0x420018 // Certificate Request | 证书请求
	TagCertificateRequestType                Tag = 0x420019 // Certificate Request Type | 证书请求类型
	TagCertificateType                       Tag = 0x42001D // Certificate Type | 证书类型
	TagCertificateValue                      Tag = 0x42001E // Certificate Value | 证书值
	TagCommonTemplateAttribute               Tag = 0x42001F // Common Template-Attribute | 公共模板属性
	TagCompromiseDate                        Tag = 0x420020 // Compromise Date | 泄露日期
	TagCompromiseOccurrenceDate              Tag = 0x420021 // Compromise Occurrence Date | 泄露发生日期
	TagContactInformation                    Tag = 0x420022 // Contact Information | 联系信息
	TagCredential                            Tag = 0x420023 // Credential | 凭据
	TagCredentialType                        Tag = 0x420024 // Credential Type | 凭据类型
	TagCredentialValue                       Tag = 0x420025 // Credential Value | 凭据值
	TagCriticalityIndicator                  Tag = 0x420026 // Criticality Indicator | 关键性指示
	TagCRTCoefficient                        Tag = 0x420027 // CRT Coefficient | CRT 系数
	TagCryptographicAlgorithm                Tag = 0x420028 // Cryptographic Algorithm | 密码算法
	TagCryptographicDomainParameters         Tag = 0x420029 // Cryptographic Domain Parameters | 密码域参数
	TagCryptographicLength                   Tag = 0x42002A // Cryptographic Length | 密码长度
	TagCryptographicParameters               Tag = 0x42002B // Cryptographic Parameters | 密码参数
	TagCryptographicUsageMask                Tag = 0x42002C // Cryptographic Usage Mask | 密码学用法掩码
	TagCustomAttribute                       Tag = 0x42002D // Custom Attribute | 自定义属性
	TagD                                     Tag = 0x42002E // D (private scalar) | D（私钥标量）
	TagDeactivationDate                      Tag = 0x42002F // Deactivation Date | 停用日期
	TagDerivationData                        Tag = 0x420030 // Derivation Data | 派生数据
	TagDerivationMethod                      Tag = 0x420031 // Derivation Method | 派生方法
	TagDerivationParameters                  Tag = 0x420032 // Derivation Parameters | 派生参数
	TagDestroyDate                           Tag = 0x420033 // Destroy Date | 销毁日期
	TagDigest                                Tag = 0x420034 // Digest | 摘要
	TagDigestValue                           Tag = 0x420035 // Digest Value | 摘要值
	TagEncryptionKeyInformation              Tag = 0x420036 // Encryption Key Information | 加密密钥信息
	TagG                                     Tag = 0x420037 // G (base point) | G（基点）
	TagHashingAlgorithm                      Tag = 0x420038 // Hashing Algorithm | 哈希算法
	TagInitialDate                           Tag = 0x420039 // Initial Date | 初始日期
	TagInitializationVector                  Tag = 0x42003A // Initialization Vector | 初始化向量
	TagIterationCount                        Tag = 0x42003C // Iteration Count | 迭代次数
	TagIVCounterNonce                        Tag = 0x42003D // IV/Counter/Nonce | IV/计数器/随机数
	TagJ                                     Tag = 0x42003E // J (cofactor) | J（余因子）
	TagKey                                   Tag = 0x42003F // Key (transparent key bytes) | Key（透明密钥字节）
	TagKeyBlock                              Tag = 0x420040 // Key Block | 密钥块
	TagKeyCompressionType                    Tag = 0x420041 // Key Compression Type | 密钥压缩类型
	TagKeyFormatType                         Tag = 0x420042 // Key Format Type | 密钥格式类型
	TagKeyMaterial                           Tag = 0x420043 // Key Material | 密钥材料
	TagKeyPartIdentifier                     Tag = 0x420044 // Key Part Identifier | 密钥部分标识
	TagKeyValue                              Tag = 0x420045 // Key Value | 密钥值
	TagKeyWrappingData                       Tag = 0x420046 // Key Wrapping Data | 密钥封装数据
	TagKeyWrappingSpecification              Tag = 0x420047 // Key Wrapping Specification | 密钥封装规格
	TagLastChangeDate                        Tag = 0x420048 // Last Change Date | 最后变更日期
	TagLeaseTime                             Tag = 0x420049 // Lease Time | 租用时间
	TagLink                                  Tag = 0x42004A // Link | 链接
	TagLinkType                              Tag = 0x42004B // Link Type | 链接类型
	TagLinkedObjectIdentifier                Tag = 0x42004C // Linked Object Identifier | 链接对象标识符
	TagMACSignature                          Tag = 0x42004D // MAC/Signature | MAC/签名
	TagMACSignatureKeyInformation            Tag = 0x42004E // MAC/Signature Key Information | MAC/签名密钥信息
	TagMaximumItems                          Tag = 0x42004F // Maximum Items | 最大项数
	TagMaximumResponseSize                   Tag = 0x420050 // Maximum Response Size | 最大响应长度
	TagMessageExtension                      Tag = 0x420051 // Message Extension | 消息扩展
	TagModulus                               Tag = 0x420052 // Modulus | 模数
	TagName                                  Tag = 0x420053 // Name | 名称
	TagNameType                              Tag = 0x420054 // Name Type | 名称类型
	TagNameValue                             Tag = 0x420055 // Name Value | 名称值
	TagObjectGroup                           Tag = 0x420056 // Object Group | 对象组
	TagObjectType                            Tag = 0x420057 // Object Type | 对象类型
	TagOffset                                Tag = 0x420058 // Offset | 偏移
	TagOpaqueDataType                        Tag = 0x420059 // Opaque Data Type | 不透明数据类型
	TagOpaqueDataValue                       Tag = 0x42005A // Opaque Data Value | 不透明数据值
	TagOpaqueObject                          Tag = 0x42005B // Opaque Object | 不透明对象
	TagOperation                             Tag = 0x42005C // Operation | 操作
	TagOperationPolicyName                   Tag = 0x42005D // Operation Policy Name | 操作策略名称
	TagP                                     Tag = 0x42005E // P (prime) | P（素数）
	TagPaddingMethod                         Tag = 0x42005F // Padding Method | 填充方法
	TagPrimeExponentP                        Tag = 0x420060 // Prime Exponent P | 素指数 P
	TagPrimeExponentQ                        Tag = 0x420061 // Prime Exponent Q | 素指数 Q
	TagPrimeFieldSize                        Tag = 0x420062 // Prime Field Size | 素域大小
	TagPrivateExponent                       Tag = 0x420063 // Private Exponent | 私有指数
	TagPrivateKey                            Tag = 0x420064 // Private Key | 私钥
	TagPrivateKeyTemplateAttribute           Tag = 0x420065 // Private Key Template-Attribute | 私钥模板属性
	TagPrivateKeyUniqueIdentifier            Tag = 0x420066 // Private Key Unique Identifier | 私钥唯一标识符
	TagProcessStartDate                      Tag = 0x420067 // Process Start Date | 处理开始日期
	TagProtectStopDate                       Tag = 0x420068 // Protect Stop Date | 保护停止日期
	TagProtocolVersion                       Tag = 0x420069 // Protocol Version | 协议版本
	TagProtocolVersionMajor                  Tag = 0x42006A // Protocol Version Major | 协议主版本
	TagProtocolVersionMinor                  Tag = 0x42006B // Protocol Version Minor | 协议次版本
	TagPublicExponent                        Tag = 0x42006C // Public Exponent | 公开指数
	TagPublicKey                             Tag = 0x42006D // Public Key | 公钥
	TagPublicKeyTemplateAttribute            Tag = 0x42006E // Public Key Template-Attribute | 公钥模板属性
	TagPublicKeyUniqueIdentifier             Tag = 0x42006F // Public Key Unique Identifier | 公钥唯一标识符
	TagPutFunction                           Tag = 0x420070 // Put Function | Put 功能
	TagQ                                     Tag = 0x420071 // Q (prime) | Q（素数）
	TagQString                               Tag = 0x420072 // Q String (EC point) | Q 字符串（椭圆曲线点）
	TagQlength                               Tag = 0x420073 // Q Length | Q 长度
	TagQueryFunction                         Tag = 0x420074 // Query Function | 查询功能
	TagRecommendedCurve                      Tag = 0x420075 // Recommended Curve | 推荐曲线
	TagReplacedUniqueIdentifier              Tag = 0x420076 // Replaced Unique Identifier | 被替换的唯一标识符
	TagRequestHeader                         Tag = 0x420077 // Request Header | 请求头
	TagRequestMessage                        Tag = 0x420078 // Request Message | 请求消息
	TagRequestPayload                        Tag = 0x420079 // Request Payload | 请求负载
	TagResponseHeader                        Tag = 0x42007A // Response Header | 响应头
	TagResponseMessage                       Tag = 0x42007B // Response Message | 响应消息
	TagResponsePayload                       Tag = 0x42007C // Response Payload | 响应负载
	TagResultMessage                         Tag = 0x42007D // Result Message | 结果消息
	TagResultReason                          Tag = 0x42007E // Result Reason | 结果原因
	TagResultStatus                          Tag = 0x42007F // Result Status | 结果状态
	TagRevocationMessage                     Tag = 0x420080 // Revocation Message | 撤销消息
	TagRevocationReason                      Tag = 0x420081 // Revocation Reason | 撤销原因
	TagRevocationReasonCode                  Tag = 0x420082 // Revocation Reason Code | 撤销原因代码
	TagKeyRoleType                           Tag = 0x420083 // Key Role Type | 密钥角色类型
	TagSalt                                  Tag = 0x420084 // Salt | 盐值
	TagSecretData                            Tag = 0x420085 // Secret Data | 秘密数据
	TagSecretDataType                        Tag = 0x420086 // Secret Data Type | 秘密数据类型
	TagServerInformation                     Tag = 0x420088 // Server Information | 服务器信息
	TagSplitKey                              Tag = 0x420089 // Split Key | 分割密钥
	TagSplitKeyMethod                        Tag = 0x42008A // Split Key Method | 分割密钥方法
	TagSplitKeyParts                         Tag = 0x42008B // Split Key Parts | 分割密钥部分数
	TagSplitKeyThreshold                     Tag = 0x42008C // Split Key Threshold | 分割密钥阈值
	TagState                                 Tag = 0x42008D // State | 状态
	TagStorageStatusMask                     Tag = 0x42008E // Storage Status Mask | 存储状态掩码
	TagSymmetricKey                          Tag = 0x42008F // Symmetric Key | 对称密钥
	TagTemplate                              Tag = 0x420090 // Template | 模板
	TagTemplateAttribute                     Tag = 0x420091 // Template-Attribute | 模板属性
	TagTimeStamp                             Tag = 0x420092 // Time Stamp | 时间戳
	TagUniqueBatchItemID                     Tag = 0x420093 // Unique Batch Item ID | 批处理项唯一标识
	TagUniqueIdentifier                      Tag = 0x420094 // Unique Identifier | 唯一标识符
	TagUsageLimits                           Tag = 0x420095 // Usage Limits | 使用限制
	TagUsageLimitsCount                      Tag = 0x420096 // Usage Limits Count | 使用限制计数
	TagUsageLimitsTotal                      Tag = 0x420097 // Usage Limits Total | 使用限制总量
	TagUsageLimitsUnit                       Tag = 0x420098 // Usage Limits Unit | 使用限制单位
	TagUsername                              Tag = 0x420099 // Username | 用户名
	TagValidityDate                          Tag = 0x42009A // Validity Date | 有效期
	TagValidityIndicator                     Tag = 0x42009B // Validity Indicator | 有效性指示
	TagVendorExtension                       Tag = 0x42009C // Vendor Extension | 厂商扩展
	TagVendorIdentification                  Tag = 0x42009D // Vendor Identification | 厂商标识
	TagWrappingMethod                        Tag = 0x42009E // Wrapping Method | 封装方法
	TagX                                     Tag = 0x42009F // X coordinate | X 坐标
	TagY                                     Tag = 0x4200A0 // Y coordinate | Y 坐标
	TagPassword                              Tag = 0x4200A1 // Password | 口令
	TagDeviceIdentifier                      Tag = 0x4200A2 // Device Identifier | 设备标识符
	TagEncodingOption                        Tag = 0x4200A3 // Encoding Option | 编码选项
	TagExtensionInformation                  Tag = 0x4200A4 // Extension Information | 扩展信息
	TagExtensionName                         Tag = 0x4200A5 // Extension Name | 扩展名
	TagExtensionTag                          Tag = 0x4200A6 // Extension Tag | 扩展标签
	TagExtensionType                         Tag = 0x4200A7 // Extension Type | 扩展类型
	TagFresh                                 Tag = 0x4200A8 // Fresh | 新鲜
	TagMachineIdentifier                     Tag = 0x4200A9 // Machine Identifier | 机器标识
	TagMediaIdentifier                       Tag = 0x4200AA // Media Identifier | 介质标识
	TagNetworkIdentifier                     Tag = 0x4200AB // Network Identifier | 网络标识
	TagObjectGroupMember                     Tag = 0x4200AC // Object Group Member | 对象组成员
	TagCertificateLength                     Tag = 0x4200AD // Certificate Length | 证书长度
	TagDigitalSignatureAlgorithm             Tag = 0x4200AE // Digital Signature Algorithm | 数字签名算法
	TagKeyValueLocation                      Tag = 0x4200B8 // Key Value Location | 密钥值位置
	TagOriginalCreationDate                  Tag = 0x4200BC // Original Creation Date | 原始创建日期
	TagAlternativeName                       Tag = 0x4200BF // Alternative Name | 替代名称
	TagData                                  Tag = 0x4200C2 // Data | 数据
	TagSignatureData                         Tag = 0x4200C3 // Signature Data | 签名数据
	TagDataLength                            Tag = 0x4200C4 // Data Length | 数据长度
	TagRandomIV                              Tag = 0x4200C5 // Random IV | 随机 IV
	TagMACData                               Tag = 0x4200C6 // MAC Data | MAC 数据
	TagIVLength                              Tag = 0x4200CD // IV Length | IV 长度
	TagTagLength                             Tag = 0x4200CE // Tag Length | 标签长度
	TagFixedFieldLength                      Tag = 0x4200CF // Fixed Field Length | 固定字段长度
	TagCounterLength                         Tag = 0x4200D0 // Counter Length | 计数器长度
	TagInitialCounterValue                   Tag = 0x4200D1 // Initial Counter Value | 初始计数器值
	TagInvocationFieldLength                 Tag = 0x4200D2 // Invocation Field Length | 调用字段长度
	TagOffsetItems                           Tag = 0x4200D4 // Offset Items | 偏移项数
	TagLocatedItems                          Tag = 0x4200D5 // Located Items | 已定位项数
	TagCorrelationValue                      Tag = 0x4200D6 // Correlation Value | 关联值
	TagInitIndicator                         Tag = 0x4200D7 // Init Indicator | 初始指示
	TagFinalIndicator                        Tag = 0x4200D8 // Final Indicator | 最终指示
	TagRNGParameters                         Tag = 0x4200D9 // RNG Parameters | 随机数生成器参数
	TagProfileInformation                    Tag = 0x4200EB // Profile Information | 配置文件信息
	TagProfileName                           Tag = 0x4200EC // Profile Name | 配置文件名称
	TagServerURI                             Tag = 0x4200ED // Server URI | 服务器 URI
	TagServerPort                            Tag = 0x4200EE // Server Port | 服务器端口
	TagKeyWrapType                           Tag = 0x4200F8 // Key Wrap Type | 密钥封装类型
	TagDescription                           Tag = 0x4200FC // Description | 描述
	TagComment                               Tag = 0x4200FD // Comment | 注释
	TagAuthenticatedEncryptionAdditionalData Tag = 0x4200FE // Authenticated Encryption Additional Data | 认证加密附加数据
	TagAuthenticatedEncryptionTag            Tag = 0x4200FF // Authenticated Encryption Tag | 认证加密标签
	TagSaltLength                            Tag = 0x420100 // Salt Length | 盐长度
	TagMaskGenerator                         Tag = 0x420101 // Mask Generator | 掩码生成器
	TagMaskGeneratorHashingAlgorithm         Tag = 0x420102 // Mask Generator Hashing Algorithm | 掩码生成器哈希算法
	TagClientCorrelationValue                Tag = 0x420105 // Client Correlation Value | 客户端关联值
	TagServerCorrelationValue                Tag = 0x420106 // Server Correlation Value | 服务器关联值
	TagDigestedData                          Tag = 0x420107 // Digested Data | 摘要数据
	TagSensitive                             Tag = 0x420120 // Sensitive | 敏感
	TagAlwaysSensitive                       Tag = 0x420121 // Always Sensitive | 始终敏感
	TagExtractable                           Tag = 0x420122 // Extractable | 可导出
	TagNeverExtractable                      Tag = 0x420123 // Never Extractable | 永不可导出
	TagReplaceExisting                       Tag = 0x420124 // Replace Existing | 替换已有
	TagAttributes                            Tag = 0x420125 // Attributes (KMIP 2.0) | 属性（KMIP 2.0）
	TagCommonAttributes                      Tag = 0x420126 // Common Attributes (KMIP 2.0) | 公共属性（KMIP 2.0）
	TagPrivateKeyAttributes                  Tag = 0x420127 // Private Key Attributes (KMIP 2.0) | 私钥属性（KMIP 2.0）
	TagPublicKeyAttributes                   Tag = 0x420128 // Public Key Attributes (KMIP 2.0) | 公钥属性（KMIP 2.0）
	TagAttributeReference                    Tag = 0x42013B // Attribute Reference (KMIP 2.0) | 属性引用（KMIP 2.0）
)

// Type is a TTLV item type. | Type 是 TTLV 项类型。
type Type uint8

// The KMIP TTLV item types. | KMIP TTLV 项类型。
const (
	// TypeStructure is a nested structure. | TypeStructure 是嵌套结构。
	TypeStructure Type = 0x01
	// TypeInteger is a signed 8-byte integer. | TypeInteger 是有符号 8 字节整数。
	TypeInteger Type = 0x02
	// TypeLongInteger is a signed 4-byte integer. | TypeLongInteger 是有符号 4 字节整数。
	TypeLongInteger Type = 0x03
	// TypeBigInteger is a signed multiple-of-8-byte integer. | TypeBigInteger 是有符号且长度为 8 倍数的整数。
	TypeBigInteger Type = 0x04
	// TypeEnumeration is an unsigned 4-byte enumeration. | TypeEnumeration 是无符号 4 字节枚举。
	TypeEnumeration Type = 0x05
	// TypeBoolean is an 8-byte boolean. | TypeBoolean 是 8 字节布尔值。
	TypeBoolean Type = 0x06
	// TypeTextString is a UTF-8 string padded to 8 bytes. | TypeTextString 是补齐到 8 字节的 UTF-8 字符串。
	TypeTextString Type = 0x07
	// TypeByteString is a byte string padded to 8 bytes. | TypeByteString 是补齐到 8 字节的字节串。
	TypeByteString Type = 0x08
	// TypeDateTime is a POSIX timestamp in 8 bytes. | TypeDateTime 是 8 字节 POSIX 时间戳。
	TypeDateTime Type = 0x09
	// TypeInterval is an unsigned 4-byte interval in seconds. | TypeInterval 是无符号 4 字节秒间隔。
	TypeInterval Type = 0x0A
	// TypeDateTimeExtended is an 8-byte seconds plus 4-byte microseconds timestamp. | TypeDateTimeExtended 是 8 字节秒加 4 字节微秒的时间戳。
	TypeDateTimeExtended Type = 0x0B
)

// String returns the canonical TTLV type name. | String 返回规范 TTLV 类型名。
func (t Type) String() string {
	switch t {
	case TypeStructure:
		return "Structure"
	case TypeInteger:
		return "Integer"
	case TypeLongInteger:
		return "LongInteger"
	case TypeBigInteger:
		return "BigInteger"
	case TypeEnumeration:
		return "Enumeration"
	case TypeBoolean:
		return "Boolean"
	case TypeTextString:
		return "TextString"
	case TypeByteString:
		return "ByteString"
	case TypeDateTime:
		return "DateTime"
	case TypeInterval:
		return "Interval"
	case TypeDateTimeExtended:
		return "DateTimeExtended"
	default:
		return "Unknown"
	}
}

// valid reports whether the type is one of the KMIP TTLV types. | valid 报告类型是否为 KMIP TTLV 类型之一。
func (t Type) valid() bool { return t >= TypeStructure && t <= TypeDateTimeExtended }

// Operation is a KMIP operation code. | Operation 是 KMIP 操作代码。
type Operation uint32

// The KMIP operation codes implemented by this package. | 本包实现的 KMIP 操作代码。
const (
	OpCreate             Operation = 0x00000001 // Create | 创建
	OpCreateKeyPair      Operation = 0x00000002 // Create Key Pair | 创建密钥对
	OpRegister           Operation = 0x00000003 // Register | 注册
	OpReKey              Operation = 0x00000004 // Re-key | 重新生成密钥
	OpDeriveKey          Operation = 0x00000005 // Derive Key | 派生密钥
	OpCertify            Operation = 0x00000006 // Certify | 签发证书
	OpRecertify          Operation = 0x00000007 // Recertify | 重新签发证书
	OpLocate             Operation = 0x00000008 // Locate | 定位
	OpCheck              Operation = 0x00000009 // Check | 检查
	OpGet                Operation = 0x0000000A // Get | 获取
	OpGetAttributes      Operation = 0x0000000B // Get Attributes | 获取属性
	OpGetAttributeList   Operation = 0x0000000C // Get Attribute List | 获取属性列表
	OpAddAttribute       Operation = 0x0000000D // Add Attribute | 添加属性
	OpModifyAttribute    Operation = 0x0000000E // Modify Attribute | 修改属性
	OpDeleteAttribute    Operation = 0x0000000F // Delete Attribute | 删除属性
	OpObtainLease        Operation = 0x00000010 // Obtain Lease | 获取租约
	OpGetUsageAllocation Operation = 0x00000011 // Get Usage Allocation | 获取用量分配
	OpActivate           Operation = 0x00000012 // Activate | 激活
	OpRevoke             Operation = 0x00000013 // Revoke | 撤销
	OpDestroy            Operation = 0x00000014 // Destroy | 销毁
	OpArchive            Operation = 0x00000015 // Archive | 归档
	OpRecover            Operation = 0x00000016 // Recover | 恢复
	OpValidate           Operation = 0x00000017 // Validate | 验证
	OpQuery              Operation = 0x00000018 // Query | 查询
	OpCancel             Operation = 0x00000019 // Cancel | 取消
	OpPoll               Operation = 0x0000001A // Poll | 轮询
	OpNotify             Operation = 0x0000001B // Notify | 通知
	OpPut                Operation = 0x0000001C // Put | 放置
	OpReKeyKeyPair       Operation = 0x0000001D // Re-key Key Pair | 重新生成密钥对
	OpDiscoverVersions   Operation = 0x0000001E // Discover Versions | 发现版本
	OpEncrypt            Operation = 0x0000001F // Encrypt | 加密
	OpDecrypt            Operation = 0x00000020 // Decrypt | 解密
	OpSign               Operation = 0x00000021 // Sign | 签名
	OpSignatureVerify    Operation = 0x00000022 // Signature Verify | 验签
	OpMAC                Operation = 0x00000023 // MAC | MAC
	OpMACVerify          Operation = 0x00000024 // MAC Verify | MAC 验证
	OpRNGRetrieve        Operation = 0x00000025 // RNG Retrieve | 获取随机数
	OpRNGSeed            Operation = 0x00000026 // RNG Seed | 随机数种子
	OpHash               Operation = 0x00000027 // Hash | 哈希
	OpCreateSplitKey     Operation = 0x00000028 // Create Split Key | 创建分割密钥
	OpJoinSplitKey       Operation = 0x00000029 // Join Split Key | 合并分割密钥
	OpImport             Operation = 0x0000002A // Import | 导入
	OpExport             Operation = 0x0000002B // Export | 导出
	OpLog                Operation = 0x0000002C // Log | 日志
	OpLogin              Operation = 0x0000002D // Login | 登录
	OpLogout             Operation = 0x0000002E // Logout | 登出
	OpDelegatedLogin     Operation = 0x0000002F // Delegated Login | 委托登录
	OpAdjustAttribute    Operation = 0x00000030 // Adjust Attribute | 调整属性
	OpSetAttribute       Operation = 0x00000031 // Set Attribute | 设置属性
	OpSetEndpointRole    Operation = 0x00000032 // Set Endpoint Role | 设置端点角色
	OpPKCS11             Operation = 0x00000033 // PKCS#11 | PKCS#11
	OpInterop            Operation = 0x00000034 // Interop | 互操作
	OpReprovision        Operation = 0x00000035 // Re-provision | 重新配置
	// OpWrapKey wraps an object with a wrapping key. It is a ydx extension to the OASIS operation enumeration and is
	// implemented symmetrically by this package's client and server. | OpWrapKey 用封装密钥封装对象；它是 ydx 对 OASIS
	// 操作枚举的扩展，本包的客户端与服务器对称实现。
	OpWrapKey Operation = 0x00000037
	// OpUnwrapKey unwraps a wrapped key block and registers the result. It is a ydx extension. | OpUnwrapKey 解封已封装的密钥块并注册结果；属于 ydx 扩展。
	OpUnwrapKey Operation = 0x00000038
)

// String returns the specification name of the operation. | String 返回操作的规范名称。
func (o Operation) String() string {
	switch o {
	case OpCreate:
		return "Create"
	case OpCreateKeyPair:
		return "Create Key Pair"
	case OpRegister:
		return "Register"
	case OpReKey:
		return "Re-key"
	case OpDeriveKey:
		return "Derive Key"
	case OpCertify:
		return "Certify"
	case OpRecertify:
		return "Recertify"
	case OpLocate:
		return "Locate"
	case OpCheck:
		return "Check"
	case OpGet:
		return "Get"
	case OpGetAttributes:
		return "Get Attributes"
	case OpGetAttributeList:
		return "Get Attribute List"
	case OpAddAttribute:
		return "Add Attribute"
	case OpModifyAttribute:
		return "Modify Attribute"
	case OpDeleteAttribute:
		return "Delete Attribute"
	case OpObtainLease:
		return "Obtain Lease"
	case OpGetUsageAllocation:
		return "Get Usage Allocation"
	case OpActivate:
		return "Activate"
	case OpRevoke:
		return "Revoke"
	case OpDestroy:
		return "Destroy"
	case OpArchive:
		return "Archive"
	case OpRecover:
		return "Recover"
	case OpValidate:
		return "Validate"
	case OpQuery:
		return "Query"
	case OpCancel:
		return "Cancel"
	case OpPoll:
		return "Poll"
	case OpNotify:
		return "Notify"
	case OpPut:
		return "Put"
	case OpReKeyKeyPair:
		return "Re-key Key Pair"
	case OpDiscoverVersions:
		return "Discover Versions"
	case OpEncrypt:
		return "Encrypt"
	case OpDecrypt:
		return "Decrypt"
	case OpSign:
		return "Sign"
	case OpSignatureVerify:
		return "Signature Verify"
	case OpMAC:
		return "MAC"
	case OpMACVerify:
		return "MAC Verify"
	case OpRNGRetrieve:
		return "RNG Retrieve"
	case OpRNGSeed:
		return "RNG Seed"
	case OpHash:
		return "Hash"
	case OpCreateSplitKey:
		return "Create Split Key"
	case OpJoinSplitKey:
		return "Join Split Key"
	case OpImport:
		return "Import"
	case OpExport:
		return "Export"
	case OpLog:
		return "Log"
	case OpLogin:
		return "Login"
	case OpLogout:
		return "Logout"
	case OpDelegatedLogin:
		return "Delegated Login"
	case OpAdjustAttribute:
		return "Adjust Attribute"
	case OpSetAttribute:
		return "Set Attribute"
	case OpSetEndpointRole:
		return "Set Endpoint Role"
	case OpPKCS11:
		return "PKCS#11"
	case OpInterop:
		return "Interop"
	case OpReprovision:
		return "Re-provision"
	case OpWrapKey:
		return "Wrap Key"
	case OpUnwrapKey:
		return "Unwrap Key"
	default:
		return "Unknown"
	}
}

// ObjectType is a KMIP managed object type. | ObjectType 是 KMIP 受管对象类型。
type ObjectType uint32

// The KMIP managed object types. | KMIP 受管对象类型。
const (
	ObjectTypeCertificate        ObjectType = 0x00000001 // Certificate | 证书
	ObjectTypeSymmetricKey       ObjectType = 0x00000002 // Symmetric Key | 对称密钥
	ObjectTypePublicKey          ObjectType = 0x00000003 // Public Key | 公钥
	ObjectTypePrivateKey         ObjectType = 0x00000004 // Private Key | 私钥
	ObjectTypeSplitKey           ObjectType = 0x00000005 // Split Key | 分割密钥
	ObjectTypeTemplate           ObjectType = 0x00000006 // Template | 模板
	ObjectTypeSecretData         ObjectType = 0x00000007 // Secret Data | 秘密数据
	ObjectTypeOpaqueObject       ObjectType = 0x00000008 // Opaque Object | 不透明对象
	ObjectTypePGPKey             ObjectType = 0x00000009 // PGP Key | PGP 密钥
	ObjectTypeCertificateRequest ObjectType = 0x0000000A // Certificate Request | 证书请求
)

// String returns the specification name of the object type. | String 返回对象类型的规范名称。
func (t ObjectType) String() string {
	switch t {
	case ObjectTypeCertificate:
		return "Certificate"
	case ObjectTypeSymmetricKey:
		return "Symmetric Key"
	case ObjectTypePublicKey:
		return "Public Key"
	case ObjectTypePrivateKey:
		return "Private Key"
	case ObjectTypeSplitKey:
		return "Split Key"
	case ObjectTypeTemplate:
		return "Template"
	case ObjectTypeSecretData:
		return "Secret Data"
	case ObjectTypeOpaqueObject:
		return "Opaque Object"
	case ObjectTypePGPKey:
		return "PGP Key"
	case ObjectTypeCertificateRequest:
		return "Certificate Request"
	default:
		return "Unknown"
	}
}

// State is a managed object lifecycle state. | State 是受管对象的生命周期状态。
type State uint32

// The KMIP lifecycle states. | KMIP 生命周期状态。
const (
	StatePreActive            State = 0x00000001 // Pre-Active | 激活前
	StateActive               State = 0x00000002 // Active | 已激活
	StateDeactivated          State = 0x00000003 // Deactivated | 已停用
	StateCompromised          State = 0x00000004 // Compromised | 已泄露
	StateDestroyed            State = 0x00000005 // Destroyed | 已销毁
	StateDestroyedCompromised State = 0x00000006 // Destroyed Compromised | 销毁且已泄露
)

// String returns the specification name of the state. | String 返回状态的规范名称。
func (s State) String() string {
	switch s {
	case StatePreActive:
		return "Pre-Active"
	case StateActive:
		return "Active"
	case StateDeactivated:
		return "Deactivated"
	case StateCompromised:
		return "Compromised"
	case StateDestroyed:
		return "Destroyed"
	case StateDestroyedCompromised:
		return "Destroyed Compromised"
	default:
		return "Unknown"
	}
}

// CryptographicAlgorithm is a KMIP cryptographic algorithm enumeration. | CryptographicAlgorithm 是 KMIP 密码算法枚举。
type CryptographicAlgorithm uint32

// The cryptographic algorithms supported by this package. | 本包支持的密码算法。
const (
	AlgorithmDES              CryptographicAlgorithm = 0x00000001 // DES | DES
	Algorithm3DES             CryptographicAlgorithm = 0x00000002 // Triple DES | 三重 DES
	AlgorithmAES              CryptographicAlgorithm = 0x00000003 // AES | AES
	AlgorithmRSA              CryptographicAlgorithm = 0x00000004 // RSA | RSA
	AlgorithmDSA              CryptographicAlgorithm = 0x00000005 // DSA | DSA
	AlgorithmECDSA            CryptographicAlgorithm = 0x00000006 // ECDSA | ECDSA
	AlgorithmHMACSHA1         CryptographicAlgorithm = 0x00000007 // HMAC-SHA1 | HMAC-SHA1
	AlgorithmHMACSHA224       CryptographicAlgorithm = 0x00000008 // HMAC-SHA224 | HMAC-SHA224
	AlgorithmHMACSHA256       CryptographicAlgorithm = 0x00000009 // HMAC-SHA256 | HMAC-SHA256
	AlgorithmHMACSHA384       CryptographicAlgorithm = 0x0000000A // HMAC-SHA384 | HMAC-SHA384
	AlgorithmHMACSHA512       CryptographicAlgorithm = 0x0000000B // HMAC-SHA512 | HMAC-SHA512
	AlgorithmHMACMD5          CryptographicAlgorithm = 0x0000000C // HMAC-MD5 | HMAC-MD5
	AlgorithmDH               CryptographicAlgorithm = 0x0000000D // Diffie-Hellman | Diffie-Hellman
	AlgorithmECDH             CryptographicAlgorithm = 0x0000000E // ECDH | ECDH
	AlgorithmEC               CryptographicAlgorithm = 0x0000001A // Elliptic Curve | 椭圆曲线
	AlgorithmChaCha20Poly1305 CryptographicAlgorithm = 0x0000001E // ChaCha20-Poly1305 | ChaCha20-Poly1305
	AlgorithmSM2              CryptographicAlgorithm = 0x0000002B // SM2 | SM2
	AlgorithmSM3              CryptographicAlgorithm = 0x0000002C // SM3 | SM3
	AlgorithmSM4              CryptographicAlgorithm = 0x0000002D // SM4 | SM4
	AlgorithmEd25519          CryptographicAlgorithm = 0x00000037 // Ed25519 | Ed25519
	AlgorithmEd448            CryptographicAlgorithm = 0x00000038 // Ed448 | Ed448
)

// String returns the specification name of the algorithm. | String 返回算法的规范名称。
func (a CryptographicAlgorithm) String() string {
	switch a {
	case AlgorithmDES:
		return "DES"
	case Algorithm3DES:
		return "3DES"
	case AlgorithmAES:
		return "AES"
	case AlgorithmRSA:
		return "RSA"
	case AlgorithmDSA:
		return "DSA"
	case AlgorithmECDSA:
		return "ECDSA"
	case AlgorithmHMACSHA1:
		return "HMAC-SHA1"
	case AlgorithmHMACSHA224:
		return "HMAC-SHA224"
	case AlgorithmHMACSHA256:
		return "HMAC-SHA256"
	case AlgorithmHMACSHA384:
		return "HMAC-SHA384"
	case AlgorithmHMACSHA512:
		return "HMAC-SHA512"
	case AlgorithmHMACMD5:
		return "HMAC-MD5"
	case AlgorithmDH:
		return "DH"
	case AlgorithmECDH:
		return "ECDH"
	case AlgorithmEC:
		return "EC"
	case AlgorithmChaCha20Poly1305:
		return "ChaCha20-Poly1305"
	case AlgorithmSM2:
		return "SM2"
	case AlgorithmSM3:
		return "SM3"
	case AlgorithmSM4:
		return "SM4"
	case AlgorithmEd25519:
		return "Ed25519"
	case AlgorithmEd448:
		return "Ed448"
	default:
		return "Unknown"
	}
}

// KeyFormatType is a KMIP key format type. | KeyFormatType 是 KMIP 密钥格式类型。
type KeyFormatType uint32

// The KMIP key format types. | KMIP 密钥格式类型。
const (
	KeyFormatRaw                      KeyFormatType = 0x00000001 // Raw | 原始格式
	KeyFormatOpaque                   KeyFormatType = 0x00000002 // Opaque | 不透明格式
	KeyFormatPKCS1                    KeyFormatType = 0x00000003 // PKCS#1 | PKCS#1
	KeyFormatPKCS8                    KeyFormatType = 0x00000004 // PKCS#8 | PKCS#8
	KeyFormatX509                     KeyFormatType = 0x00000005 // X.509 SubjectPublicKeyInfo | X.509 SPKI
	KeyFormatECPrivateKey             KeyFormatType = 0x00000006 // SEC1 ECPrivateKey | SEC1 ECPrivateKey
	KeyFormatTransparentSymmetricKey  KeyFormatType = 0x00000007 // Transparent Symmetric Key | 透明对称密钥
	KeyFormatTransparentRSAPrivateKey KeyFormatType = 0x0000000A // Transparent RSA Private Key | 透明 RSA 私钥
	KeyFormatTransparentRSAPublicKey  KeyFormatType = 0x0000000B // Transparent RSA Public Key | 透明 RSA 公钥
	KeyFormatTransparentECPrivateKey  KeyFormatType = 0x00000014 // Transparent EC Private Key | 透明 EC 私钥
	KeyFormatTransparentECPublicKey   KeyFormatType = 0x00000015 // Transparent EC Public Key | 透明 EC 公钥
	KeyFormatPKCS12                   KeyFormatType = 0x00000016 // PKCS#12 | PKCS#12
	// KeyFormatJWK is a JSON Web Key (RFC 7517) encoding carried as a byte string. KMIP 2.0 assigns no
	// Key Format Type value to JWK; 0x80000001 is a ydx vendor extension in the extension range.
	// | KeyFormatJWK 是以字节串承载的 JSON Web Key（RFC 7517）编码。KMIP 2.0 未给 JWK 分配
	// Key Format Type 值；0x80000001 是扩展范围内的 ydx 厂商扩展值。
	KeyFormatJWK KeyFormatType = 0x80000001
)

// String returns the specification name of the key format. | String 返回密钥格式的规范名称。
func (f KeyFormatType) String() string {
	switch f {
	case KeyFormatRaw:
		return "Raw"
	case KeyFormatOpaque:
		return "Opaque"
	case KeyFormatPKCS1:
		return "PKCS#1"
	case KeyFormatPKCS8:
		return "PKCS#8"
	case KeyFormatX509:
		return "X.509"
	case KeyFormatECPrivateKey:
		return "ECPrivateKey"
	case KeyFormatTransparentSymmetricKey:
		return "Transparent Symmetric Key"
	case KeyFormatTransparentRSAPrivateKey:
		return "Transparent RSA Private Key"
	case KeyFormatTransparentRSAPublicKey:
		return "Transparent RSA Public Key"
	case KeyFormatTransparentECPrivateKey:
		return "Transparent EC Private Key"
	case KeyFormatTransparentECPublicKey:
		return "Transparent EC Public Key"
	case KeyFormatPKCS12:
		return "PKCS#12"
	case KeyFormatJWK:
		return "JWK"
	default:
		return "Unknown"
	}
}

// KeyCompressionType is a KMIP key compression type. | KeyCompressionType 是 KMIP 密钥压缩类型。
type KeyCompressionType uint32

// The KMIP key compression types used for elliptic-curve public keys. | 用于椭圆曲线公钥的 KMIP 密钥压缩类型。
const (
	KeyCompressionNone                    KeyCompressionType = 0x00000001 // No compression | 不压缩
	KeyCompressionECPublicKeyUncompressed KeyCompressionType = 0x00000002 // Uncompressed point | 未压缩点
	KeyCompressionECPublicKeyX962Prime    KeyCompressionType = 0x00000003 // X9.62 compressed prime point | X9.62 压缩素数点
	KeyCompressionECPublicKeyX962Char2    KeyCompressionType = 0x00000004 // X9.62 compressed char-2 point | X9.62 压缩二元域点
	KeyCompressionECPublicKeyX962Hybrid   KeyCompressionType = 0x00000005 // X9.62 hybrid point | X9.62 混合点
)

// RecommendedCurve is a KMIP recommended elliptic curve. | RecommendedCurve 是 KMIP 推荐椭圆曲线。
type RecommendedCurve uint32

// The KMIP recommended curves supported by this package. | 本包支持的 KMIP 推荐曲线。
const (
	CurveP192 RecommendedCurve = 0x00000001 // NIST P-192 | NIST P-192
	CurveP224 RecommendedCurve = 0x00000004 // NIST P-224 | NIST P-224
	CurveP256 RecommendedCurve = 0x00000007 // NIST P-256 | NIST P-256
	CurveP384 RecommendedCurve = 0x0000000A // NIST P-384 | NIST P-384
	CurveP521 RecommendedCurve = 0x0000000D // NIST P-521 | NIST P-521
)

// CryptographicUsageMask is a bit mask of allowed cryptographic usages. | CryptographicUsageMask 是允许的密码学用途位掩码。
type CryptographicUsageMask uint32

// The KMIP cryptographic usage mask bits. | KMIP 密码学用法掩码位。
const (
	UsageMaskSign               CryptographicUsageMask = 0x00000001 // Sign | 签名
	UsageMaskVerify             CryptographicUsageMask = 0x00000002 // Verify | 验签
	UsageMaskEncrypt            CryptographicUsageMask = 0x00000004 // Encrypt | 加密
	UsageMaskDecrypt            CryptographicUsageMask = 0x00000008 // Decrypt | 解密
	UsageMaskWrapKey            CryptographicUsageMask = 0x00000010 // Wrap Key | 封装密钥
	UsageMaskUnwrapKey          CryptographicUsageMask = 0x00000020 // Unwrap Key | 解封密钥
	UsageMaskExport             CryptographicUsageMask = 0x00000040 // Export | 导出
	UsageMaskMACGenerate        CryptographicUsageMask = 0x00000080 // MAC Generate | 生成 MAC
	UsageMaskMACVerify          CryptographicUsageMask = 0x00000100 // MAC Verify | 验证 MAC
	UsageMaskDeriveKey          CryptographicUsageMask = 0x00000200 // Derive Key | 派生密钥
	UsageMaskContentCommitment  CryptographicUsageMask = 0x00000400 // Content Commitment | 内容承诺
	UsageMaskKeyAgreement       CryptographicUsageMask = 0x00000800 // Key Agreement | 密钥协商
	UsageMaskCertificateSign    CryptographicUsageMask = 0x00001000 // Certificate Sign | 证书签名
	UsageMaskCRLSign            CryptographicUsageMask = 0x00002000 // CRL Sign | CRL 签名
	UsageMaskGenerateCryptogram CryptographicUsageMask = 0x00004000 // Generate Cryptogram | 生成密文
	UsageMaskValidateCryptogram CryptographicUsageMask = 0x00008000 // Validate Cryptogram | 验证密文
	UsageMaskTranslateEncrypt   CryptographicUsageMask = 0x00010000 // Translate Encrypt | 转换加密
	UsageMaskTranslateDecrypt   CryptographicUsageMask = 0x00020000 // Translate Decrypt | 转换解密
	UsageMaskTranslateWrap      CryptographicUsageMask = 0x00040000 // Translate Wrap | 转换封装
	UsageMaskTranslateUnwrap    CryptographicUsageMask = 0x00080000 // Translate Unwrap | 转换解封
)

// Has reports whether all bits of flag are set in m. | Has 报告 m 是否已设置 flag 的全部位。
func (m CryptographicUsageMask) Has(flag CryptographicUsageMask) bool { return m&flag == flag }

// String renders the mask as a '|'-separated list of the known bit names. | String 以 '|' 分隔的已知位名渲染掩码。
func (m CryptographicUsageMask) String() string {
	if m == 0 {
		return "None"
	}
	names := make([]string, 0, 8)
	for _, bit := range []struct {
		mask CryptographicUsageMask
		name string
	}{
		{UsageMaskSign, "Sign"},
		{UsageMaskVerify, "Verify"},
		{UsageMaskEncrypt, "Encrypt"},
		{UsageMaskDecrypt, "Decrypt"},
		{UsageMaskWrapKey, "Wrap Key"},
		{UsageMaskUnwrapKey, "Unwrap Key"},
		{UsageMaskExport, "Export"},
		{UsageMaskMACGenerate, "MAC Generate"},
		{UsageMaskMACVerify, "MAC Verify"},
		{UsageMaskDeriveKey, "Derive Key"},
		{UsageMaskContentCommitment, "Content Commitment"},
		{UsageMaskKeyAgreement, "Key Agreement"},
		{UsageMaskCertificateSign, "Certificate Sign"},
		{UsageMaskCRLSign, "CRL Sign"},
		{UsageMaskGenerateCryptogram, "Generate Cryptogram"},
		{UsageMaskValidateCryptogram, "Validate Cryptogram"},
		{UsageMaskTranslateEncrypt, "Translate Encrypt"},
		{UsageMaskTranslateDecrypt, "Translate Decrypt"},
		{UsageMaskTranslateWrap, "Translate Wrap"},
		{UsageMaskTranslateUnwrap, "Translate Unwrap"},
	} {
		if m.Has(bit.mask) {
			names = append(names, bit.name)
		}
	}
	if len(names) == 0 {
		return "Unknown"
	}
	return strings.Join(names, "|")
}

// ResultStatus is a KMIP batch-item result status. | ResultStatus 是 KMIP 批处理项结果状态。
type ResultStatus uint32

// The KMIP result statuses. | KMIP 结果状态。
const (
	ResultStatusSuccess          ResultStatus = 0x00000000 // Success | 成功
	ResultStatusOperationFailed  ResultStatus = 0x00000001 // Operation Failed | 操作失败
	ResultStatusOperationPending ResultStatus = 0x00000002 // Operation Pending | 操作待定
	ResultStatusOperationUndone  ResultStatus = 0x00000003 // Operation Undone | 操作已撤销
)

// String returns the specification name of the result status. | String 返回结果状态的规范名称。
func (s ResultStatus) String() string {
	switch s {
	case ResultStatusSuccess:
		return "Success"
	case ResultStatusOperationFailed:
		return "Operation Failed"
	case ResultStatusOperationPending:
		return "Operation Pending"
	case ResultStatusOperationUndone:
		return "Operation Undone"
	default:
		return "Unknown"
	}
}

// ResultReason is a KMIP result reason code. | ResultReason 是 KMIP 结果原因代码。
type ResultReason uint32

// The KMIP result reasons used by this package. | 本包使用的 KMIP 结果原因。
const (
	ResultReasonItemNotFound                       ResultReason = 0x00000001 // Item Not Found | 对象不存在
	ResultReasonResponseTooLarge                   ResultReason = 0x00000002 // Response Too Large | 响应过大
	ResultReasonAuthenticationNotSuccessful        ResultReason = 0x00000003 // Authentication Not Successful | 认证失败
	ResultReasonInvalidMessage                     ResultReason = 0x00000004 // Invalid Message | 消息非法
	ResultReasonOperationNotSupported              ResultReason = 0x00000005 // Operation Not Supported | 操作不支持
	ResultReasonMissingData                        ResultReason = 0x00000006 // Missing Data | 数据缺失
	ResultReasonInvalidField                       ResultReason = 0x00000007 // Invalid Field | 字段非法
	ResultReasonFeatureNotSupported                ResultReason = 0x00000008 // Feature Not Supported | 特性不支持
	ResultReasonOperationCanceledByRequester       ResultReason = 0x00000009 // Operation Canceled By Requester | 请求方取消
	ResultReasonCryptographicFailure               ResultReason = 0x0000000A // Cryptographic Failure | 密码学失败
	ResultReasonIllegalOperation                   ResultReason = 0x0000000B // Illegal Operation | 非法操作
	ResultReasonPermissionDenied                   ResultReason = 0x0000000C // Permission Denied | 权限不足
	ResultReasonObjectArchived                     ResultReason = 0x0000000D // Object Archived | 对象已归档
	ResultReasonIndexOutOfBounds                   ResultReason = 0x0000000E // Index Out of Bounds | 索引越界
	ResultReasonApplicationNamespaceNotSupported   ResultReason = 0x0000000F // Application Namespace Not Supported | 应用命名空间不支持
	ResultReasonKeyFormatTypeNotSupported          ResultReason = 0x00000010 // Key Format Type Not Supported | 密钥格式不支持
	ResultReasonKeyCompressionTypeNotSupported     ResultReason = 0x00000011 // Key Compression Type Not Supported | 密钥压缩类型不支持
	ResultReasonEncodingOptionError                ResultReason = 0x00000012 // Encoding Option Error | 编码选项错误
	ResultReasonKeyValueNotPresent                 ResultReason = 0x00000013 // Key Value Not Present | 密钥值不存在
	ResultReasonAttestationRequired                ResultReason = 0x00000014 // Attestation Required | 需要证明
	ResultReasonAttestationFailed                  ResultReason = 0x00000015 // Attestation Failed | 证明失败
	ResultReasonSensitive                          ResultReason = 0x00000016 // Sensitive | 敏感
	ResultReasonNotExtractable                     ResultReason = 0x00000017 // Not Extractable | 不可导出
	ResultReasonObjectAlreadyExists                ResultReason = 0x00000018 // Object Already Exists | 对象已存在
	ResultReasonInvalidTicket                      ResultReason = 0x00000019 // Invalid Ticket | 票据非法
	ResultReasonUsageLimitExceeded                 ResultReason = 0x0000001A // Usage Limit Exceeded | 超出使用限制
	ResultReasonNumericRange                       ResultReason = 0x0000001B // Numeric Range | 数值越界
	ResultReasonInvalidDataType                    ResultReason = 0x0000001C // Invalid Data Type | 数据类型非法
	ResultReasonUnsupportedAttribute               ResultReason = 0x0000001F // Unsupported Attribute | 属性不支持
	ResultReasonAttributeNotFound                  ResultReason = 0x00000021 // Attribute Not Found | 属性不存在
	ResultReasonBadCryptographicParameters         ResultReason = 0x00000024 // Bad Cryptographic Parameters | 密码参数非法
	ResultReasonBadPassword                        ResultReason = 0x00000025 // Bad Password | 口令错误
	ResultReasonCodecError                         ResultReason = 0x00000026 // Codec Error | 编解码错误
	ResultReasonIllegalObjectType                  ResultReason = 0x00000028 // Illegal Object Type | 对象类型非法
	ResultReasonIncompatibleCryptographicUsageMask ResultReason = 0x00000029 // Incompatible Cryptographic Usage Mask | 密码学用法掩码不兼容
	ResultReasonInternalServerError                ResultReason = 0x0000002A // Internal Server Error | 服务器内部错误
	ResultReasonInvalidAttribute                   ResultReason = 0x0000002C // Invalid Attribute | 属性非法
	ResultReasonInvalidAttributeValue              ResultReason = 0x0000002D // Invalid Attribute Value | 属性值非法
	ResultReasonInvalidObjectType                  ResultReason = 0x00000030 // Invalid Object Type | 对象类型非法
	ResultReasonKeyWrapTypeNotSupported            ResultReason = 0x00000032 // Key Wrap Type Not Supported | 密钥封装类型不支持
	ResultReasonGeneralFailure                     ResultReason = 0x00000100 // General Failure | 通用失败
)

// String returns the specification name of the result reason. | String 返回结果原因的规范名称。
func (r ResultReason) String() string {
	switch r {
	case ResultReasonItemNotFound:
		return "Item Not Found"
	case ResultReasonResponseTooLarge:
		return "Response Too Large"
	case ResultReasonAuthenticationNotSuccessful:
		return "Authentication Not Successful"
	case ResultReasonInvalidMessage:
		return "Invalid Message"
	case ResultReasonOperationNotSupported:
		return "Operation Not Supported"
	case ResultReasonMissingData:
		return "Missing Data"
	case ResultReasonInvalidField:
		return "Invalid Field"
	case ResultReasonFeatureNotSupported:
		return "Feature Not Supported"
	case ResultReasonOperationCanceledByRequester:
		return "Operation Canceled By Requester"
	case ResultReasonCryptographicFailure:
		return "Cryptographic Failure"
	case ResultReasonIllegalOperation:
		return "Illegal Operation"
	case ResultReasonPermissionDenied:
		return "Permission Denied"
	case ResultReasonObjectArchived:
		return "Object Archived"
	case ResultReasonIndexOutOfBounds:
		return "Index Out of Bounds"
	case ResultReasonApplicationNamespaceNotSupported:
		return "Application Namespace Not Supported"
	case ResultReasonKeyFormatTypeNotSupported:
		return "Key Format Type Not Supported"
	case ResultReasonKeyCompressionTypeNotSupported:
		return "Key Compression Type Not Supported"
	case ResultReasonEncodingOptionError:
		return "Encoding Option Error"
	case ResultReasonKeyValueNotPresent:
		return "Key Value Not Present"
	case ResultReasonAttestationRequired:
		return "Attestation Required"
	case ResultReasonAttestationFailed:
		return "Attestation Failed"
	case ResultReasonSensitive:
		return "Sensitive"
	case ResultReasonNotExtractable:
		return "Not Extractable"
	case ResultReasonObjectAlreadyExists:
		return "Object Already Exists"
	case ResultReasonInvalidTicket:
		return "Invalid Ticket"
	case ResultReasonUsageLimitExceeded:
		return "Usage Limit Exceeded"
	case ResultReasonNumericRange:
		return "Numeric Range"
	case ResultReasonInvalidDataType:
		return "Invalid Data Type"
	case ResultReasonUnsupportedAttribute:
		return "Unsupported Attribute"
	case ResultReasonAttributeNotFound:
		return "Attribute Not Found"
	case ResultReasonBadCryptographicParameters:
		return "Bad Cryptographic Parameters"
	case ResultReasonBadPassword:
		return "Bad Password"
	case ResultReasonCodecError:
		return "Codec Error"
	case ResultReasonIllegalObjectType:
		return "Illegal Object Type"
	case ResultReasonIncompatibleCryptographicUsageMask:
		return "Incompatible Cryptographic Usage Mask"
	case ResultReasonInternalServerError:
		return "Internal Server Error"
	case ResultReasonInvalidAttribute:
		return "Invalid Attribute"
	case ResultReasonInvalidAttributeValue:
		return "Invalid Attribute Value"
	case ResultReasonInvalidObjectType:
		return "Invalid Object Type"
	case ResultReasonKeyWrapTypeNotSupported:
		return "Key Wrap Type Not Supported"
	case ResultReasonGeneralFailure:
		return "General Failure"
	default:
		return "Unknown"
	}
}

// RevocationReasonCode is a KMIP revocation reason. | RevocationReasonCode 是 KMIP 撤销原因。
type RevocationReasonCode uint32

// The KMIP revocation reason codes. | KMIP 撤销原因代码。
const (
	RevocationUnspecified          RevocationReasonCode = 0x00000001 // Unspecified | 未指定
	RevocationKeyCompromise        RevocationReasonCode = 0x00000002 // Key Compromise | 密钥泄露
	RevocationCACompromise         RevocationReasonCode = 0x00000003 // CA Compromise | CA 泄露
	RevocationAffiliationChanged   RevocationReasonCode = 0x00000004 // Affiliation Changed | 隶属关系变更
	RevocationSuperseded           RevocationReasonCode = 0x00000005 // Superseded | 已被取代
	RevocationCessationOfOperation RevocationReasonCode = 0x00000006 // Cessation Of Operation | 停止使用
	RevocationPrivilegeWithdrawn   RevocationReasonCode = 0x00000007 // Privilege Withdrawn | 权限撤销
)

// String returns the specification name of the revocation reason. | String 返回撤销原因的规范名称。
func (r RevocationReasonCode) String() string {
	switch r {
	case RevocationUnspecified:
		return "Unspecified"
	case RevocationKeyCompromise:
		return "Key Compromise"
	case RevocationCACompromise:
		return "CA Compromise"
	case RevocationAffiliationChanged:
		return "Affiliation Changed"
	case RevocationSuperseded:
		return "Superseded"
	case RevocationCessationOfOperation:
		return "Cessation Of Operation"
	case RevocationPrivilegeWithdrawn:
		return "Privilege Withdrawn"
	default:
		return "Unknown"
	}
}

// NameType is a KMIP name type. | NameType 是 KMIP 名称类型。
type NameType uint32

// The KMIP name types. | KMIP 名称类型。
const (
	NameTypeUninterpretedTextString NameType = 0x00000001 // Uninterpreted Text String | 未解释文本字符串
	NameTypeURI                     NameType = 0x00000002 // URI | URI
)

// String returns the specification name of the name type. | String 返回名称类型的规范名称。
func (t NameType) String() string {
	switch t {
	case NameTypeUninterpretedTextString:
		return "Uninterpreted Text String"
	case NameTypeURI:
		return "URI"
	default:
		return "Unknown"
	}
}

// SecretDataType is a KMIP secret data type. | SecretDataType 是 KMIP 秘密数据类型。
type SecretDataType uint32

// The KMIP secret data types. | KMIP 秘密数据类型。
const (
	SecretDataTypePassword SecretDataType = 0x00000001 // Password | 口令
	SecretDataTypeSeed     SecretDataType = 0x00000002 // Seed | 种子
)

// CertificateType is a KMIP certificate type. | CertificateType 是 KMIP 证书类型。
type CertificateType uint32

// The KMIP certificate types. | KMIP 证书类型。
const (
	CertificateTypeX509 CertificateType = 0x00000001 // X.509 | X.509
	CertificateTypePGP  CertificateType = 0x00000002 // PGP | PGP
)

// WrappingMethod is a KMIP key wrapping method. | WrappingMethod 是 KMIP 密钥封装方法。
type WrappingMethod uint32

// The KMIP key wrapping methods. | KMIP 密钥封装方法。
const (
	WrappingMethodEncrypt            WrappingMethod = 0x00000001 // Encrypt | 加密
	WrappingMethodMACSign            WrappingMethod = 0x00000002 // MAC/Sign | MAC/签名
	WrappingMethodEncryptThenMACSign WrappingMethod = 0x00000003 // Encrypt then MAC/Sign | 先加密后 MAC/签名
	WrappingMethodMACSignThenEncrypt WrappingMethod = 0x00000004 // MAC/Sign then Encrypt | 先 MAC/签名后加密
	WrappingMethodTR31               WrappingMethod = 0x00000005 // TR-31 | TR-31
)

// EncodingOption is a KMIP encoding option. | EncodingOption 是 KMIP 编码选项。
type EncodingOption uint32

// The KMIP encoding options. | KMIP 编码选项。
const (
	EncodingOptionNoEncoding   EncodingOption = 0x00000001 // No Encoding | 不编码
	EncodingOptionTTLVEncoding EncodingOption = 0x00000002 // TTLV Encoding | TTLV 编码
)

// KeyWrapType is a KMIP key wrap type. | KeyWrapType 是 KMIP 密钥封装类型。
type KeyWrapType uint32

// The KMIP key wrap types. | KMIP 密钥封装类型。
const (
	KeyWrapTypeNotWrapped   KeyWrapType = 0x00000001 // Not Wrapped | 未封装
	KeyWrapTypeAsRegistered KeyWrapType = 0x00000002 // As Registered | 按注册状态
)

// QueryFunction is a KMIP query function. | QueryFunction 是 KMIP 查询功能。
type QueryFunction uint32

// The KMIP query functions. | KMIP 查询功能。
const (
	QueryFunctionOperations                QueryFunction = 0x00000001 // Operations | 操作
	QueryFunctionObjects                   QueryFunction = 0x00000002 // Objects | 对象
	QueryFunctionServerInformation         QueryFunction = 0x00000003 // Server Information | 服务器信息
	QueryFunctionApplicationNamespaces     QueryFunction = 0x00000004 // Application Namespaces | 应用命名空间
	QueryFunctionExtensionList             QueryFunction = 0x00000005 // Extension List | 扩展列表
	QueryFunctionExtensionMap              QueryFunction = 0x00000006 // Extension Map | 扩展映射
	QueryFunctionAttestationTypes          QueryFunction = 0x00000007 // Attestation Types | 证明类型
	QueryFunctionRNGs                      QueryFunction = 0x00000008 // RNGs | 随机数生成器
	QueryFunctionValidations               QueryFunction = 0x00000009 // Validations | 验证
	QueryFunctionProfiles                  QueryFunction = 0x0000000A // Profiles | 配置文件
	QueryFunctionCapabilities              QueryFunction = 0x0000000B // Capabilities | 能力
	QueryFunctionClientRegistrationMethods QueryFunction = 0x0000000C // Client Registration Methods | 客户端注册方法
)

// DerivationMethod is a KMIP key derivation method. | DerivationMethod 是 KMIP 密钥派生方法。
type DerivationMethod uint32

// The KMIP key derivation methods. | KMIP 密钥派生方法。
const (
	DerivationMethodPBKDF2        DerivationMethod = 0x00000001 // PBKDF2 | PBKDF2
	DerivationMethodHash          DerivationMethod = 0x00000002 // Hash | 哈希
	DerivationMethodHMAC          DerivationMethod = 0x00000003 // HMAC | HMAC
	DerivationMethodEncrypt       DerivationMethod = 0x00000004 // Encrypt | 加密
	DerivationMethodNIST800108C   DerivationMethod = 0x00000005 // NIST SP 800-108 Counter Mode | NIST SP 800-108 计数器模式
	DerivationMethodNIST800108F   DerivationMethod = 0x00000006 // NIST SP 800-108 Feedback Mode | NIST SP 800-108 反馈模式
	DerivationMethodNIST800108DPI DerivationMethod = 0x00000007 // NIST SP 800-108 Double Pipeline | NIST SP 800-108 双管线模式
	DerivationMethodAsymmetricKey DerivationMethod = 0x00000008 // Asymmetric Key | 非对称密钥
	DerivationMethodAWS4          DerivationMethod = 0x00000009 // AWS Signature Version 4 | AWS 签名版本 4
	DerivationMethodHKDF          DerivationMethod = 0x0000000A // HKDF | HKDF
)

// HashingAlgorithm is a KMIP hashing algorithm. | HashingAlgorithm 是 KMIP 哈希算法。
type HashingAlgorithm uint32

// The KMIP hashing algorithms supported by this package. | 本包支持的 KMIP 哈希算法。
const (
	HashingAlgorithmSHA1       HashingAlgorithm = 0x00000004 // SHA-1 | SHA-1
	HashingAlgorithmSHA224     HashingAlgorithm = 0x00000005 // SHA-224 | SHA-224
	HashingAlgorithmSHA256     HashingAlgorithm = 0x00000006 // SHA-256 | SHA-256
	HashingAlgorithmSHA384     HashingAlgorithm = 0x00000007 // SHA-384 | SHA-384
	HashingAlgorithmSHA512     HashingAlgorithm = 0x00000008 // SHA-512 | SHA-512
	HashingAlgorithmSHA512_224 HashingAlgorithm = 0x0000000C // SHA-512/224 | SHA-512/224
	HashingAlgorithmSHA512_256 HashingAlgorithm = 0x0000000D // SHA-512/256 | SHA-512/256
	HashingAlgorithmSHA3_256   HashingAlgorithm = 0x0000000F // SHA3-256 | SHA3-256
	HashingAlgorithmSHA3_384   HashingAlgorithm = 0x00000010 // SHA3-384 | SHA3-384
	HashingAlgorithmSHA3_512   HashingAlgorithm = 0x00000011 // SHA3-512 | SHA3-512
	HashingAlgorithmSM3        HashingAlgorithm = 0x00000012 // SM3 (ydx extension value) | SM3（ydx 扩展值）
)

// BlockCipherMode is a KMIP block cipher mode. | BlockCipherMode 是 KMIP 分组密码模式。
type BlockCipherMode uint32

// The KMIP block cipher modes. | KMIP 分组密码模式。
const (
	BlockCipherModeCBC  BlockCipherMode = 0x00000001 // CBC | CBC
	BlockCipherModeECB  BlockCipherMode = 0x00000002 // ECB | ECB
	BlockCipherModeCFB  BlockCipherMode = 0x00000004 // CFB | CFB
	BlockCipherModeOFB  BlockCipherMode = 0x00000005 // OFB | OFB
	BlockCipherModeCTR  BlockCipherMode = 0x00000006 // CTR | CTR
	BlockCipherModeGCM  BlockCipherMode = 0x00000009 // GCM | GCM
	BlockCipherModeCCM  BlockCipherMode = 0x00000008 // CCM | CCM
	BlockCipherModeXTS  BlockCipherMode = 0x0000000B // XTS | XTS
	BlockCipherModeAEAD BlockCipherMode = 0x00000012 // AEAD | AEAD
)

// PaddingMethod is a KMIP padding method. | PaddingMethod 是 KMIP 填充方法。
type PaddingMethod uint32

// The KMIP padding methods. | KMIP 填充方法。
const (
	PaddingMethodNone     PaddingMethod = 0x00000001 // None | 无
	PaddingMethodOAEP     PaddingMethod = 0x00000002 // OAEP | OAEP
	PaddingMethodPKCS5    PaddingMethod = 0x00000003 // PKCS#5 | PKCS#5
	PaddingMethodPKCS1V15 PaddingMethod = 0x00000008 // PKCS#1 v1.5 | PKCS#1 v1.5
	PaddingMethodPSS      PaddingMethod = 0x0000000A // PSS | PSS
)

// DigitalSignatureAlgorithm is a KMIP digital signature algorithm. | DigitalSignatureAlgorithm 是 KMIP 数字签名算法。
type DigitalSignatureAlgorithm uint32

// The KMIP digital signature algorithms. | KMIP 数字签名算法。
const (
	DigitalSignatureRSAPKCS1SHA256 DigitalSignatureAlgorithm = 0x00000005 // SHA-256 with RSA | SHA-256 与 RSA
	DigitalSignatureRSAPKCS1SHA384 DigitalSignatureAlgorithm = 0x00000006 // SHA-384 with RSA | SHA-384 与 RSA
	DigitalSignatureRSAPKCS1SHA512 DigitalSignatureAlgorithm = 0x00000007 // SHA-512 with RSA | SHA-512 与 RSA
	DigitalSignatureRSAPSS         DigitalSignatureAlgorithm = 0x00000008 // RSASSA-PSS | RSASSA-PSS
	DigitalSignatureECDSASHA256    DigitalSignatureAlgorithm = 0x0000000E // ECDSA with SHA-256 | ECDSA 与 SHA-256
	DigitalSignatureECDSASHA384    DigitalSignatureAlgorithm = 0x0000000F // ECDSA with SHA-384 | ECDSA 与 SHA-384
	DigitalSignatureECDSASHA512    DigitalSignatureAlgorithm = 0x00000010 // ECDSA with SHA-512 | ECDSA 与 SHA-512
	DigitalSignatureEd25519        DigitalSignatureAlgorithm = 0x00000014 // Ed25519 (ydx extension value) | Ed25519（ydx 扩展值）
	DigitalSignatureSM2SM3         DigitalSignatureAlgorithm = 0x00000015 // SM2 with SM3 (ydx extension value) | SM2 与 SM3（ydx 扩展值）
)

// MaskGenerator is a KMIP mask generation function. | MaskGenerator 是 KMIP 掩码生成函数。
type MaskGenerator uint32

// The KMIP mask generation functions. | KMIP 掩码生成函数。
const (
	MaskGeneratorMGF1 MaskGenerator = 0x00000001 // MGF1 | MGF1
)

// ValidityIndicator is a KMIP signature/MAC validity indicator. | ValidityIndicator 是 KMIP 签名/MAC 有效性指示。
type ValidityIndicator uint32

// The KMIP validity indicators. | KMIP 有效性指示。
const (
	ValidityIndicatorValid   ValidityIndicator = 0x00000001 // Valid | 有效
	ValidityIndicatorInvalid ValidityIndicator = 0x00000002 // Invalid | 无效
	ValidityIndicatorUnknown ValidityIndicator = 0x00000003 // Unknown | 未知
)

// CredentialType is a KMIP credential type. | CredentialType 是 KMIP 凭据类型。
type CredentialType uint32

// The KMIP credential types. | KMIP 凭据类型。
const (
	CredentialTypeUsernameAndPassword CredentialType = 0x00000001 // Username and Password | 用户名与口令
	CredentialTypeDevice              CredentialType = 0x00000002 // Device | 设备
	CredentialTypeAttestation         CredentialType = 0x00000003 // Attestation | 证明
)

// BatchErrorContinuationOption is a KMIP batch error continuation option. | BatchErrorContinuationOption 是 KMIP 批处理错误继续选项。
type BatchErrorContinuationOption uint32

// The KMIP batch error continuation options. | KMIP 批处理错误继续选项。
const (
	BatchContinue BatchErrorContinuationOption = 0x00000001 // Continue | 继续
	BatchStop     BatchErrorContinuationOption = 0x00000002 // Stop | 停止
	BatchUndo     BatchErrorContinuationOption = 0x00000003 // Undo | 撤销
)
