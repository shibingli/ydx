package oauth2

import "strconv"

// Hash tags keep every key touched by one Lua script in the same Redis Cluster slot.
// | 哈希标签让单个脚本访问的所有键落在同一个 Redis Cluster 槽位。
const (
	// codesTag indexes authorization codes. | codesTag 索引授权码。
	codesTag = "{authstore:oauth2:codes}"
	// refreshTag indexes refresh tokens, their families and their subjects.
	// | refreshTag 索引刷新令牌、其家族与主体。
	refreshTag = "{authstore:oauth2:refresh}"
	// accessTag indexes opaque access tokens. | accessTag 索引不透明访问令牌。
	accessTag = "{authstore:oauth2:access}"
	// devicesTag indexes device authorization grants and user codes.
	// | devicesTag 索引设备授权许可与用户码。
	devicesTag = "{authstore:oauth2:devices}"
	// parTag indexes pushed authorization requests. | parTag 索引推送授权请求。
	parTag = "{authstore:oauth2:par}"
	// clientsTag indexes client registrations. | clientsTag 索引客户端注册。
	clientsTag = "{authstore:oauth2:clients}"
	// noncesTag indexes DPoP nonces. | noncesTag 索引 DPoP nonce。
	noncesTag = "{authstore:oauth2:nonces}"
	// replayTag indexes DPoP proof identifiers. | replayTag 索引 DPoP 证明标识。
	replayTag = "{authstore:oauth2:replay}"
	// scopesTag indexes registered scopes. | scopesTag 索引已注册作用域。
	scopesTag = "{authstore:oauth2:scopes}"
)

// keys builds every key below one configurable namespace. | keys 在一个可配置命名空间下构造所有键。
type keys struct {
	// prefix is the caller-configured namespace. | prefix 是调用方配置的命名空间。
	prefix string
}

// newKeys returns a key builder for prefix. | newKeys 返回 prefix 的键构造器。
func newKeys(prefix string) keys {
	return keys{prefix: prefix}
}

// segment encodes one arbitrary string as a length-prefixed key segment. The length prefix makes
// concatenations injective even when values contain the separator byte. | segment 把任意字符串编码为
// 带长度前缀的键段。长度前缀使拼接即使值包含分隔字节也无歧义。
func segment(value string) string {
	return strconv.Itoa(len(value)) + ":" + value
}

// codesAll is the set holding every authorization-code key. | codesAll 是保存全部授权码键的集合。
func (k keys) codesAll() string { return k.prefix + codesTag + ":all" }

// code is the hash holding one authorization code. | code 是保存单个授权码的哈希。
func (k keys) code(codeHash string) string {
	return k.prefix + codesTag + ":code:" + segment(codeHash)
}

// refreshAll is the set holding every refresh-token key. | refreshAll 是保存全部刷新令牌键的集合。
func (k keys) refreshAll() string { return k.prefix + refreshTag + ":all" }

// refreshToken is the hash holding one refresh token. | refreshToken 是保存单个刷新令牌的哈希。
func (k keys) refreshToken(tokenHash string) string {
	return k.prefix + refreshTag + ":token:" + segment(tokenHash)
}

// refreshFamily is the set holding every token key of one family. | refreshFamily 是保存单个家族全部令牌键的集合。
func (k keys) refreshFamily(familyID string) string {
	return k.prefix + refreshTag + ":family:" + segment(familyID)
}

// refreshSubject is the set holding every token key of one client and subject.
// | refreshSubject 是保存单个客户端与主体全部令牌键的集合。
func (k keys) refreshSubject(clientID, subject string) string {
	return k.prefix + refreshTag + ":subject:" + segment(clientID) + ":" + segment(subject)
}

// accessAll is the set holding every access-token key. | accessAll 是保存全部访问令牌键的集合。
func (k keys) accessAll() string { return k.prefix + accessTag + ":all" }

// accessToken is the hash holding one opaque access token. | accessToken 是保存单个不透明访问令牌的哈希。
func (k keys) accessToken(tokenHash string) string {
	return k.prefix + accessTag + ":token:" + segment(tokenHash)
}

// devicesAll is the set holding every device-code key. | devicesAll 是保存全部设备码键的集合。
func (k keys) devicesAll() string { return k.prefix + devicesTag + ":all" }

// device is the hash holding one device authorization grant. | device 是保存单个设备授权许可的哈希。
func (k keys) device(deviceCodeHash string) string {
	return k.prefix + devicesTag + ":code:" + segment(deviceCodeHash)
}

// deviceUser is the index from a short user code to its device-code key.
// | deviceUser 是从短用户码到设备码键的索引。
func (k keys) deviceUser(userCode string) string {
	return k.prefix + devicesTag + ":user:" + segment(userCode)
}

// parAll is the set holding every pushed-authorization-request key.
// | parAll 是保存全部推送授权请求键的集合。
func (k keys) parAll() string { return k.prefix + parTag + ":all" }

// par is the hash holding one pushed authorization request. | par 是保存单个推送授权请求的哈希。
func (k keys) par(requestURI string) string {
	return k.prefix + parTag + ":request:" + segment(requestURI)
}

// clientsAll is the set holding every client ID. | clientsAll 是保存全部客户端标识的集合。
func (k keys) clientsAll() string { return k.prefix + clientsTag + ":all" }

// client is the hash holding one client registration. | client 是保存单个客户端注册的哈希。
func (k keys) client(id string) string {
	return k.prefix + clientsTag + ":client:" + segment(id)
}

// clientPrefix is the prefix used by the list Lua script to rebuild client keys.
// | clientPrefix 是列表脚本重建客户端键时使用的前缀。
func (k keys) clientPrefix() string { return k.prefix + clientsTag + ":client:" }

// noncesExpiry is the hash from a nonce to its exact expiry. | noncesExpiry 是从 nonce 到精确期限的哈希。
func (k keys) noncesExpiry() string { return k.prefix + noncesTag + ":expiry" }

// noncesIndex is the sorted set of nonces scored by expiry second. | noncesIndex 是按期限秒评分的 nonce 有序集合。
func (k keys) noncesIndex() string { return k.prefix + noncesTag + ":index" }

// replayJTI is the key recording one DPoP proof identifier. | replayJTI 是记录单个 DPoP 证明标识的键。
func (k keys) replayJTI(jti string) string {
	return k.prefix + replayTag + ":jti:" + segment(jti)
}

// scopesDefs is the hash from a scope name to its definition JSON. | scopesDefs 是从作用域名到定义 JSON 的哈希。
func (k keys) scopesDefs() string { return k.prefix + scopesTag + ":defs" }

// scopesOrder is the list preserving scope registration order. | scopesOrder 是保留作用域注册顺序的列表。
func (k keys) scopesOrder() string { return k.prefix + scopesTag + ":order" }
