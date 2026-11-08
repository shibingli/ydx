package jose

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"sync"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// The JWK key type names defined by RFC 7518 and RFC 8037. | RFC 7518 与 RFC 8037 定义的 JWK 密钥类型名。
const (
	// KeyTypeRSA is the RSA key type. | KeyTypeRSA 是 RSA 密钥类型。
	KeyTypeRSA = "RSA"
	// KeyTypeEC is the elliptic curve key type. | KeyTypeEC 是椭圆曲线密钥类型。
	KeyTypeEC = "EC"
	// KeyTypeOKP is the octet key pair type used by Ed25519 and X25519. | KeyTypeOKP 是 Ed25519 与 X25519 使用的八位组密钥对类型。
	KeyTypeOKP = "OKP"
	// KeyTypeOct is the symmetric key type. | KeyTypeOct 是对称密钥类型。
	KeyTypeOct = "oct"
)

// The curve names defined by RFC 7518 and RFC 8037. | RFC 7518 与 RFC 8037 定义的曲线名。
const (
	// CurveP256 is NIST P-256, used by ES256 and ECDH-ES. | CurveP256 是 NIST P-256，用于 ES256 与 ECDH-ES。
	CurveP256 = "P-256"
	// CurveP384 is NIST P-384, used by ES384 and ECDH-ES. | CurveP384 是 NIST P-384，用于 ES384 与 ECDH-ES。
	CurveP384 = "P-384"
	// CurveP521 is NIST P-521, used by ES512 and ECDH-ES. | CurveP521 是 NIST P-521，用于 ES512 与 ECDH-ES。
	CurveP521 = "P-521"
	// CurveEd25519 is the Edwards curve used by EdDSA. | CurveEd25519 是 EdDSA 使用的爱德华兹曲线。
	CurveEd25519 = "Ed25519"
	// CurveX25519 is the Montgomery curve used by ECDH-ES with OKP keys. | CurveX25519 是 OKP 密钥执行 ECDH-ES 时使用的蒙哥马利曲线。
	CurveX25519 = "X25519"
)

// OtherPrime is one additional RSA prime of a multi-prime key (RFC 7518 §6.3.2.7). | OtherPrime
// 是多素数 RSA 密钥中的一个附加素数（RFC 7518 §6.3.2.7）。
type OtherPrime struct {
	// R is the prime factor, base64url encoded. | R 是素数因子，base64url 编码。
	R string `json:"r"`
	// D is the factor CRT exponent, base64url encoded. | D 是该因子的 CRT 指数，base64url 编码。
	D string `json:"d"`
	// T is the factor CRT coefficient, base64url encoded. | T 是该因子的 CRT 系数，base64url 编码。
	T string `json:"t"`
}

// keyCache memoizes the standard-library key material derived from a JWK. | keyCache 缓存由 JWK
// 派生出的标准库密钥材料。
//
// Only pointer-typed keys (*rsa.PrivateKey, *ecdsa.PrivateKey, *ecdh.PrivateKey and their public
// counterparts) are memoized. Slice-typed values ([]byte for "oct", ed25519.PrivateKey and
// ed25519.PublicKey) are rebuilt on every call so a caller mutating a returned slice cannot corrupt
// later conversions. | 仅缓存指针类型的密钥（*rsa.PrivateKey、*ecdsa.PrivateKey、*ecdh.PrivateKey
// 及其公钥形式）。切片类型的值（"oct" 的 []byte、ed25519.PrivateKey 与 ed25519.PublicKey）每次都会
// 重新构建，避免调用方修改返回的切片后污染后续转换。
type keyCache struct {
	privOnce sync.Once
	priv     any
	privErr  error

	pubOnce sync.Once
	pub     any
	pubErr  error
}

// Key is a JSON Web Key (RFC 7517) covering RSA, EC, OKP and octet key types. | Key 是 JSON Web Key
// （RFC 7517），覆盖 RSA、EC、OKP 与对称密钥类型。
//
// The zero value is not a valid key. A Key is an immutable value once published: callers may share
// one instance between goroutines as long as nobody assigns to its fields. Methods that mutate the
// receiver's fields are not safe for concurrent use, and mutating a key after it has been used
// lowers the derived-key cache, which is only valid for the member values it was built from. | 零值
// 不是合法密钥。密钥发布后应视为不可变值：只要无人给其字段赋值，调用方可以在多个 goroutine 间共享
// 同一实例。修改接收者字段的方法不可并发调用；密钥一旦被使用后再修改，会保留基于旧成员值构建的派生
// 密钥缓存。
type Key struct {
	// Kty is the key type: "RSA", "EC", "OKP" or "oct". | Kty 是密钥类型："RSA"、"EC"、"OKP" 或 "oct"。
	Kty string `json:"kty"`
	// Use is the intended use, typically "sig" or "enc". | Use 是预期用途，通常为 "sig" 或 "enc"。
	Use string `json:"use,omitempty"`
	// KeyOps lists the permitted operations, for example "sign" and "verify". | KeyOps 列出允许的操作，例如 "sign" 与 "verify"。
	KeyOps []string `json:"key_ops,omitempty"`
	// Alg is the intended algorithm; empty means the key is not algorithm-bound. | Alg 是预期算法；为空表示密钥未绑定算法。
	Alg string `json:"alg,omitempty"`
	// Kid is the key identifier used to select the key during rotation. | Kid 是密钥标识，用于轮换期间选择密钥。
	Kid string `json:"kid,omitempty"`
	// X5c is the X.509 certificate chain, each entry standard base64 DER. | X5c 是 X.509 证书链，每项为标准 base64 的 DER。
	X5c []string `json:"x5c,omitempty"`
	// X5t is the SHA-1 certificate thumbprint, base64url encoded. | X5t 是证书的 SHA-1 指纹，base64url 编码。
	X5t string `json:"x5t,omitempty"`
	// X5tS256 is the SHA-256 certificate thumbprint, base64url encoded. | X5tS256 是证书的 SHA-256 指纹，base64url 编码。
	X5tS256 string `json:"x5t#S256,omitempty"`

	// N is the RSA modulus, base64url encoded. | N 是 RSA 模数，base64url 编码。
	N string `json:"n,omitempty"`
	// E is the RSA public exponent, base64url encoded. | E 是 RSA 公钥指数，base64url 编码。
	E string `json:"e,omitempty"`
	// D is the RSA private exponent or the EC/OKP private value, base64url encoded. | D 是 RSA 私钥指数或 EC/OKP 私有值，base64url 编码。
	D string `json:"d,omitempty"`
	// P is the first RSA prime factor, base64url encoded. | P 是第一个 RSA 素数因子，base64url 编码。
	P string `json:"p,omitempty"`
	// Q is the second RSA prime factor, base64url encoded. | Q 是第二个 RSA 素数因子，base64url 编码。
	Q string `json:"q,omitempty"`
	// DP is the first RSA CRT exponent, base64url encoded. | DP 是第一个 RSA CRT 指数，base64url 编码。
	DP string `json:"dp,omitempty"`
	// DQ is the second RSA CRT exponent, base64url encoded. | DQ 是第二个 RSA CRT 指数，base64url 编码。
	DQ string `json:"dq,omitempty"`
	// QI is the RSA CRT coefficient, base64url encoded. | QI 是 RSA CRT 系数，base64url 编码。
	QI string `json:"qi,omitempty"`
	// Oth holds additional primes of a multi-prime RSA key. | Oth 保存多素数 RSA 密钥的附加素数。
	Oth []OtherPrime `json:"oth,omitempty"`

	// Crv is the curve name for EC and OKP keys. | Crv 是 EC 与 OKP 密钥的曲线名。
	Crv string `json:"crv,omitempty"`
	// X is the EC x coordinate or the OKP public value, base64url encoded. | X 是 EC 的 x 坐标或 OKP 公钥值，base64url 编码。
	X string `json:"x,omitempty"`
	// Y is the EC y coordinate, base64url encoded. | Y 是 EC 的 y 坐标，base64url 编码。
	Y string `json:"y,omitempty"`

	// K is the symmetric key value of an "oct" key, base64url encoded. | K 是 "oct" 对称密钥的密钥值，base64url 编码。
	K string `json:"k,omitempty"`

	// cache holds lazily derived standard-library key material. It is never serialized, never
	// compared and never copied into a clone. | cache 保存延迟派生的标准库密钥材料。它不会被序列化、
	// 比较，也不会被复制到克隆中。
	cache *keyCache
}

// MarshalJSON encodes k as a JWK with only the members relevant to its type. | MarshalJSON 把 k
// 编码为只包含其类型相关成员的 JWK。
func (k Key) MarshalJSON() ([]byte, error) {
	type plain Key
	out, err := json.Marshal(plain(k))
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidKey, "encode JWK | 编码 JWK")
	}
	return out, nil
}

// Clone returns a deep copy of k. | Clone 返回 k 的深拷贝。
func (k *Key) Clone() *Key {
	if k == nil {
		return nil
	}
	c := *k
	c.KeyOps = append([]string(nil), k.KeyOps...)
	c.X5c = append([]string(nil), k.X5c...)
	if len(k.Oth) > 0 {
		c.Oth = append([]OtherPrime(nil), k.Oth...)
	}
	// The clone's fields may be edited independently, so it must not inherit key material derived
	// from the source member values. | 克隆的字段可以独立编辑，因此它不能继承由源成员值派生的密钥材料。
	c.cache = nil
	return &c
}

// withCache attaches an empty derived-key cache and returns k. | withCache 附加空的派生密钥缓存并
// 返回 k。
//
// It is called by every constructor that returns a freshly built key, before the key is shared
// between goroutines, so the cache pointer itself is never written concurrently. | 所有返回新构建密钥
// 的构造函数都会在密钥被多个 goroutine 共享之前调用它，因此缓存指针本身不会被并发写入。
func (k *Key) withCache() *Key {
	if k != nil && k.cache == nil {
		k.cache = &keyCache{}
	}
	return k
}

// Public returns a copy of k with all private material removed. | Public 返回移除全部私钥材料的 k
// 副本。
//
// For an "oct" key the symmetric value is retained, because an HMAC or key-wrap key has no public
// half. The receiver is not modified. | 对 "oct" 密钥保留对称密钥值，因为 HMAC 或密钥包装密钥
// 没有公钥部分。接收者不会被修改。
func (k *Key) Public() *Key {
	if k == nil {
		return nil
	}
	c := k.Clone()
	switch k.Kty {
	case KeyTypeRSA:
		c.D, c.P, c.Q, c.DP, c.DQ, c.QI = "", "", "", "", "", ""
		c.Oth = nil
	case KeyTypeEC, KeyTypeOKP:
		c.D = ""
	}
	return c
}

// PrivateKey returns the key as a standard-library private key value. | PrivateKey 把密钥转换为
// 标准库私钥值。
//
// The returned type is *rsa.PrivateKey for RSA, *ecdsa.PrivateKey for EC, ed25519.PrivateKey for
// Ed25519, *ecdh.PrivateKey for X25519, and []byte for "oct". A key without private material is
// reported as ErrNotPrivateKey. | 返回类型为：RSA 返回 *rsa.PrivateKey，EC 返回 *ecdsa.PrivateKey，
// Ed25519 返回 ed25519.PrivateKey，X25519 返回 *ecdh.PrivateKey，"oct" 返回 []byte。缺少私钥
// 材料时报告 ErrNotPrivateKey。
func (k *Key) PrivateKey() (any, error) {
	if k == nil {
		return nil, ErrInvalidKey
	}
	c := k.cache
	if c == nil || !k.cacheableKey() {
		return k.buildPrivateKey()
	}
	c.privOnce.Do(func() { c.priv, c.privErr = k.buildPrivateKey() })
	return c.priv, c.privErr
}

// buildPrivateKey derives the standard-library private key without consulting the cache. | buildPrivateKey
// 不经过缓存直接派生标准库私钥。
func (k *Key) buildPrivateKey() (any, error) {
	switch k.Kty {
	case KeyTypeRSA:
		return k.rsaPrivateKey()
	case KeyTypeEC:
		return k.ecPrivateKey()
	case KeyTypeOKP:
		return k.okpPrivateKey()
	case KeyTypeOct:
		secret, err := k.octets()
		if err != nil {
			return nil, err
		}
		return secret, nil
	default:
		return nil, errs.Detail(ErrInvalidKey, "unsupported kty=%[1]q | 不支持的 kty=%[1]q", k.Kty)
	}
}

// cacheableKey reports whether the derived key material is pointer-typed and therefore safe to
// memoize. | cacheableKey 报告派生密钥材料是否为指针类型，因而可以安全缓存。
func (k *Key) cacheableKey() bool {
	switch k.Kty {
	case KeyTypeRSA, KeyTypeEC:
		return true
	case KeyTypeOKP:
		return k.Crv == CurveX25519
	}
	return false
}

// PublicKey returns the key as a standard-library public key value. | PublicKey 把密钥转换为标准库
// 公钥值。
//
// The returned type is *rsa.PublicKey for RSA, *ecdsa.PublicKey for EC, ed25519.PublicKey for
// Ed25519, *ecdh.PublicKey for X25519, and []byte for "oct". | 返回类型为：RSA 返回 *rsa.PublicKey，
// EC 返回 *ecdsa.PublicKey，Ed25519 返回 ed25519.PublicKey，X25519 返回 *ecdh.PublicKey，
// "oct" 返回 []byte。
func (k *Key) PublicKey() (any, error) {
	if k == nil {
		return nil, ErrInvalidKey
	}
	c := k.cache
	if c == nil || !k.cacheableKey() {
		return k.buildPublicKey()
	}
	c.pubOnce.Do(func() { c.pub, c.pubErr = k.buildPublicKey() })
	return c.pub, c.pubErr
}

// buildPublicKey derives the standard-library public key without consulting the cache. | buildPublicKey
// 不经过缓存直接派生标准库公钥。
func (k *Key) buildPublicKey() (any, error) {
	switch k.Kty {
	case KeyTypeRSA:
		n, err := decodeMember("n", k.N)
		if err != nil {
			return nil, err
		}
		e, err := decodeExponent(k.E)
		if err != nil {
			return nil, err
		}
		if len(n) == 0 || e == 0 {
			return nil, errs.Detail(ErrInvalidKey, "RSA key is missing n or e | RSA 密钥缺少 n 或 e")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: e}, nil
	case KeyTypeEC:
		crv, err := ecCurve(k.Crv)
		if err != nil {
			return nil, err
		}
		return ecPoint(k, crv)
	case KeyTypeOKP:
		switch k.Crv {
		case CurveEd25519:
			x, err := decodeMember("x", k.X)
			if err != nil {
				return nil, err
			}
			if len(x) != ed25519.PublicKeySize {
				return nil, errs.Detail(ErrInvalidKey, "Ed25519 public key is %[1]d bytes | Ed25519 公钥为 %[1]d 字节", len(x))
			}
			return ed25519.PublicKey(x), nil
		case CurveX25519:
			x, err := decodeMember("x", k.X)
			if err != nil {
				return nil, err
			}
			pub, err := ecdh.X25519().NewPublicKey(x)
			if err != nil {
				return nil, errs.WrapDetail(err, ErrInvalidKey, "X25519 public key | X25519 公钥")
			}
			return pub, nil
		default:
			return nil, errs.Detail(ErrInvalidKey, "unsupported OKP crv=%[1]q | 不支持的 OKP crv=%[1]q", k.Crv)
		}
	case KeyTypeOct:
		return k.octets()
	default:
		return nil, errs.Detail(ErrInvalidKey, "unsupported kty=%[1]q | 不支持的 kty=%[1]q", k.Kty)
	}
}

// Thumbprint returns the RFC 7638 SHA-256 thumbprint of k as unpadded base64url. | Thumbprint 返回
// k 的 RFC 7638 SHA-256 指纹，使用无填充 base64url。
//
// The thumbprint covers only the required public members of the key type, so it is stable across
// rotations of kid, use and alg. | 指纹只覆盖密钥类型的必需公开成员，因此在 kid、use 与 alg 变化
// 时保持稳定。
func (k *Key) Thumbprint() (string, error) {
	if k == nil {
		return "", ErrInvalidKey
	}
	var canonical []byte
	switch k.Kty {
	case KeyTypeRSA:
		if k.N == "" || k.E == "" {
			return "", errs.Detail(ErrInvalidKey, "RSA thumbprint needs n and e | RSA 指纹需要 n 与 e")
		}
		canonical = append(canonical, `{"e":`...)
		canonical = appendJSONString(canonical, k.E)
		canonical = append(canonical, `,"kty":"RSA","n":`...)
		canonical = appendJSONString(canonical, k.N)
		canonical = append(canonical, '}')
	case KeyTypeEC:
		if k.Crv == "" || k.X == "" || k.Y == "" {
			return "", errs.Detail(ErrInvalidKey, "EC thumbprint needs crv, x and y | EC 指纹需要 crv、x 与 y")
		}
		canonical = append(canonical, `{"crv":`...)
		canonical = appendJSONString(canonical, k.Crv)
		canonical = append(canonical, `,"kty":"EC","x":`...)
		canonical = appendJSONString(canonical, k.X)
		canonical = append(canonical, `,"y":`...)
		canonical = appendJSONString(canonical, k.Y)
		canonical = append(canonical, '}')
	case KeyTypeOKP:
		if k.Crv == "" || k.X == "" {
			return "", errs.Detail(ErrInvalidKey, "OKP thumbprint needs crv and x | OKP 指纹需要 crv 与 x")
		}
		canonical = append(canonical, `{"crv":`...)
		canonical = appendJSONString(canonical, k.Crv)
		canonical = append(canonical, `,"kty":"OKP","x":`...)
		canonical = appendJSONString(canonical, k.X)
		canonical = append(canonical, '}')
	case KeyTypeOct:
		if k.K == "" {
			return "", errs.Detail(ErrInvalidKey, "oct thumbprint needs k | oct 指纹需要 k")
		}
		canonical = append(canonical, `{"k":`...)
		canonical = appendJSONString(canonical, k.K)
		canonical = append(canonical, `,"kty":"oct"}`...)
	default:
		return "", errs.Detail(ErrInvalidKey, "unsupported kty=%[1]q | 不支持的 kty=%[1]q", k.Kty)
	}
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// Validate checks the structural consistency of k and its declared alg. | Validate 检查 k 的结构
// 一致性及其声明的 alg。
//
// It verifies that the members required by the key type are present and decodable, that EC points
// lie on the named curve, that private EC material matches the published public point, and that a
// declared alg is compatible with the key type and size. | 它校验密钥类型所需的成员存在且可解码，
// EC 点位于指定曲线上，EC 私钥材料与公布的公钥点一致，以及声明的 alg 与密钥类型和长度兼容。
func (k *Key) Validate() error {
	if k == nil {
		return ErrInvalidKey
	}
	switch k.Kty {
	case KeyTypeRSA:
		if _, err := decodeMember("n", k.N); err != nil {
			return err
		}
		if _, err := decodeExponent(k.E); err != nil {
			return err
		}
		if k.D != "" {
			if _, err := k.rsaPrivateKey(); err != nil {
				return err
			}
		}
	case KeyTypeEC:
		crv, err := ecCurve(k.Crv)
		if err != nil {
			return err
		}
		if _, err := ecPoint(k, crv); err != nil {
			return err
		}
		if k.D != "" {
			if _, err := k.ecPrivateKey(); err != nil {
				return err
			}
		}
	case KeyTypeOKP:
		switch k.Crv {
		case CurveEd25519:
			x, err := decodeMember("x", k.X)
			if err != nil {
				return err
			}
			if len(x) != ed25519.PublicKeySize {
				return errs.Detail(ErrInvalidKey, "Ed25519 public key is %[1]d bytes | Ed25519 公钥为 %[1]d 字节", len(x))
			}
			if k.D != "" {
				if _, err := k.okpPrivateKey(); err != nil {
					return err
				}
			}
		case CurveX25519:
			x, err := decodeMember("x", k.X)
			if err != nil {
				return err
			}
			if _, err := ecdh.X25519().NewPublicKey(x); err != nil {
				return errs.WrapDetail(err, ErrInvalidKey, "X25519 public key | X25519 公钥")
			}
			if k.D != "" {
				if _, err := k.okpPrivateKey(); err != nil {
					return err
				}
			}
		default:
			return errs.Detail(ErrInvalidKey, "unsupported OKP crv=%[1]q | 不支持的 OKP crv=%[1]q", k.Crv)
		}
	case KeyTypeOct:
		secret, err := k.octets()
		if err != nil {
			return err
		}
		if len(secret) == 0 {
			return errs.Detail(ErrInvalidKey, "oct key is empty | oct 密钥为空")
		}
	default:
		return errs.Detail(ErrInvalidKey, "unsupported kty=%[1]q | 不支持的 kty=%[1]q", k.Kty)
	}
	if k.Alg != "" {
		if err := checkKeyAlg(k, k.Alg); err != nil {
			return err
		}
	}
	return nil
}

// ParseKey parses one JWK. | ParseKey 解析单个 JWK。
//
// Parsing is structural and does not run Validate; a caller that is about to use the key should
// call Validate or rely on PrivateKey / PublicKey, which reject malformed material. | 解析只做结构
// 处理，不执行 Validate；准备使用密钥的调用方应调用 Validate，或依赖 PrivateKey / PublicKey，
// 二者会拒绝非法材料。
func ParseKey(data []byte) (*Key, error) {
	var k Key
	if err := unmarshal(data, &k); err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidKey, "parse JWK | 解析 JWK")
	}
	if k.Kty == "" {
		return nil, errs.Detail(ErrInvalidKey, "JWK has no kty | JWK 缺少 kty")
	}
	return k.withCache(), nil
}

// octets returns the decoded symmetric secret of an "oct" key. | octets 返回 "oct" 密钥解码后的
// 对称密钥值。
func (k *Key) octets() ([]byte, error) {
	if k.Kty != KeyTypeOct {
		return nil, errs.Detail(ErrKeyTypeMismatch, "key kty=%[1]q is not oct | 密钥 kty=%[1]q 不是 oct", k.Kty)
	}
	secret, err := decodeMember("k", k.K)
	if err != nil {
		return nil, err
	}
	if len(secret) == 0 {
		return nil, errs.Detail(ErrInvalidKey, "oct key is empty | oct 密钥为空")
	}
	return secret, nil
}

// rsaPrivateKey reconstructs an *rsa.PrivateKey. | rsaPrivateKey 重建 *rsa.PrivateKey。
func (k *Key) rsaPrivateKey() (*rsa.PrivateKey, error) {
	if k.D == "" {
		return nil, ErrNotPrivateKey
	}
	n, err := decodeMember("n", k.N)
	if err != nil {
		return nil, err
	}
	e, err := decodeExponent(k.E)
	if err != nil {
		return nil, err
	}
	d, err := decodeMember("d", k.D)
	if err != nil {
		return nil, err
	}
	p, err := decodeMember("p", k.P)
	if err != nil {
		return nil, err
	}
	q, err := decodeMember("q", k.Q)
	if err != nil {
		return nil, err
	}
	if len(p) == 0 || len(q) == 0 {
		return nil, errs.Detail(ErrInvalidKey, "RSA private key requires p and q | RSA 私钥需要 p 与 q")
	}
	primes := []*big.Int{new(big.Int).SetBytes(p), new(big.Int).SetBytes(q)}
	for i := range k.Oth {
		r, err := decodeMember("oth.r", k.Oth[i].R)
		if err != nil {
			return nil, err
		}
		if len(r) == 0 {
			return nil, errs.Detail(ErrInvalidKey, "RSA other prime is empty | RSA 附加素数为空")
		}
		primes = append(primes, new(big.Int).SetBytes(r))
	}
	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: new(big.Int).SetBytes(n), E: e},
		D:         new(big.Int).SetBytes(d),
		Primes:    primes,
	}
	if err := priv.Validate(); err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidKey, "RSA private key | RSA 私钥")
	}
	priv.Precompute()
	return priv, nil
}

// ecPrivateKey reconstructs an *ecdsa.PrivateKey. | ecPrivateKey 重建 *ecdsa.PrivateKey。
func (k *Key) ecPrivateKey() (*ecdsa.PrivateKey, error) {
	if k.D == "" {
		return nil, ErrNotPrivateKey
	}
	crv, err := ecCurve(k.Crv)
	if err != nil {
		return nil, err
	}
	dBytes, err := decodeMember("d", k.D)
	if err != nil {
		return nil, err
	}
	if len(dBytes) == 0 {
		return nil, errs.Detail(ErrInvalidKey, "EC private value is empty | EC 私有值为空")
	}
	size := (crv.Params().BitSize + 7) / 8
	// A JWK integer drops leading zero bytes, while the standard-library raw scalar form is
	// fixed-width, so left-pad before parsing. | JWK 整数会去掉前导零字节，而标准库的原始标量形式是
	// 定宽的，因此解析前先左补零。
	if len(dBytes) > size {
		return nil, errs.Detail(ErrInvalidKey, "EC private value is out of range | EC 私有值超出范围")
	}
	padded := make([]byte, size)
	copy(padded[size-len(dBytes):], dBytes)
	priv, err := ecdsa.ParseRawPrivateKey(crv, padded)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidKey, "EC private value | EC 私有值")
	}
	if k.X != "" || k.Y != "" {
		if k.X == "" || k.Y == "" {
			return nil, errs.Detail(ErrInvalidKey, "EC key has only one coordinate | EC 密钥只包含一个坐标")
		}
		pub, err := ecPoint(k, crv)
		if err != nil {
			return nil, err
		}
		if !pub.Equal(&priv.PublicKey) {
			return nil, errs.Detail(ErrInvalidKey, "EC public point does not match d | EC 公钥点与 d 不匹配")
		}
	}
	return priv, nil
}

// okpPrivateKey reconstructs an Ed25519 or X25519 private key. | okpPrivateKey 重建 Ed25519 或
// X25519 私钥。
func (k *Key) okpPrivateKey() (any, error) {
	if k.D == "" {
		return nil, ErrNotPrivateKey
	}
	d, err := decodeMember("d", k.D)
	if err != nil {
		return nil, err
	}
	switch k.Crv {
	case CurveEd25519:
		seed := d
		if len(d) == ed25519.PrivateKeySize {
			seed = d[:ed25519.SeedSize]
		}
		if len(seed) != ed25519.SeedSize {
			return nil, errs.Detail(ErrInvalidKey, "Ed25519 private value is %[1]d bytes | Ed25519 私有值为 %[1]d 字节", len(d))
		}
		priv := ed25519.NewKeyFromSeed(seed)
		if k.X != "" {
			x, err := decodeMember("x", k.X)
			if err != nil {
				return nil, err
			}
			if len(x) != ed25519.PublicKeySize || string(x) != string(priv.Public().(ed25519.PublicKey)) {
				return nil, errs.Detail(ErrInvalidKey, "Ed25519 public key does not match d | Ed25519 公钥与 d 不匹配")
			}
		}
		return priv, nil
	case CurveX25519:
		priv, err := ecdh.X25519().NewPrivateKey(d)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidKey, "X25519 private key | X25519 私钥")
		}
		if k.X != "" {
			x, err := decodeMember("x", k.X)
			if err != nil {
				return nil, err
			}
			if string(x) != string(priv.PublicKey().Bytes()) {
				return nil, errs.Detail(ErrInvalidKey, "X25519 public key does not match d | X25519 公钥与 d 不匹配")
			}
		}
		return priv, nil
	default:
		return nil, errs.Detail(ErrInvalidKey, "unsupported OKP crv=%[1]q | 不支持的 OKP crv=%[1]q", k.Crv)
	}
}

// decodeMember base64url-decodes a required JWK member. | decodeMember 以 base64url 解码必需的
// JWK 成员。
func decodeMember(name, value string) ([]byte, error) {
	if value == "" {
		return nil, errs.Detail(ErrInvalidKey, "missing %[1]s | 缺少 %[1]s", name)
	}
	out, err := strictRawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidKey, "member %[1]s | 成员 %[1]s", name)
	}
	return out, nil
}

// decodeExponent decodes an RSA public exponent into an int. | decodeExponent 把 RSA 公钥指数解码
// 为 int。
func decodeExponent(value string) (int, error) {
	raw, err := decodeMember("e", value)
	if err != nil {
		return 0, err
	}
	e := new(big.Int).SetBytes(raw)
	if !e.IsInt64() || e.Sign() <= 0 {
		return 0, errs.Detail(ErrInvalidKey, "RSA exponent is out of range | RSA 指数超出范围")
	}
	v := e.Int64()
	if v < 3 || v > 1<<31-1 {
		return 0, errs.Detail(ErrInvalidKey, "RSA exponent %[1]d is not usable | RSA 指数 %[1]d 不可用", v)
	}
	return int(v), nil
}

// ecCurve maps a JWK curve name to an elliptic curve. | ecCurve 把 JWK 曲线名映射为椭圆曲线。
func ecCurve(name string) (elliptic.Curve, error) {
	switch name {
	case CurveP256:
		return elliptic.P256(), nil
	case CurveP384:
		return elliptic.P384(), nil
	case CurveP521:
		return elliptic.P521(), nil
	default:
		return nil, errs.Detail(ErrInvalidKey, "unsupported EC crv=%[1]q | 不支持的 EC crv=%[1]q", name)
	}
}

// ecCurveName returns the JWK name of an elliptic curve. | ecCurveName 返回椭圆曲线的 JWK 名称。
func ecCurveName(c elliptic.Curve) (string, bool) {
	if c == nil {
		return "", false
	}
	switch c.Params().Name {
	case elliptic.P256().Params().Name:
		return CurveP256, true
	case elliptic.P384().Params().Name:
		return CurveP384, true
	case elliptic.P521().Params().Name:
		return CurveP521, true
	}
	return "", false
}

// ecPoint decodes and validates the public point of an EC key. | ecPoint 解码并校验 EC 密钥的公钥点。
//
// The coordinates are assembled into the SEC 1 uncompressed form and parsed by the standard library,
// which rejects off-curve points, the point at infinity and non-NIST curves. | 坐标被组装为 SEC 1
// 未压缩形式并交给标准库解析，由标准库拒绝曲线外点、无穷远点与非 NIST 曲线。
func ecPoint(k *Key, crv elliptic.Curve) (*ecdsa.PublicKey, error) {
	xBytes, err := decodeMember("x", k.X)
	if err != nil {
		return nil, err
	}
	yBytes, err := decodeMember("y", k.Y)
	if err != nil {
		return nil, err
	}
	size := (crv.Params().BitSize + 7) / 8
	if len(xBytes) != size || len(yBytes) != size {
		return nil, errs.Detail(ErrInvalidKey, "EC coordinates must be %[1]d bytes | EC 坐标必须为 %[1]d 字节", size)
	}
	point := make([]byte, 1+2*size)
	point[0] = 4
	copy(point[1:], xBytes)
	copy(point[1+size:], yBytes)
	pub, err := ecdsa.ParseUncompressedPublicKey(crv, point)
	if err != nil {
		return nil, errs.Detail(ErrInvalidKey, "EC point is not on crv=%[1]q | EC 点不在 crv=%[1]q 上", k.Crv)
	}
	return pub, nil
}

// checkKeyUse reports whether the optional use and key_ops metadata of key permits op. | checkKeyUse
// 报告 key 可选的 use 与 key_ops 元数据是否允许 op。
//
// The checks follow RFC 7517 §4.2 and §4.3. An empty use or key_ops imposes no restriction, so
// providers that publish no metadata are unaffected. | 检查依据 RFC 7517 §4.2 与 §4.3。use 或
// key_ops 为空时不施加限制，因此不发布元数据的提供方不受影响。
func checkKeyUse(key *Key, op string) error {
	if key == nil {
		return ErrInvalidKey
	}
	switch op {
	case "sign", "verify":
		if key.Use != "" && key.Use != "sig" {
			return errs.Detail(ErrInvalidKey, "key use=%[1]q does not permit %[2]s | 密钥 use=%[1]q 不允许 %[2]s", key.Use, op)
		}
	case "encrypt", "decrypt":
		if key.Use != "" && key.Use != "enc" {
			return errs.Detail(ErrInvalidKey, "key use=%[1]q does not permit %[2]s | 密钥 use=%[1]q 不允许 %[2]s", key.Use, op)
		}
	default:
		return errs.Detail(ErrInvalidKey, "unknown key operation %[1]q | 未知密钥操作 %[1]q", op)
	}
	if len(key.KeyOps) == 0 {
		return nil
	}
	var permitted [4]string
	n := 0
	switch op {
	case "sign":
		permitted[0] = "sign"
		n = 1
	case "verify":
		permitted[0] = "verify"
		n = 1
	case "encrypt":
		permitted[0], permitted[1], permitted[2] = "encrypt", "wrapKey", "deriveKey"
		permitted[3] = "deriveBits"
		n = 4
	case "decrypt":
		permitted[0], permitted[1], permitted[2] = "decrypt", "unwrapKey", "deriveKey"
		permitted[3] = "deriveBits"
		n = 4
	}
	for _, want := range permitted[:n] {
		for _, have := range key.KeyOps {
			if have == want {
				return nil
			}
		}
	}
	return errs.Detail(ErrInvalidKey, "key_ops=%[1]v does not permit %[2]s | key_ops=%[1]v 不允许 %[2]s", key.KeyOps, op)
}

// checkKeyAlg reports whether key can perform alg. | checkKeyAlg 报告 key 能否执行 alg。
func checkKeyAlg(key *Key, alg string) error {
	if key == nil {
		return ErrInvalidKey
	}
	mismatch := func(want string) error {
		return errs.Detail(ErrKeyTypeMismatch, "alg=%[1]q requires %[2]s, key is kty=%[3]q crv=%[4]q | alg=%[1]q 需要 %[2]s，密钥为 kty=%[3]q crv=%[4]q", alg, want, key.Kty, key.Crv)
	}
	switch alg {
	case "HS256", "HS384", "HS512":
		if key.Kty != KeyTypeOct {
			return mismatch(KeyTypeOct)
		}
		secret, err := key.octets()
		if err != nil {
			return err
		}
		h, _ := jwsHash(alg)
		if len(secret) < h.Size() {
			return errs.Detail(ErrWeakKey, "alg=%[1]s needs at least %[2]d key bytes | 算法 %[1]s 至少需要 %[2]d 字节密钥", alg, h.Size())
		}
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
		"RSA-OAEP", "RSA-OAEP-256", "RSA1_5":
		if key.Kty != KeyTypeRSA {
			return mismatch(KeyTypeRSA)
		}
		// RFC 7518 §3.3 and §4.3 require a modulus of at least 2048 bits for these algorithms.
		// Family-only checks may run on a key without material; those keys are rejected later
		// when the standard-library key is derived. | RFC 7518 §3.3 与 §4.3 要求这些算法使用至少
		// 2048 位的模数。仅做算法族检查时密钥可能尚无材料，这类密钥随后在派生标准库密钥时被拒绝。
		if key.N != "" {
			pub, err := key.PublicKey()
			if err != nil {
				return err
			}
			rsaPub, ok := pub.(*rsa.PublicKey)
			if !ok {
				return mismatch(KeyTypeRSA)
			}
			if rsaPub.N == nil || rsaPub.N.BitLen() < 2048 {
				return errs.Detail(ErrWeakKey, "alg=%[1]s needs a 2048-bit RSA key | 算法 %[1]s 需要 2048 位 RSA 密钥", alg)
			}
		}
	case "ES256":
		if key.Kty != KeyTypeEC || key.Crv != CurveP256 {
			return mismatch("EC P-256")
		}
	case "ES384":
		if key.Kty != KeyTypeEC || key.Crv != CurveP384 {
			return mismatch("EC P-384")
		}
	case "ES512":
		if key.Kty != KeyTypeEC || key.Crv != CurveP521 {
			return mismatch("EC P-521")
		}
	case "EdDSA":
		if key.Kty != KeyTypeOKP || key.Crv != CurveEd25519 {
			return mismatch("OKP Ed25519")
		}
	case "A128KW", "A192KW", "A256KW":
		if key.Kty != KeyTypeOct {
			return mismatch(KeyTypeOct)
		}
		secret, err := key.octets()
		if err != nil {
			return err
		}
		want := map[string]int{"A128KW": 16, "A192KW": 24, "A256KW": 32}[alg]
		if len(secret) != want {
			return errs.Detail(ErrWeakKey, "alg=%[1]s needs a %[2]d-byte key | 算法 %[1]s 需要 %[2]d 字节密钥", alg, want)
		}
	case "dir":
		if key.Kty != KeyTypeOct {
			return mismatch(KeyTypeOct)
		}
	case "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW":
		if !isECDHKey(key) {
			return mismatch("EC or OKP X25519")
		}
	default:
		return errs.Detail(ErrAlgNotAllowed, "alg=%[1]q | 算法=%[1]q", alg)
	}
	return nil
}

// isECDHKey reports whether key can participate in ECDH-ES. | isECDHKey 报告 key 能否参与 ECDH-ES。
func isECDHKey(key *Key) bool {
	if key == nil {
		return false
	}
	if key.Kty == KeyTypeOKP {
		return key.Crv == CurveX25519
	}
	if key.Kty != KeyTypeEC {
		return false
	}
	switch key.Crv {
	case CurveP256, CurveP384, CurveP521:
		return true
	}
	return false
}
