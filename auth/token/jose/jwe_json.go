package jose

import (
	"context"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// maxJWERecipients bounds the recipients of one JWE JSON serialization. | maxJWERecipients 限制一个
// JWE JSON 序列化的接收方数量。
const maxJWERecipients = 64

// jweJSONRecipient is one recipient entry of the general JWE JSON serialization. | jweJSONRecipient
// 是通用 JWE JSON 序列化的一个接收方条目。
type jweJSONRecipient struct {
	// Header is the per-recipient unprotected header, emitted when non-empty. | Header 是每接收方
	// 非保护头部，非空时写出。
	Header map[string]any `json:"header,omitempty"`
	// EncryptedKey is the base64url encrypted key, omitted for dir and ECDH-ES. | EncryptedKey 是
	// base64url 加密密钥，dir 与 ECDH-ES 时省略。
	EncryptedKey string `json:"encrypted_key,omitempty"`
}

// jweJSONDoc is the wire form of a flattened or general JWE JSON serialization. | jweJSONDoc 是扁平
// 或通用 JWE JSON 序列化的线格式。
type jweJSONDoc struct {
	// Protected is the base64url protected header. | Protected 是 base64url 受保护头部。
	Protected string `json:"protected"`
	// Unprotected is the shared unprotected header. | Unprotected 是共享非保护头部。
	Unprotected map[string]any `json:"unprotected,omitempty"`
	// Header is the flattened per-recipient header. | Header 是扁平的每接收方头部。
	Header map[string]any `json:"header,omitempty"`
	// EncryptedKey is the flattened encrypted key. | EncryptedKey 是扁平的加密密钥。
	EncryptedKey string `json:"encrypted_key,omitempty"`
	// AAD is the base64url additional authenticated data member. | AAD 是 base64url 附加认证数据成员。
	AAD *string `json:"aad,omitempty"`
	// IV is the base64url initialization vector. | IV 是 base64url 初始化向量。
	IV string `json:"iv"`
	// Ciphertext is the base64url ciphertext. | Ciphertext 是 base64url 密文。
	Ciphertext string `json:"ciphertext"`
	// Tag is the base64url authentication tag. | Tag 是 base64url 认证标签。
	Tag string `json:"tag"`
	// Recipients holds the general-form recipient entries. | Recipients 保存通用形式的接收方条目。
	Recipients []jweJSONRecipient `json:"recipients,omitempty"`
}

// jweJSONParsed is a parsed flattened or general JWE JSON serialization. | jweJSONParsed 是解析后的
// 扁平或通用 JWE JSON 序列化。
type jweJSONParsed struct {
	// protectedSeg is the protected header segment exactly as it appeared on the wire. | protectedSeg
	// 是线格式中原样的受保护头部段。
	protectedSeg string
	// protected is the decoded protected header. | protected 是解码后的受保护头部。
	protected Header
	// unprotected is the decoded shared unprotected header. | unprotected 是解码后的共享非保护头部。
	unprotected Header
	// general reports whether the recipients array was present. | general 报告 recipients 数组是否
	// 存在。
	general bool
	// recipients holds one entry for flattened form and one or more for general form. | recipients
	// 在扁平形式下保存一个条目，在通用形式下保存一个或多个条目。
	recipients []parsedJWERecipient
	// iv, ciphertext and tag are the decoded content-encryption inputs. | iv、ciphertext 与 tag 是
	// 解码后的内容加密输入。
	iv, ciphertext, tag []byte
	// aadInput is the authenticated data passed to openContent. | aadInput 是传给 openContent 的
	// 认证数据。
	aadInput []byte
}

// parsedJWERecipient is one parsed recipient entry. | parsedJWERecipient 是一个解析后的接收方条目。
type parsedJWERecipient struct {
	// header is the per-recipient unprotected header. | header 是每接收方非保护头部。
	header Header
	// encryptedKey is the decoded encrypted key. | encryptedKey 是解码后的加密密钥。
	encryptedKey []byte
}

// jweRecipientPlan is one validated recipient during encryption. | jweRecipientPlan 是加密期间的一个
// 已校验接收方。
type jweRecipientPlan struct {
	// key is the recipient key. | key 是接收方密钥。
	key *Key
	// alg is the resolved key-management algorithm. | alg 是解析后的密钥管理算法。
	alg string
	// kid is the resolved key identifier. | kid 是解析后的密钥标识。
	kid string
	// header is the per-recipient header in the general form, nil in the single-key form. | header
	// 是通用形式下的每接收方头部，单密钥形式下为 nil。
	header map[string]any
	// encryptedKey is the wrapped CEK. | encryptedKey 是包装后的 CEK。
	encryptedKey []byte
}

// encryptJSON builds a flattened or general JWE JSON serialization. | encryptJSON 构建扁平或通用
// JWE JSON 序列化。
func encryptJSON(plaintext []byte, key *Key, opts EncryptOptions) (string, error) {
	enc := opts.Enc
	if !supportedEnc(enc) {
		return "", errs.Detail(ErrUnsupportedEnc, "enc=%[1]q | enc=%[1]q", enc)
	}
	zip := opts.Zip
	if zip != "" && zip != ZipDEF {
		return "", errs.Detail(ErrInvalidConfig, "zip=%[1]q | zip=%[1]q", zip)
	}
	if key != nil && len(opts.Recipients) > 0 {
		return "", errs.Detail(ErrInvalidConfig, "key and Recipients are mutually exclusive | key 与 Recipients 互斥")
	}
	if len(opts.Recipients) > maxJWERecipients {
		return "", errs.Detail(ErrInvalidConfig, "too many recipients: %[1]d | 接收方过多：%[1]d", len(opts.Recipients))
	}
	if len(opts.Recipients) > 0 && opts.Kid != "" {
		return "", errs.Detail(ErrInvalidConfig, "Kid belongs to each Recipient | Kid 属于各个 Recipient")
	}
	if opts.Serialization == SerializationFlattened && len(opts.Recipients) > 1 {
		return "", errs.Detail(ErrInvalidConfig, "flattened carries exactly one recipient | 扁平形式仅承载一个接收方")
	}
	if err := validateJWEUnprotectedEncrypt(opts.Unprotected); err != nil {
		return "", err
	}

	plans, err := buildJWERecipientPlans(key, opts)
	if err != nil {
		return "", err
	}
	direct := false
	for i := range plans {
		if plans[i].alg == AlgDir || plans[i].alg == AlgECDHES {
			direct = true
		}
	}
	if direct && len(plans) > 1 {
		return "", errs.Detail(ErrInvalidConfig, "dir and ECDH-ES accept one recipient | dir 与 ECDH-ES 仅接受一个接收方")
	}

	var sharedCEK []byte
	if !direct {
		p, _ := encParamsFor(enc)
		sharedCEK, err = randomBytes(p.cekLen)
		if err != nil {
			return "", err
		}
	}
	var contentCEK []byte
	var singleEPK *Key
	recipientsMode := len(opts.Recipients) > 0
	for i := range plans {
		cek, encryptedKey, epk, err := encryptCEK(plans[i].alg, plans[i].key, enc, sharedCEK, opts.APU, opts.APV)
		if err != nil {
			return "", err
		}
		if i == 0 {
			contentCEK = cek
		}
		plans[i].encryptedKey = encryptedKey
		if epk != nil {
			if recipientsMode {
				plans[i].header["epk"] = epk
			} else {
				singleEPK = epk
			}
		}
	}

	protected := make(map[string]any, 8)
	protected["enc"] = enc
	if zip != "" {
		protected["zip"] = zip
	}
	if opts.Typ != "" {
		protected["typ"] = opts.Typ
	}
	if opts.Cty != "" {
		protected["cty"] = opts.Cty
	}
	if len(opts.APU) > 0 {
		protected["apu"] = base64.RawURLEncoding.EncodeToString(opts.APU)
	}
	if len(opts.APV) > 0 {
		protected["apv"] = base64.RawURLEncoding.EncodeToString(opts.APV)
	}
	if !recipientsMode {
		protected["alg"] = plans[0].alg
		if plans[0].kid != "" {
			protected["kid"] = plans[0].kid
		}
		if singleEPK != nil {
			protected["epk"] = singleEPK
		}
	}
	for i := range plans {
		merged, err := mergeJWEHeaders(protected, opts.Unprotected, plans[i].header)
		if err != nil {
			return "", err
		}
		if _, err := jweHeaderFromMap(map[string]any(merged)); err != nil {
			return "", err
		}
	}

	headerBytes, err := json.Marshal(protected)
	if err != nil {
		return "", errs.WrapDetail(err, ErrInvalidHeader, "encode JWE protected header | 编码 JWE 受保护头部")
	}
	protectedSeg := EncodeSegment(headerBytes)
	aadInput := []byte(protectedSeg)
	var aadMember *string
	if opts.AAD != nil {
		s := EncodeSegment(opts.AAD)
		aadMember = &s
		aadInput = append(aadInput, '.')
		aadInput = append(aadInput, s...)
	}
	data := plaintext
	if zip == ZipDEF {
		data, err = deflate(plaintext)
		if err != nil {
			return "", err
		}
	}
	iv, ciphertext, tag, err := sealContent(enc, contentCEK, aadInput, data)
	if err != nil {
		return "", err
	}

	doc := &jweJSONDoc{
		Protected:   protectedSeg,
		Unprotected: opts.Unprotected,
		AAD:         aadMember,
		IV:          EncodeSegment(iv),
		Ciphertext:  EncodeSegment(ciphertext),
		Tag:         EncodeSegment(tag),
	}
	if opts.Serialization == SerializationGeneral {
		doc.Recipients = make([]jweJSONRecipient, len(plans))
		for i := range plans {
			doc.Recipients[i] = jweJSONRecipient{
				Header:       plans[i].header,
				EncryptedKey: EncodeSegment(plans[i].encryptedKey),
			}
		}
	} else {
		doc.Header = plans[0].header
		doc.EncryptedKey = EncodeSegment(plans[0].encryptedKey)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return "", errs.WrapDetail(err, ErrInvalidConfig, "encode JWE JSON | 编码 JWE JSON")
	}
	return string(out), nil
}

// buildJWERecipientPlans validates keys and resolves the algorithm of every recipient. |
// buildJWERecipientPlans 校验密钥并解析每个接收方的算法。
func buildJWERecipientPlans(key *Key, opts EncryptOptions) ([]jweRecipientPlan, error) {
	if len(opts.Recipients) == 0 {
		if key == nil {
			return nil, ErrInvalidKey
		}
		alg := opts.Alg
		if alg == "" {
			alg = key.Alg
		}
		if alg == "" {
			return nil, errs.Detail(ErrAlgNotAllowed, "no alg specified | 未指定 alg")
		}
		if err := validateJWEEncryptAlg(alg, key, opts.AllowRSA1_5); err != nil {
			return nil, err
		}
		kid := opts.Kid
		if kid == "" {
			kid = key.Kid
		}
		return []jweRecipientPlan{{key: key, alg: alg, kid: kid}}, nil
	}
	plans := make([]jweRecipientPlan, len(opts.Recipients))
	for i := range opts.Recipients {
		r := &opts.Recipients[i]
		if r.Key == nil {
			return nil, ErrInvalidKey
		}
		alg := r.Alg
		if alg == "" {
			alg = r.Key.Alg
		}
		if alg == "" {
			alg = opts.Alg
		}
		if alg == "" {
			return nil, errs.Detail(ErrAlgNotAllowed, "recipient %[1]d has no alg | 接收方 %[1]d 未指定 alg", i)
		}
		if err := validateJWEEncryptAlg(alg, r.Key, opts.AllowRSA1_5); err != nil {
			return nil, err
		}
		kid := r.Kid
		if kid == "" {
			kid = r.Key.Kid
		}
		header := make(map[string]any, 3+len(r.Header))
		header["alg"] = alg
		if kid != "" {
			header["kid"] = kid
		}
		for name, v := range r.Header {
			switch name {
			case "alg", "enc", "zip", "epk", "apu", "apv", "crit", "kid":
				return nil, errs.Detail(ErrInvalidHeader, "recipient header %[1]q is managed | 接收方头部 %[1]q 由本包管理", name)
			}
			header[name] = v
		}
		plans[i] = jweRecipientPlan{key: r.Key, alg: alg, kid: kid, header: header}
	}
	return plans, nil
}

// validateJWEEncryptAlg validates one encryption algorithm against its key. | validateJWEEncryptAlg
// 校验一个加密算法与其密钥。
func validateJWEEncryptAlg(alg string, key *Key, allowRSA15 bool) error {
	if !supportedJWEAlg(alg) {
		return errs.Detail(ErrAlgNotAllowed, "alg=%[1]q | 算法=%[1]q", alg)
	}
	if key.Alg != "" && key.Alg != alg {
		return errs.Detail(ErrAlgNotAllowed, "key alg=%[1]q does not allow %[2]q | 密钥 alg=%[1]q 不允许 %[2]q", key.Alg, alg)
	}
	if err := checkKeyAlg(key, alg); err != nil {
		return err
	}
	if err := checkKeyUse(key, "encrypt"); err != nil {
		return err
	}
	if alg == AlgRSA15 && !allowRSA15 {
		return errs.Detail(ErrAlgNotAllowed, "RSA1_5 requires explicit opt-in | RSA1_5 需要显式开启")
	}
	return nil
}

// validateJWEUnprotectedEncrypt refuses shared unprotected parameters that the encryption path
// manages, because a mismatched apu/apv/epk/zip would describe different key derivation or content
// processing than the one actually performed. | validateJWEUnprotectedEncrypt 拒绝加密路径管理的
// 共享非保护参数，因为不一致的 apu/apv/epk/zip 会描述与实际执行不同的密钥派生或内容处理。
func validateJWEUnprotectedEncrypt(u map[string]any) error {
	for name := range u {
		switch name {
		case "alg", "enc", "zip", "epk", "apu", "apv", "crit":
			return errs.Detail(ErrInvalidHeader, "unprotected header %[1]q is managed | 非保护头部 %[1]q 由本包管理", name)
		}
	}
	return nil
}

// mergeJWEHeaders validates and merges the protected, shared unprotected and per-recipient headers.
// | mergeJWEHeaders 校验并合并受保护、共享非保护与每接收方头部。
//
// A name repeated in two locations, crit outside the protected header, and enc or zip in a
// per-recipient header are refused. | 两个位置重复的名称、受保护头部之外的 crit，以及每接收方头部
// 中的 enc 或 zip 都会被拒绝。
func mergeJWEHeaders(protected, unprotected, recipient map[string]any) (Header, error) {
	merged := make(Header, len(protected)+len(unprotected)+len(recipient))
	for name, v := range protected {
		merged[name] = v
	}
	for name, v := range unprotected {
		if name == "crit" {
			return nil, errs.Detail(ErrInvalidHeader, "crit must be protected | crit 必须受保护")
		}
		if _, dup := merged[name]; dup {
			return nil, errs.Detail(ErrInvalidHeader, "duplicate %[1]s header | %[1]s 头部重复", name)
		}
		merged[name] = v
	}
	for name, v := range recipient {
		switch name {
		case "crit":
			return nil, errs.Detail(ErrInvalidHeader, "crit must be protected | crit 必须受保护")
		case "enc", "zip":
			return nil, errs.Detail(ErrInvalidHeader, "%[1]s must be shared | %[1]s 必须共享", name)
		}
		if _, dup := merged[name]; dup {
			return nil, errs.Detail(ErrInvalidHeader, "duplicate %[1]s header | %[1]s 头部重复", name)
		}
		merged[name] = v
	}
	return merged, nil
}

// parseJWEJSON parses a flattened or general JWE JSON serialization. | parseJWEJSON 解析扁平或通用
// JWE JSON 序列化。
//
// It is strict: the document is one JSON object, duplicate members at any nesting level are refused,
// general and flattened members may not be mixed, recipients must be a non-empty array of objects,
// and iv, ciphertext and tag are required strings. Unknown extension members are ignored, as RFC
// 7516 permits. | 解析是严格的：文档是单个 JSON 对象，任意层级的重复成员都会被拒绝，通用与扁平
// 成员不得混用，recipients 必须是非空对象数组，iv、ciphertext 与 tag 是必需字符串。未知扩展成员
// 按 RFC 7516 允许的方式忽略。
func parseJWEJSON(raw string) (*jweJSONParsed, error) {
	b := []byte(raw)
	if !isJSONObject(b) {
		return nil, errs.Detail(ErrMalformed, "JWE JSON is not a JSON object | JWE JSON 不是 JSON 对象")
	}
	if hasDuplicateKeys(b) {
		return nil, errs.Detail(ErrInvalidHeader, "JWE JSON has duplicate members | JWE JSON 存在重复成员")
	}
	var root map[string]any
	if err := unmarshal(b, &root); err != nil {
		return nil, errs.WrapDetail(err, ErrMalformed, "JWE JSON decode | JWE JSON 解码")
	}
	doc := &jweJSONParsed{}
	if v, ok := root["protected"]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, errs.Detail(ErrInvalidHeader, "protected is not a string | protected 不是字符串")
		}
		doc.protectedSeg = s
		headerBytes, err := DecodeSegment(s)
		if err != nil {
			return nil, err
		}
		m, err := headerJSON(headerBytes)
		if err != nil {
			return nil, err
		}
		if err := validateJWEProtectedCrit(m); err != nil {
			return nil, err
		}
		doc.protected = Header(m)
	}
	if v, ok := root["unprotected"]; ok {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, errs.Detail(ErrInvalidHeader, "unprotected is not an object | unprotected 不是对象")
		}
		doc.unprotected = Header(m)
	}
	if err := decodeJWEJSONContentMembers(root, doc); err != nil {
		return nil, err
	}
	if err := decodeJWEJSONRecipients(root, doc); err != nil {
		return nil, err
	}
	if s, ok, err := jweJSONStringMember(root, "aad"); err != nil {
		return nil, err
	} else if ok {
		if _, err := DecodeSegment(s); err != nil {
			return nil, err
		}
		doc.aadInput = append([]byte(doc.protectedSeg+"."), s...)
	} else {
		doc.aadInput = []byte(doc.protectedSeg)
	}
	return doc, nil
}

// decodeJWEJSONContentMembers decodes the required iv, ciphertext and tag members. |
// decodeJWEJSONContentMembers 解码必需的 iv、ciphertext 与 tag 成员。
func decodeJWEJSONContentMembers(root map[string]any, doc *jweJSONParsed) error {
	for _, f := range [...]struct {
		name string
		dst  *[]byte
	}{
		{"iv", &doc.iv},
		{"ciphertext", &doc.ciphertext},
		{"tag", &doc.tag},
	} {
		s, ok, err := jweJSONStringMember(root, f.name)
		if err != nil {
			return err
		}
		if !ok {
			return errs.Detail(ErrMalformed, "JWE JSON has no %[1]s | JWE JSON 缺少 %[1]s", f.name)
		}
		out, err := DecodeSegment(s)
		if err != nil {
			return err
		}
		*f.dst = out
	}
	return nil
}

// decodeJWEJSONRecipients decodes either the general recipients array or the flattened recipient.
// | decodeJWEJSONRecipients 解码通用 recipients 数组或扁平接收方。
func decodeJWEJSONRecipients(root map[string]any, doc *jweJSONParsed) error {
	header, hasHeader, err := jweJSONHeaderMember(root, "header")
	if err != nil {
		return err
	}
	encryptedKey, hasEncryptedKey, err := jweJSONEncryptedKeyMember(root)
	if err != nil {
		return err
	}
	v, ok := root["recipients"]
	if !ok {
		doc.recipients = []parsedJWERecipient{{header: header, encryptedKey: encryptedKey}}
		return nil
	}
	if hasHeader || hasEncryptedKey {
		return errs.Detail(ErrMalformed, "JWE JSON mixes general and flattened members | JWE JSON 混用通用与扁平成员")
	}
	arr, ok := v.([]any)
	if !ok || len(arr) == 0 {
		return errs.Detail(ErrMalformed, "JWE JSON recipients must be a non-empty array | JWE JSON 的 recipients 必须是非空数组")
	}
	if len(arr) > maxJWERecipients {
		return errs.Detail(ErrMalformed, "JWE JSON has too many recipients: %[1]d | JWE JSON 的接收方过多：%[1]d", len(arr))
	}
	doc.general = true
	doc.recipients = make([]parsedJWERecipient, 0, len(arr))
	for _, item := range arr {
		obj, ok := item.(map[string]any)
		if !ok {
			return errs.Detail(ErrMalformed, "JWE JSON recipient is not an object | JWE JSON 接收方不是对象")
		}
		rc := parsedJWERecipient{}
		rh, _, err := jweJSONHeaderMember(obj, "header")
		if err != nil {
			return err
		}
		rc.header = rh
		rek, _, err := jweJSONEncryptedKeyMember(obj)
		if err != nil {
			return err
		}
		rc.encryptedKey = rek
		doc.recipients = append(doc.recipients, rc)
	}
	return nil
}

// jweJSONHeaderMember decodes an optional unprotected header object. | jweJSONHeaderMember 解码可选的
// 非保护头部对象。
func jweJSONHeaderMember(root map[string]any, name string) (Header, bool, error) {
	v, ok := root[name]
	if !ok {
		return nil, false, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false, errs.Detail(ErrInvalidHeader, "%[1]s is not an object | %[1]s 不是对象", name)
	}
	return Header(m), true, nil
}

// jweJSONEncryptedKeyMember decodes an optional encrypted_key string. | jweJSONEncryptedKeyMember
// 解码可选的 encrypted_key 字符串。
func jweJSONEncryptedKeyMember(root map[string]any) ([]byte, bool, error) {
	s, ok, err := jweJSONStringMember(root, "encrypted_key")
	if err != nil || !ok {
		return nil, ok, err
	}
	out, err := DecodeSegment(s)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

// jweJSONStringMember extracts an optional string member. | jweJSONStringMember 提取可选的字符串
// 成员。
func jweJSONStringMember(root map[string]any, name string) (string, bool, error) {
	v, ok := root[name]
	if !ok {
		return "", false, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", false, errs.Detail(ErrMalformed, "%[1]s is not a string | %[1]s 不是字符串", name)
	}
	return s, true, nil
}

// recipientHeader merges and validates the headers of recipient i. | recipientHeader 合并并校验第 i
// 个接收方的头部。
func (d *jweJSONParsed) recipientHeader(i int) (Header, jweHeader, error) {
	merged, err := mergeJWEHeaders(d.protected, d.unprotected, d.recipients[i].header)
	if err != nil {
		return nil, jweHeader{}, err
	}
	h, err := jweHeaderFromMap(map[string]any(merged))
	if err != nil {
		return nil, jweHeader{}, err
	}
	return merged, h, nil
}

// recipientOrder returns recipient indexes with the preferred kid first, preserving document order
// within each group. | recipientOrder 返回接收方下标，首选 kid 在前，各组内保持文档顺序。
func (d *jweJSONParsed) recipientOrder(preferredKid string) []int {
	order := make([]int, 0, len(d.recipients))
	if preferredKid == "" {
		for i := range d.recipients {
			order = append(order, i)
		}
		return order
	}
	for i := range d.recipients {
		if d.recipientKid(i) == preferredKid {
			order = append(order, i)
		}
	}
	for i := range d.recipients {
		if d.recipientKid(i) != preferredKid {
			order = append(order, i)
		}
	}
	return order
}

// recipientKid returns the merged kid of recipient i, or "". | recipientKid 返回第 i 个接收方合并后
// 的 kid，缺失时返回 ""。
func (d *jweJSONParsed) recipientKid(i int) string {
	if v, ok := d.recipients[i].header["kid"].(string); ok {
		return v
	}
	if v, ok := d.unprotected["kid"].(string); ok {
		return v
	}
	if v, ok := d.protected["kid"].(string); ok {
		return v
	}
	return ""
}

// decryptJWEJSONWithKey decrypts a JSON JWE with one key, trying kid-matching recipients first. |
// decryptJWEJSONWithKey 使用单个密钥解密 JSON JWE，先尝试 kid 匹配的接收方。
func decryptJWEJSONWithKey(doc *jweJSONParsed, key *Key, opts DecryptOptions) ([]byte, error) {
	var firstErr error
	for _, i := range doc.recipientOrder(key.Kid) {
		_, h, err := doc.recipientHeader(i)
		if err == nil {
			err = validateJWEJSONRecipient(h, opts)
		}
		if err == nil {
			plaintext, derr := decryptJWEJSONContent(doc, i, h, key, opts)
			if derr == nil {
				return plaintext, nil
			}
			err = derr
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		return nil, errs.Detail(ErrDecryptionFailed, "no recipient | 没有接收方")
	}
	return nil, firstErr
}

// decryptJWEJSONWithResolver decrypts a JSON JWE with keys chosen per recipient by resolver. |
// decryptJWEJSONWithResolver 使用 resolver 为每个接收方选择的密钥解密 JSON JWE。
func decryptJWEJSONWithResolver(doc *jweJSONParsed, resolver KeyResolver, opts DecryptOptions) ([]byte, error) {
	var firstErr error
	for i := range doc.recipients {
		merged, h, err := doc.recipientHeader(i)
		if err == nil {
			err = validateJWEJSONRecipient(h, opts)
		}
		var key *Key
		if err == nil {
			key, err = resolver.ResolveKey(context.Background(), merged)
			if err == nil && key == nil {
				err = errs.Detail(ErrKeyNotFound, "resolver returned nil key | 解析器返回 nil 密钥")
			}
		}
		if err == nil {
			plaintext, derr := decryptJWEJSONContent(doc, i, h, key, opts)
			if derr == nil {
				return plaintext, nil
			}
			err = derr
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		return nil, errs.Detail(ErrDecryptionFailed, "no recipient | 没有接收方")
	}
	return nil, firstErr
}

// validateJWEJSONRecipient checks the shared algorithms and RSA1_5 opt-in of one recipient. |
// validateJWEJSONRecipient 校验一个接收方共享的算法与 RSA1_5 开关。
func validateJWEJSONRecipient(h jweHeader, opts DecryptOptions) error {
	if !supportedJWEAlg(h.Alg) {
		return errs.Detail(ErrAlgNotAllowed, "alg=%[1]q | 算法=%[1]q", h.Alg)
	}
	if !supportedEnc(h.Enc) {
		return errs.Detail(ErrUnsupportedEnc, "enc=%[1]q | enc=%[1]q", h.Enc)
	}
	if h.Zip != "" && h.Zip != ZipDEF {
		return errs.Detail(ErrInvalidHeader, "zip=%[1]q | zip=%[1]q", h.Zip)
	}
	if h.Alg == AlgRSA15 && !opts.AllowRSA1_5 {
		return errs.Detail(ErrAlgNotAllowed, "RSA1_5 requires explicit opt-in | RSA1_5 需要显式开启")
	}
	return nil
}

// decryptJWEJSONContent performs key management and content decryption for one recipient. |
// decryptJWEJSONContent 为一个接收方执行密钥管理与内容解密。
func decryptJWEJSONContent(doc *jweJSONParsed, i int, h jweHeader, key *Key, opts DecryptOptions) ([]byte, error) {
	if key.Alg != "" && key.Alg != h.Alg {
		return nil, errs.Detail(ErrAlgNotAllowed, "key alg=%[1]q does not allow %[2]q | 密钥 alg=%[1]q 不允许 %[2]q", key.Alg, h.Alg)
	}
	if err := checkKeyAlg(key, h.Alg); err != nil {
		return nil, err
	}
	if err := checkKeyUse(key, "decrypt"); err != nil {
		return nil, err
	}
	cek, err := decryptCEK(h, key, doc.recipients[i].encryptedKey)
	if err != nil {
		return nil, err
	}
	plaintext, err := openContent(h.Enc, cek, doc.aadInput, doc.iv, doc.ciphertext, doc.tag)
	if err != nil {
		return nil, err
	}
	if h.Zip == ZipDEF {
		plaintext, err = inflate(plaintext, opts.MaxDecompressedSize)
		if err != nil {
			return nil, err
		}
	}
	return plaintext, nil
}
