package kms

import (
	"context"
	"crypto/x509"
	"encoding/pem"

	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/guomi"
	"github.com/shibingli/ydx/json"
)

// ExportKey returns public or private key material subject to the key Exportable flag and the
// service export policy. | ExportKey 在密钥 Exportable 标志与服务导出策略约束下返回公钥或私钥材料。
//
// Public export is always allowed. Private export requires both key.Exportable and
// ExportPolicy.AllowPrivate; otherwise ErrExportDenied is returned and audited as denied. The
// operation is audited. | 公钥导出始终允许。私钥导出同时要求 key.Exportable 与
// ExportPolicy.AllowPrivate；否则返回 ErrExportDenied 并记录拒绝审计。该操作会写入审计。
func (s *Service) ExportKey(ctx context.Context, id string, request ExportRequest) (*ExportedKey, error) {
	key, err := s.loadResolvedKey(ctx, id)
	if err != nil {
		s.fail(ctx, OperationKeyExport, id, 0, err)
		return nil, err
	}
	defer key.eraseMaterial()
	exported, err := exportKeyMaterial(key, s.exportPolicy, request)
	if err != nil {
		if errorsIs(err, ErrExportDenied) {
			s.deny(ctx, OperationKeyExport, key.ID, map[string]string{"format": string(request.Format), "private": boolLabel(request.Private)})
		} else {
			s.fail(ctx, OperationKeyExport, key.ID, request.Version, err)
		}
		return nil, err
	}
	s.succeed(ctx, OperationKeyExport, key.ID, exported.Version, map[string]string{
		"format":  string(exported.Format),
		"private": boolLabel(exported.Private),
		"type":    string(key.Type),
	})
	return exported, nil
}

// exportStoredKey reads a key as stored and applies the export policy. | exportStoredKey 按存储原样
// 读取密钥并应用导出策略。
func exportStoredKey(ctx context.Context, store Store, policy ExportPolicy, id string, request ExportRequest) (*ExportedKey, error) {
	key, err := resolveStoredKey(ctx, store, id)
	if err != nil {
		return nil, err
	}
	return exportKeyMaterial(key, policy, request)
}

// exportKeyMaterial encodes one version of key according to request. | exportKeyMaterial 按 request
// 编码密钥的某个版本。
func exportKeyMaterial(key *Key, policy ExportPolicy, request ExportRequest) (*ExportedKey, error) {
	if key == nil {
		return nil, ErrNotFound
	}
	versionNumber := request.Version
	if versionNumber == 0 {
		versionNumber = key.Version
	}
	version := key.VersionAt(versionNumber)
	if version == nil {
		return nil, errs.Detail(ErrVersionNotFound, "key %[1]q version %[2]d | 密钥 %[1]q 版本 %[2]d", key.ID, versionNumber)
	}
	format := request.Format
	if format == "" {
		if key.IsSymmetric() {
			format = ExportFormatRaw
		} else {
			format = ExportFormatPEM
		}
	}
	switch format {
	case ExportFormatJWK, ExportFormatPEM, ExportFormatRaw:
	default:
		return nil, errs.Detail(ErrInvalidRequest, "unknown export format %[1]q | 未知导出格式 %[1]q", format)
	}
	if request.Private {
		if !key.Exportable || !policy.AllowPrivate {
			return nil, errs.Detail(ErrExportDenied, "private export requires Exportable and policy opt-in | 私钥导出要求 Exportable 且策略开启")
		}
		material := version.Material
		if len(material) == 0 && version.Version == key.Version {
			material = key.Material
		}
		if len(material) == 0 {
			return nil, errs.Detail(ErrInvalidMaterial, "version %[1]d has no private material | 版本 %[1]d 没有私钥材料", versionNumber)
		}
		encoded, err := encodePrivateMaterial(key, versionNumber, format, material)
		if err != nil {
			return nil, err
		}
		return &ExportedKey{
			KeyID:    key.ID,
			Version:  versionNumber,
			Type:     key.Type,
			Format:   format,
			Private:  true,
			Material: encoded,
		}, nil
	}
	if key.IsSymmetric() {
		return nil, errs.Detail(ErrExportDenied, "symmetric keys have no public half | 对称密钥没有公钥部分")
	}
	public := version.PublicMaterial
	if len(public) == 0 && version.Version == key.Version {
		public = key.PublicMaterial
	}
	if len(public) == 0 {
		return nil, errs.Detail(ErrInvalidMaterial, "version %[1]d has no public material | 版本 %[1]d 没有公钥材料", versionNumber)
	}
	encoded, err := encodePublicMaterial(key, versionNumber, format, public)
	if err != nil {
		return nil, err
	}
	return &ExportedKey{
		KeyID:          key.ID,
		Version:        versionNumber,
		Type:           key.Type,
		Format:         format,
		Private:        false,
		PublicMaterial: encoded,
	}, nil
}

// encodePrivateMaterial encodes private material in format. | encodePrivateMaterial 把私钥材料编码为 format。
func encodePrivateMaterial(key *Key, version uint32, format ExportFormat, material []byte) ([]byte, error) {
	switch format {
	case ExportFormatRaw:
		return append([]byte(nil), material...), nil
	case ExportFormatPEM:
		switch key.Type {
		case KeyTypeSM2:
			return append([]byte(nil), material...), nil
		case KeyTypeAES, KeyTypeChaCha20, KeyTypeSM4:
			return nil, errs.Detail(ErrNotSupported, "symmetric keys have no PEM encoding | 对称密钥没有 PEM 编码")
		default:
			parsed, err := parsePrivateKey(key.Type, material)
			if err != nil {
				return nil, err
			}
			der, err := marshalPrivateDER(parsed)
			if err != nil {
				return nil, err
			}
			return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
		}
	case ExportFormatJWK:
		kid := jwkKeyID(key.ID, version)
		switch key.Type {
		case KeyTypeSM2:
			return nil, errs.Detail(ErrNotSupported, "SM2 has no JWK encoding | SM2 没有 JWK 编码")
		case KeyTypeAES, KeyTypeChaCha20, KeyTypeSM4:
			jwk, err := jose.FromHMAC(kid, material)
			if err != nil {
				return nil, errs.WrapDetail(err, ErrInvalidMaterial, "encode symmetric JWK | 编码对称 JWK")
			}
			return json.Marshal(jwk)
		default:
			parsed, err := parsePrivateKey(key.Type, material)
			if err != nil {
				return nil, err
			}
			jwk, err := jose.FromPrivateKey(kid, parsed)
			if err != nil {
				return nil, errs.WrapDetail(err, ErrInvalidMaterial, "encode private JWK | 编码私钥 JWK")
			}
			return json.Marshal(jwk)
		}
	default:
		return nil, errs.Detail(ErrNotSupported, "private export format %[1]q | 私钥导出格式 %[1]q", format)
	}
}

// encodePublicMaterial encodes public material in format. | encodePublicMaterial 把公钥材料编码为 format。
func encodePublicMaterial(key *Key, version uint32, format ExportFormat, material []byte) ([]byte, error) {
	switch format {
	case ExportFormatRaw:
		return append([]byte(nil), material...), nil
	case ExportFormatPEM:
		if key.Type == KeyTypeSM2 {
			return append([]byte(nil), material...), nil
		}
		parsed, err := parsePublicKey(key.Type, material)
		if err != nil {
			return nil, err
		}
		der, err := marshalPublicDER(parsed)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
	case ExportFormatJWK:
		if key.Type == KeyTypeSM2 {
			return nil, errs.Detail(ErrNotSupported, "SM2 has no JWK encoding | SM2 没有 JWK 编码")
		}
		parsed, err := parsePublicKey(key.Type, material)
		if err != nil {
			return nil, err
		}
		jwk, err := jose.FromPublicKey(jwkKeyID(key.ID, version), parsed)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidMaterial, "encode public JWK | 编码公钥 JWK")
		}
		return json.Marshal(jwk)
	default:
		return nil, errs.Detail(ErrNotSupported, "public export format %[1]q | 公钥导出格式 %[1]q", format)
	}
}

// marshalPrivateDER re-encodes a parsed private key as PKCS#8 DER. | marshalPrivateDER 把解析后的私钥
// 重新编码为 PKCS#8 DER。
func marshalPrivateDER(key any) ([]byte, error) {
	if sm2, ok := key.(*guomi.PrivateKey); ok {
		return guomi.MarshalPrivateKeyPEM(sm2)
	}
	der, err := marshalPKCS8(key)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidMaterial, "encode PKCS#8 private key | 编码 PKCS#8 私钥")
	}
	return der, nil
}

// marshalPublicDER re-encodes a parsed public key as PKIX DER. | marshalPublicDER 把解析后的公钥重新
// 编码为 PKIX DER。
func marshalPublicDER(key any) ([]byte, error) {
	if sm2, ok := key.(*guomi.PublicKey); ok {
		return guomi.MarshalPublicKeyPEM(sm2)
	}
	der, err := marshalPKIX(key)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidMaterial, "encode PKIX public key | 编码 PKIX 公钥")
	}
	return der, nil
}

// jwkKeyID binds a JWK to one key version. | jwkKeyID 把 JWK 绑定到某个密钥版本。
func jwkKeyID(keyID string, version uint32) string {
	return keyID + "#" + strconvUint32(version)
}

// marshalPKCS8 encodes a private key as PKCS#8 DER. | marshalPKCS8 把私钥编码为 PKCS#8 DER。
func marshalPKCS8(key any) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(key)
}

// marshalPKIX encodes a public key as PKIX DER. | marshalPKIX 把公钥编码为 PKIX DER。
func marshalPKIX(key any) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(key)
}
