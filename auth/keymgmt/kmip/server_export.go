package kmip

import "github.com/shibingli/ydx/errs"

// handleExportForVersion implements the KMIP 1.4 Export operation using the payload shape of version. | handleExportForVersion
// 使用 version 的负载形状实现 KMIP 1.4 Export 操作。
//
// Export was removed in KMIP 2.0, so 2.x requests return ErrUnsupported. Export honors the Extractable attribute for
// symmetric keys, private keys and secret data, exactly like Get. Certificates are exported as X.509 material. | KMIP
// 2.0 已移除 Export，因此 2.x 请求返回 ErrUnsupported。Export 与 Get 一样遵守对称密钥、私钥与秘密数据的
// Extractable 属性。证书以 X.509 材料导出。
func (s *Server) handleExportForVersion(request ExportRequest, version ProtocolVersion) (Item, error) {
	if usesKMIP20Payloads(version) {
		return Item{}, errs.Detail(ErrUnsupported,
			"Export was removed in KMIP 2.0; use Get | KMIP 2.0 已移除 Export；请使用 Get")
	}
	record, err := s.loadRecord(request.UniqueIdentifier)
	if err != nil {
		return Item{}, err
	}
	if record.Object == nil || record.State == StateDestroyed {
		return Item{}, errs.Detail(ErrState, "object %q was destroyed | 对象 %q 已销毁", record.UniqueIdentifier, record.UniqueIdentifier)
	}
	objectType := record.Object.Type
	if objectType == ObjectTypeCertificate {
		return exportCertificate(record, request)
	}
	kb, err := record.Object.KeyBlock()
	if err != nil {
		return Item{}, errs.Detail(ErrUnsupported, "object type %s cannot be exported | 对象类型 %s 无法导出", objectType, objectType)
	}
	switch objectType {
	case ObjectTypeSymmetricKey, ObjectTypePrivateKey, ObjectTypeSecretData:
		if !record.Extractable {
			return Item{}, resultErrorFor(ResultStatusOperationFailed, ResultReasonNotExtractable,
				"object is not extractable | 对象不可导出")
		}
	}
	format := request.KeyFormatType
	if format == 0 {
		format = kb.Format
	}
	if format != kb.Format {
		converted, err := convertKeyBlockFormat(*kb, format)
		if err != nil {
			return Item{}, err
		}
		kb = &converted
	}
	material, err := exportKeyMaterial(kb)
	if err != nil {
		return Item{}, err
	}
	return ExportResponse{
		ObjectType:         objectType,
		UniqueIdentifier:   record.UniqueIdentifier,
		KeyFormatType:      kb.Format,
		KeyCompressionType: kb.Compression,
		KeyMaterial:        material,
	}.Item()
}

// exportCertificate builds an Export response for a certificate record. | exportCertificate 为证书记录构造 Export 响应。
func exportCertificate(record ObjectRecord, request ExportRequest) (Item, error) {
	if record.Object == nil || record.Object.Certificate == nil {
		return Item{}, errs.Detail(ErrState, "certificate %q has no value | 证书 %q 没有值", record.UniqueIdentifier, record.UniqueIdentifier)
	}
	format := request.KeyFormatType
	if format != 0 && format != KeyFormatX509 {
		return Item{}, errs.Detail(ErrUnsupported,
			"certificates are exported only as X.509; requested %s | 证书仅以 X.509 导出；请求的格式为 %s", format, format)
	}
	value := record.Object.Certificate.CertificateValue
	if len(value) == 0 {
		return Item{}, errs.Detail(ErrState, "certificate %q has no material | 证书 %q 没有材料", record.UniqueIdentifier, record.UniqueIdentifier)
	}
	return ExportResponse{
		ObjectType:       ObjectTypeCertificate,
		UniqueIdentifier: record.UniqueIdentifier,
		KeyFormatType:    KeyFormatX509,
		KeyMaterial:      append([]byte(nil), value...),
	}.Item()
}

// exportKeyMaterial extracts the encoded bytes of a key block. Byte-string material is copied; structured material
// is encoded as TTLV, which is how KMIP 1.4 carries transparent formats in Key Material. | exportKeyMaterial 提取
// 密钥块的编码字节。字节串材料直接复制；结构化材料按 TTLV 编码，这是 KMIP 1.4 在 Key Material 中携带透明格式
// 的方式。
func exportKeyMaterial(kb *KeyBlock) ([]byte, error) {
	if kb == nil {
		return nil, errs.Detail(ErrState, "object has no key block | 对象没有密钥块")
	}
	switch kb.Value.Material.Type {
	case TypeByteString:
		material, err := kb.Value.Material.AsByteString()
		if err != nil {
			return nil, err
		}
		if len(material) == 0 {
			return nil, errs.Detail(ErrState, "object has no key material | 对象没有密钥材料")
		}
		return append([]byte(nil), material...), nil
	case TypeStructure:
		material, err := Encode(kb.Value.Material)
		if err != nil {
			return nil, err
		}
		return material, nil
	default:
		return nil, errs.Detail(ErrUnsupported,
			"key material type %s cannot be exported | 密钥材料类型 %s 无法导出", kb.Value.Material.Type, kb.Value.Material.Type)
	}
}
