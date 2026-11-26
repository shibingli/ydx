package raft

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/shibingli/ydx/errs"
)

const (
	// hardStateVersionEncrypted wraps the version 1 record in an AEAD envelope.
	// | hardStateVersionEncrypted 把版本 1 记录封装在 AEAD 信封中。
	hardStateVersionEncrypted = byte(2)
	// hardStateEncryptedHeaderSize is magic, version, key ID, suite and nonce. |
	// hardStateEncryptedHeaderSize 是魔数、版本、密钥 ID、套件与 nonce 的长度。
	hardStateEncryptedHeaderSize = 8 + 1 + 4 + 1 + encryptionNonceSize
	// hardStateEncryptedSize is the encrypted file length. | hardStateEncryptedSize
	// 是加密文件长度。
	hardStateEncryptedSize = hardStateEncryptedHeaderSize + hardStateSize + encryptionTagSize
)

// encodeHardState serializes term, vote and commit, encrypting the version 1
// record when the hard-state target is enabled. | encodeHardState 序列化任期、选票与
// 提交索引；启用硬状态加密目标时对版本 1 记录加密。
func (s *FileStorage) encodeHardState(hs HardState) ([]byte, error) {
	plain := encodeHardStateFile(hs)
	if !s.cipher.encrypts(EncryptHardState) {
		return plain, nil
	}
	key := s.cipher.activeKey()
	aead, err := key.contextAEAD(infoHardState)
	if err != nil {
		return nil, err
	}
	var header [hardStateEncryptedHeaderSize]byte
	copy(header[:8], hardStateMagic)
	header[8] = hardStateVersionEncrypted
	binary.LittleEndian.PutUint32(header[9:13], key.id)
	header[13] = byte(key.suite)
	if _, err := rand.Read(header[14:]); err != nil {
		return nil, errs.Wrap(err, ErrRandom)
	}
	out := make([]byte, 0, hardStateEncryptedSize)
	out = append(out, header[:]...)
	out = aead.Seal(out, header[14:], plain, header[:])
	return out, nil
}

// decodeHardState parses a plaintext version 1 file or decrypts a version 2
// envelope. | decodeHardState 解析版本 1 明文文件或解密版本 2 信封。
func (s *FileStorage) decodeHardState(data []byte) (HardState, error) {
	if len(data) < 9 || string(data[:8]) != hardStateMagic {
		return HardState{}, errs.Detail(ErrCorrupt, "bad hard state magic | 硬状态魔数错误")
	}
	if data[8] == hardStateVersion {
		if s.cipher.encrypts(EncryptHardState) && !s.cipher.allowPlaintextFiles {
			return HardState{}, errs.Detail(ErrInvalidConfig,
				"plaintext hard state with hard-state encryption enabled | 启用硬状态加密时遇到明文硬状态")
		}
		return decodeHardStateFile(data)
	}
	if data[8] != hardStateVersionEncrypted {
		return HardState{}, errs.Detail(ErrCorrupt,
			"hard state version %d | 硬状态版本 %d", data[8], data[8])
	}
	if len(data) != hardStateEncryptedSize {
		return HardState{}, errs.Detail(ErrCorrupt,
			"encrypted hard state size %d, want %d | 加密硬状态长度 %d，期望 %d",
			len(data), hardStateEncryptedSize, len(data), hardStateEncryptedSize)
	}
	if s.cipher == nil {
		return HardState{}, errs.Detail(ErrInvalidConfig,
			"encrypted hard state requires encryption keys | 加密硬状态需要加密密钥")
	}
	header := data[:hardStateEncryptedHeaderSize]
	keyID := binary.LittleEndian.Uint32(header[9:13])
	suite := EncryptionSuite(header[13])
	if !suite.valid() {
		return HardState{}, errs.Detail(ErrCorrupt, "unknown suite %d | 未知套件 %d", header[13], header[13])
	}
	key, ok := s.cipher.ring.keys[keyID]
	if !ok {
		return HardState{}, errs.Detail(ErrKeyNotFound,
			"hard state key ID %[1]d is not in the ring | 硬状态密钥 ID %[1]d 不在密钥环中", keyID)
	}
	if key.suite != suite {
		return HardState{}, errs.Detail(ErrCorrupt,
			"hard state key %d suite differs from header suite | 硬状态密钥 %d 套件与头部套件不一致", keyID, keyID)
	}
	aead, err := key.contextAEAD(infoHardState)
	if err != nil {
		return HardState{}, err
	}
	plain, err := aead.Open(nil, header[14:], data[hardStateEncryptedHeaderSize:], header)
	if err != nil {
		return HardState{}, errs.WrapDetail(err, ErrCorrupt, "hard state authentication failed | 硬状态认证失败")
	}
	return decodeHardStateFile(plain)
}
