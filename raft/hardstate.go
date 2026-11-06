package raft

import (
	"encoding/binary"
	"hash/crc32"
	"os"

	"github.com/shibingli/ydx/errs"
)

const (
	hardStateMagic   = "YDRHS001"
	hardStateVersion = byte(1)
	hardStateSize    = 8 + 1 + 8 + 8 + 8 + 4
)

// encodeHardStateFile serializes term, vote and commit with a CRC. |
// encodeHardStateFile 序列化任期、选票与提交索引并附加 CRC。
func encodeHardStateFile(hs HardState) []byte {
	data := make([]byte, hardStateSize)
	copy(data[:8], hardStateMagic)
	data[8] = hardStateVersion
	binary.LittleEndian.PutUint64(data[9:17], hs.Term)
	binary.LittleEndian.PutUint64(data[17:25], uint64(hs.Vote))
	binary.LittleEndian.PutUint64(data[25:33], hs.Commit)
	binary.LittleEndian.PutUint32(data[33:37], crc32.Checksum(data[:33], castagnoli))
	return data
}

// decodeHardStateFile validates and parses a hard-state record. |
// decodeHardStateFile 校验并解析硬状态记录。
func decodeHardStateFile(data []byte) (HardState, error) {
	if len(data) != hardStateSize {
		return HardState{}, errs.Detail(ErrCorrupt,
			"hard state size %d, want %d | 硬状态长度 %d，期望 %d",
			len(data), hardStateSize, len(data), hardStateSize)
	}
	if string(data[:8]) != hardStateMagic {
		return HardState{}, errs.Detail(ErrCorrupt, "bad hard state magic | 硬状态魔数错误")
	}
	if data[8] != hardStateVersion {
		return HardState{}, errs.Detail(ErrCorrupt,
			"hard state version %d | 硬状态版本 %d", data[8], data[8])
	}
	if crc32.Checksum(data[:33], castagnoli) != binary.LittleEndian.Uint32(data[33:37]) {
		return HardState{}, errs.Detail(ErrCorrupt, "hard state CRC mismatch | 硬状态 CRC 不匹配")
	}
	return HardState{
		Term:   binary.LittleEndian.Uint64(data[9:17]),
		Vote:   NodeID(binary.LittleEndian.Uint64(data[17:25])),
		Commit: binary.LittleEndian.Uint64(data[25:33]),
	}, nil
}

// PersistHardState implements HardStateStorage. It writes a small dedicated file
// under hsMu, independently of the WAL batch writer, so a large snapshot image
// write cannot delay a vote. | PersistHardState 实现 HardStateStorage。它在 hsMu
// 下写入独立的小文件，不经过 WAL 批次写协程，因此大型快照镜像写入不会延迟选票。
func (s *FileStorage) PersistHardState(hs *HardState) error {
	if hs == nil {
		return errs.Detail(ErrInvalidConfig, "nil hard state | 硬状态为空")
	}
	s.hsMu.Lock()
	defer s.hsMu.Unlock()
	if s.hsClosed {
		return ErrStopped
	}
	data := encodeHardStateFile(*hs)
	tmp := s.hsPath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return errs.Wrap(err, ErrStorage)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return errs.Wrap(err, ErrStorage)
	}
	if !s.noSync {
		if err := syncFile(f); err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return errs.Wrap(err, ErrStorage)
		}
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return errs.Wrap(err, ErrStorage)
	}
	if err := os.Rename(tmp, s.hsPath); err != nil {
		_ = os.Remove(tmp)
		return errs.Wrap(err, ErrStorage)
	}
	if !s.noSync {
		if err := syncDir(s.dir); err != nil {
			return errs.Wrap(err, ErrStorage)
		}
	}
	return nil
}

// mergeHardStateFile folds the dedicated hard state into the WAL-recovered
// state. The highest term wins; a non-zero vote for that term is preserved. |
// mergeHardStateFile 将专用硬状态合并进 WAL 恢复出的状态。最高任期优先，并保留
// 该任期内的非零选票。
func (s *FileStorage) mergeHardStateFile(hs *HardState) error {
	s.hsMu.Lock()
	defer s.hsMu.Unlock()
	data, err := os.ReadFile(s.hsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return errs.Wrap(err, ErrStorage)
	}
	fileHS, err := decodeHardStateFile(data)
	if err != nil {
		return err
	}
	switch {
	case fileHS.Term > hs.Term:
		hs.Term = fileHS.Term
		hs.Vote = fileHS.Vote
	case fileHS.Term == hs.Term:
		if hs.Vote != 0 && fileHS.Vote != 0 && hs.Vote != fileHS.Vote {
			return errs.Detail(ErrCorrupt,
				"conflicting hard state votes %d/%d | 硬状态选票冲突 %d/%d",
				hs.Vote, fileHS.Vote, hs.Vote, fileHS.Vote)
		}
		if hs.Vote == 0 {
			hs.Vote = fileHS.Vote
		}
	}
	if fileHS.Commit > hs.Commit {
		hs.Commit = fileHS.Commit
	}
	return nil
}
