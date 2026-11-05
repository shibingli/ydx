package raft

import (
	"encoding/binary"

	"github.com/shibingli/ydx/errs"
)

// RDMA chunk framing constants. A stream frame is split into RDMA messages of
// at most one registered slot. Each message starts with this fixed header so
// the receiver can reassemble one frame from consecutive messages. | RDMA 分块
// 帧常量。一个流帧被拆分为不超过一个注册槽位的 RDMA 消息；每条消息以固定头开始，
// 接收方据此把连续消息重组成一个帧。
const (
	rdmaChunkHeaderLen = 16
	rdmaChunkMagic     = uint32(0x59445241) // "YDRA"
	rdmaChunkVersion   = byte(1)
)

// encodeRDMAChunkHeader writes total frame length and chunk offset. | encodeRDMAChunkHeader
// 写入帧总长度与分块偏移。
func encodeRDMAChunkHeader(dst []byte, total, offset uint32) {
	binary.LittleEndian.PutUint32(dst[0:4], rdmaChunkMagic)
	dst[4] = rdmaChunkVersion
	dst[5] = 0
	binary.LittleEndian.PutUint16(dst[6:8], 0)
	binary.LittleEndian.PutUint32(dst[8:12], total)
	binary.LittleEndian.PutUint32(dst[12:16], offset)
}

// decodeRDMAChunkHeader validates and reads one chunk header. | decodeRDMAChunkHeader
// 校验并读取一个分块头。
func decodeRDMAChunkHeader(src []byte, maxFrame int) (total, offset uint32, err error) {
	if len(src) < rdmaChunkHeaderLen {
		return 0, 0, errs.Detail(ErrCorrupt, "short RDMA chunk header %d", len(src))
	}
	if binary.LittleEndian.Uint32(src[0:4]) != rdmaChunkMagic {
		return 0, 0, errs.Detail(ErrCorrupt, "bad RDMA chunk magic")
	}
	if src[4] != rdmaChunkVersion {
		return 0, 0, errs.Detail(ErrCorrupt, "RDMA chunk version %d", src[4])
	}
	total = binary.LittleEndian.Uint32(src[8:12])
	offset = binary.LittleEndian.Uint32(src[12:16])
	if total == 0 {
		return 0, 0, errs.Detail(ErrCorrupt, "zero RDMA frame length")
	}
	if maxFrame > 0 && uint64(total) > uint64(maxFrame) {
		return 0, 0, errs.Detail(ErrTooLarge, "RDMA frame %d bytes", total)
	}
	if offset >= total {
		return 0, 0, errs.Detail(ErrCorrupt, "RDMA offset %d >= total %d", offset, total)
	}
	return total, offset, nil
}
