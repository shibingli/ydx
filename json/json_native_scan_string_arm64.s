//go:build arm64 && !jsonx_std

#include "textflag.h"

// func scanStringBodyNEON(data []byte, start int) int
// Returns the start of the first 16-byte block containing a quote, backslash, control byte or
// non-ASCII byte, or the position after the last full clean block. |
// 返回首个含引号、反斜杠、控制字节或非 ASCII 字节的 16 字节块起点；若全部干净，则返回最后一个完整块之后的位置。
TEXT ·scanStringBodyNEON(SB), NOSPLIT, $0-40
	MOVD data_base+0(FP), R0
	MOVD data_len+8(FP), R1
	MOVD start+24(FP), R2
	VMOVI $0x22, V1.B16
	VMOVI $0x5c, V2.B16
	VMOVI $0x20, V3.B16
	VMOVI $0x7f, V4.B16

loop:
	SUB $16, R1, R5
	CMP $0, R5
	BLT done
	ADD R0, R2, R6
	VLD1 (R6), [V0.B16]
	VCMEQ V1.B16, V0.B16, V5.B16
	VCMEQ V2.B16, V0.B16, V6.B16
	VORR V6.B16, V5.B16, V5.B16
	VCMHI V0.B16, V3.B16, V6.B16
	VORR V6.B16, V5.B16, V5.B16
	VCMHI V4.B16, V0.B16, V6.B16
	VORR V6.B16, V5.B16, V5.B16
	VUMAXV V5.B16, V5
	VMOV V5.S[0], R7
	AND $0xFF, R7
	CBNZ R7, done
	ADD $16, R2, R2
	B loop

done:
	MOVD R2, ret+32(FP)
	RET
