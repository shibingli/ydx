//go:build arm64

#include "textflag.h"

// func indexByteNEON(s string, c byte, from int) int
// Scans full 16-byte blocks for c. | 以 16 字节块扫描 c。
TEXT ·indexByteNEON(SB), NOSPLIT, $0-40
	MOVD s_base+0(FP), R0
	MOVD s_len+8(FP), R1
	MOVBU c+16(FP), R2
	MOVD from+24(FP), R3
	VDUP R2, V1.B16

loop:
	SUB R3, R1, R4
	CMP $16, R4
	BLT none
	ADD R0, R3, R5
	VLD1 (R5), [V0.B16]
	VCMEQ V1.B16, V0.B16, V2.B16
	VUMAXV V2.B16, V2
	VMOV V2.D[0], R4
	AND $255, R4, R4
	CBNZ R4, found
	ADD $16, R3
	B loop

found:
	MOVD R3, ret+32(FP)
	RET

none:
	MOVD $-1, R4
	MOVD R4, ret+32(FP)
	RET

// func indexByteSetNEON(s string, t *[128]byte, from int) int
// Scans full 16-byte blocks for any byte in the table set. | 以 16 字节块扫描表集合中的任意字节。
TEXT ·indexByteSetNEON(SB), NOSPLIT, $0-40
	MOVD s_base+0(FP), R0
	MOVD s_len+8(FP), R1
	MOVD t+16(FP), R2
	MOVD from+24(FP), R3
	VLD1 (R2), [V1.B16]
	ADD $64, R2, R4
	VLD1 (R4), [V2.B16]
	VMOVI $15, V7.B16

loop:
	SUB R3, R1, R5
	CMP $16, R5
	BLT none
	ADD R0, R3, R6
	VLD1 (R6), [V0.B16]
	VUSHR $4, V0.B16, V3.B16
	VAND V7.B16, V3.B16, V3.B16
	VAND V7.B16, V0.B16, V4.B16
	VTBL V4.B16, [V1.B16], V5.B16
	VTBL V3.B16, [V2.B16], V6.B16
	VAND V6.B16, V5.B16, V5.B16
	VUMAXV V5.B16, V6
	VMOV V6.D[0], R7
	AND $255, R7, R7
	CBNZ R7, found
	ADD $16, R3
	B loop

found:
	MOVD R3, ret+32(FP)
	RET

none:
	MOVD $-1, R7
	MOVD R7, ret+32(FP)
	RET

// func indexFoldPairNEON(s string, c0, c1 byte, from int) int
// Scans full 16-byte blocks for two consecutive bytes whose lowercased forms match c0 and c1. |
// 以 16 字节块扫描连续两个字节，其小写形式分别匹配 c0 与 c1。
TEXT ·indexFoldPairNEON(SB), NOSPLIT, $0-40
	MOVD s_base+0(FP), R0
	MOVD s_len+8(FP), R1
	MOVBU c0+16(FP), R2
	MOVBU c1+17(FP), R3
	MOVD from+24(FP), R4
	VDUP R2, V1.B16
	VDUP R3, V2.B16
	VMOVI $32, V3.B16

loop:
	SUB R4, R1, R5
	CMP $17, R5
	BLT none
	ADD R0, R4, R6
	VLD1 (R6), [V0.B16]
	ADD $1, R6, R8
	VLD1 (R8), [V4.B16]
	VORR V3.B16, V0.B16, V5.B16
	VORR V3.B16, V4.B16, V6.B16
	VCMEQ V1.B16, V5.B16, V7.B16
	VCMEQ V2.B16, V6.B16, V8.B16
	VAND V8.B16, V7.B16, V7.B16
	VUMAXV V7.B16, V7
	VMOV V7.D[0], R7
	AND $255, R7, R7
	CBNZ R7, found
	ADD $16, R4
	B loop

found:
	MOVD R4, ret+32(FP)
	RET

none:
	MOVD $-1, R7
	MOVD R7, ret+32(FP)
	RET
