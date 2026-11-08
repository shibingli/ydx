//go:build arm64 && !jsonx_std

#include "textflag.h"

// func skipSpaceNEON(data []byte, start int) int
// Returns the start of the first 16-byte block containing a non-whitespace byte, or the position
// after the last full whitespace block. | 返回首个含非空白字节的 16 字节块起点；若全部为空白，则返回
// 最后一个完整块之后的位置。
TEXT ·skipSpaceNEON(SB), NOSPLIT, $0-40
	MOVD data_base+0(FP), R0
	MOVD data_len+8(FP), R1
	MOVD start+24(FP), R2
	SUB R2, R1, R1
	VMOVI $0x20, V1.B16
	VMOVI $0x09, V2.B16
	VMOVI $0x0a, V3.B16
	VMOVI $0x0d, V4.B16

loop:
	CMP $16, R1
	BLT done
	ADD R0, R2, R6
	VLD1 (R6), [V0.B16]
	VCMEQ V1.B16, V0.B16, V5.B16
	VCMEQ V2.B16, V0.B16, V6.B16
	VORR V6.B16, V5.B16, V5.B16
	VCMEQ V3.B16, V0.B16, V6.B16
	VORR V6.B16, V5.B16, V5.B16
	VCMEQ V4.B16, V0.B16, V6.B16
	VORR V6.B16, V5.B16, V5.B16
	VUMINV V5.B16, V5
	VMOV V5.S[0], R7
	AND $0xFF, R7
	CMP $0xFF, R7
	BNE done
	ADD $16, R2, R2
	SUB $16, R1, R1
	B loop

done:
	MOVD R2, ret+32(FP)
	RET

// func scanDigitsNEON(data []byte, start int) int
// Returns the start of the first 16-byte block containing a non-digit byte, or the position after
// the last full digit block. | 返回首个含非数字字节的 16 字节块起点；若全部为数字，则返回最后一个
// 完整块之后的位置。
TEXT ·scanDigitsNEON(SB), NOSPLIT, $0-40
	MOVD data_base+0(FP), R0
	MOVD data_len+8(FP), R1
	MOVD start+24(FP), R2
	SUB R2, R1, R1
	// V3 = c > 0x2f (c >= '0'); V4 = 0x3a > c (c <= '9'). | V3 判定下界，V4 判定上界。
	VMOVI $0x2f, V1.B16
	VMOVI $0x3a, V2.B16

loop:
	CMP $16, R1
	BLT done
	ADD R0, R2, R6
	VLD1 (R6), [V0.B16]
	VCMHI V1.B16, V0.B16, V3.B16
	VCMHI V0.B16, V2.B16, V4.B16
	VAND V4.B16, V3.B16, V5.B16
	VUMINV V5.B16, V5
	VMOV V5.S[0], R7
	AND $0xFF, R7
	CMP $0xFF, R7
	BNE done
	ADD $16, R2, R2
	SUB $16, R1, R1
	B loop

done:
	MOVD R2, ret+32(FP)
	RET

// func scanCompactOutsideNEON(src []byte, pos int) int
// Returns the start of the first 16-byte block containing a quote or JSON whitespace, or the
// position after the last full clean block. | 返回首个含引号或 JSON 空白的 16 字节块起点；若全部
// 干净，则返回最后一个完整块之后的位置。
TEXT ·scanCompactOutsideNEON(SB), NOSPLIT, $0-40
	MOVD src_base+0(FP), R0
	MOVD src_len+8(FP), R1
	MOVD pos+24(FP), R2
	SUB R2, R1, R1
	VMOVI $0x22, V1.B16
	VMOVI $0x20, V2.B16
	VMOVI $0x09, V3.B16
	VMOVI $0x0a, V4.B16
	VMOVI $0x0d, V5.B16

loop:
	CMP $16, R1
	BLT done
	ADD R0, R2, R6
	VLD1 (R6), [V0.B16]
	VCMEQ V1.B16, V0.B16, V7.B16
	VCMEQ V2.B16, V0.B16, V8.B16
	VORR V8.B16, V7.B16, V7.B16
	VCMEQ V3.B16, V0.B16, V8.B16
	VORR V8.B16, V7.B16, V7.B16
	VCMEQ V4.B16, V0.B16, V8.B16
	VORR V8.B16, V7.B16, V7.B16
	VCMEQ V5.B16, V0.B16, V8.B16
	VORR V8.B16, V7.B16, V7.B16
	VUMAXV V7.B16, V7
	VMOV V7.S[0], R7
	AND $0xFF, R7
	CBNZ R7, done
	ADD $16, R2, R2
	SUB $16, R1, R1
	B loop

done:
	MOVD R2, ret+32(FP)
	RET

// func scanCompactInsideNEON(src []byte, pos int, escapeHTML bool) int
// Returns the start of the first 16-byte block containing a byte that appendCompactJSON must copy
// specially, or the position after the last full clean block. | 返回首个含 appendCompactJSON 必须
// 特殊处理字节的 16 字节块起点；若全部干净，则返回最后一个完整块之后的位置。
TEXT ·scanCompactInsideNEON(SB), NOSPLIT, $0-48
	MOVD src_base+0(FP), R0
	MOVD src_len+8(FP), R1
	MOVD pos+24(FP), R2
	SUB R2, R1, R1
	MOVBU escapeHTML+32(FP), R8
	VMOVI $0x22, V1.B16
	VMOVI $0x5c, V2.B16
	VMOVI $0x20, V3.B16
	VMOVI $0x3c, V5.B16
	VMOVI $0x3e, V6.B16
	VMOVI $0x26, V7.B16
	VMOVI $0xe2, V9.B16
	CBNZ R8, html

loop:
	CMP $16, R1
	BLT done
	ADD R0, R2, R6
	VLD1 (R6), [V0.B16]
	VCMEQ V1.B16, V0.B16, V4.B16
	VCMEQ V2.B16, V0.B16, V8.B16
	VORR V8.B16, V4.B16, V4.B16
	VCMHI V0.B16, V3.B16, V8.B16
	VORR V8.B16, V4.B16, V4.B16
	VUMAXV V4.B16, V4
	VMOV V4.S[0], R7
	AND $0xFF, R7
	CBNZ R7, done
	ADD $16, R2, R2
	SUB $16, R1, R1
	B loop

html:
	CMP $16, R1
	BLT done
	ADD R0, R2, R6
	VLD1 (R6), [V0.B16]
	VCMEQ V1.B16, V0.B16, V4.B16
	VCMEQ V2.B16, V0.B16, V8.B16
	VORR V8.B16, V4.B16, V4.B16
	VCMHI V0.B16, V3.B16, V8.B16
	VORR V8.B16, V4.B16, V4.B16
	VCMEQ V5.B16, V0.B16, V8.B16
	VORR V8.B16, V4.B16, V4.B16
	VCMEQ V6.B16, V0.B16, V8.B16
	VORR V8.B16, V4.B16, V4.B16
	VCMEQ V7.B16, V0.B16, V8.B16
	VORR V8.B16, V4.B16, V4.B16
	VCMEQ V9.B16, V0.B16, V8.B16
	VORR V8.B16, V4.B16, V4.B16
	VUMAXV V4.B16, V4
	VMOV V4.S[0], R7
	AND $0xFF, R7
	CBNZ R7, done
	ADD $16, R2, R2
	SUB $16, R1, R1
	B html

done:
	MOVD R2, ret+40(FP)
	RET
