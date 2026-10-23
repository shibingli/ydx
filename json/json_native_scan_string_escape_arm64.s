//go:build arm64 && !jsonx_std

#include "textflag.h"

// func stringNeedsEscapeNEON(s string, escapeHTML bool) (scan int, needs int)
// Scans full 16-byte blocks and returns the bytes scanned cleanly plus whether an escape-needing
// byte was found. | 扫描完整 16 字节块，返回干净扫描的字节数与是否发现需要转义的字节。
TEXT ·stringNeedsEscapeNEON(SB), NOSPLIT, $0-40
	MOVD s_base+0(FP), R0
	MOVD s_len+8(FP), R1
	MOVBU escapeHTML+16(FP), R8
	MOVD $0, R9
	VMOVI $0x22, V1.B16
	VMOVI $0x5c, V2.B16
	VMOVI $0x20, V3.B16
	VMOVI $0x7f, V4.B16
	VMOVI $0x3c, V5.B16
	VMOVI $0x3e, V6.B16
	VMOVI $0x26, V7.B16
	CBNZ R8, html

loop:
	SUB $16, R1, R10
	CMP $0, R10
	BLT clean
	ADD R0, R9, R11
	VLD1 (R11), [V0.B16]
	VCMEQ V1.B16, V0.B16, V8.B16
	VCMEQ V2.B16, V0.B16, V9.B16
	VORR V9.B16, V8.B16, V8.B16
	VCMHI V0.B16, V3.B16, V9.B16
	VORR V9.B16, V8.B16, V8.B16
	VCMHI V4.B16, V0.B16, V9.B16
	VORR V9.B16, V8.B16, V8.B16
	VUMAXV V8.B16, V8
	VMOV V8.S[0], R12
	AND $0xFF, R12
	CBNZ R12, found
	ADD $16, R9, R9
	B loop

html:
	SUB $16, R1, R10
	CMP $0, R10
	BLT clean
	ADD R0, R9, R11
	VLD1 (R11), [V0.B16]
	VCMEQ V1.B16, V0.B16, V8.B16
	VCMEQ V2.B16, V0.B16, V9.B16
	VORR V9.B16, V8.B16, V8.B16
	VCMHI V0.B16, V3.B16, V9.B16
	VORR V9.B16, V8.B16, V8.B16
	VCMHI V4.B16, V0.B16, V9.B16
	VORR V9.B16, V8.B16, V8.B16
	VCMEQ V5.B16, V0.B16, V9.B16
	VORR V9.B16, V8.B16, V8.B16
	VCMEQ V6.B16, V0.B16, V9.B16
	VORR V9.B16, V8.B16, V8.B16
	VCMEQ V7.B16, V0.B16, V9.B16
	VORR V9.B16, V8.B16, V8.B16
	VUMAXV V8.B16, V8
	VMOV V8.S[0], R12
	AND $0xFF, R12
	CBNZ R12, found
	ADD $16, R9, R9
	B html

found:
	MOVD R9, scan+24(FP)
	MOVD $1, R13
	MOVD R13, needs+32(FP)
	RET

clean:
	MOVD R9, scan+24(FP)
	MOVD $0, R13
	MOVD R13, needs+32(FP)
	RET
