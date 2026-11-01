//go:build arm64 && !xml_std

#include "textflag.h"

// func indexByteNEON(data []byte, start int, c byte) int
TEXT ·indexByteNEON(SB), NOSPLIT, $0-48
	MOVD data_base+0(FP), R0
	MOVD data_len+8(FP), R1
	MOVD start+24(FP), R2
	MOVD c+32(FP), R3
	AND $0xFF, R3
	VDUP R3, V1.B16
loop:
	SUB R2, R1, R9
	CMP $16, R9
	BLT tail
	ADD R0, R2, R10
	VLD1 (R10), [V0.B16]
	VCMEQ V1.B16, V0.B16, V5.B16
	VUMAXV V5.B16, V7
	VMOV V7.S[0], R11
	AND $0xFF, R11
	CMP $0, R11
	BNE hit
	ADD $16, R2, R2
	B loop
hit:
	MOVD $0, R11
hitloop:
	CMP $16, R11
	BGE found
	ADD R10, R11, R12
	MOVBU (R12), R13
	CMP R3, R13
	BEQ found
	ADD $1, R11, R11
	B hitloop
found:
	ADD R11, R2, R2
	MOVD R2, ret+40(FP)
	RET
tail:
	CMP R1, R2
	BGE notfound
	ADD R0, R2, R10
	MOVBU (R10), R13
	CMP R3, R13
	BEQ tfound
	ADD $1, R2, R2
	B tail
tfound:
	MOVD R2, ret+40(FP)
	RET
notfound:
	MOVD $-1, R2
	MOVD R2, ret+40(FP)
	RET

// func indexAny2NEON(data []byte, start int, c1, c2 byte) int
TEXT ·indexAny2NEON(SB), NOSPLIT, $0-48
	MOVD data_base+0(FP), R0
	MOVD data_len+8(FP), R1
	MOVD start+24(FP), R2
	MOVD c1+32(FP), R3
	MOVD c2+33(FP), R4
	AND $0xFF, R3
	AND $0xFF, R4
	VDUP R3, V1.B16
	VDUP R4, V2.B16
loop:
	SUB R2, R1, R9
	CMP $16, R9
	BLT tail
	ADD R0, R2, R10
	VLD1 (R10), [V0.B16]
	VCMEQ V1.B16, V0.B16, V5.B16
	VCMEQ V2.B16, V0.B16, V6.B16
	VORR V6.B16, V5.B16, V5.B16
	VUMAXV V5.B16, V7
	VMOV V7.S[0], R11
	AND $0xFF, R11
	CMP $0, R11
	BNE hit
	ADD $16, R2, R2
	B loop
hit:
	MOVD $0, R11
hitloop:
	CMP $16, R11
	BGE found
	ADD R10, R11, R12
	MOVBU (R12), R13
	CMP R3, R13
	BEQ found
	CMP R4, R13
	BEQ found
	ADD $1, R11, R11
	B hitloop
found:
	ADD R11, R2, R2
	MOVD R2, ret+40(FP)
	RET
tail:
	CMP R1, R2
	BGE notfound
	ADD R0, R2, R10
	MOVBU (R10), R13
	CMP R3, R13
	BEQ tfound
	CMP R4, R13
	BEQ tfound
	ADD $1, R2, R2
	B tail
tfound:
	MOVD R2, ret+40(FP)
	RET
notfound:
	MOVD $-1, R2
	MOVD R2, ret+40(FP)
	RET

// func indexAny3NEON(data []byte, start int, c1, c2, c3 byte) int
TEXT ·indexAny3NEON(SB), NOSPLIT, $0-48
	MOVD data_base+0(FP), R0
	MOVD data_len+8(FP), R1
	MOVD start+24(FP), R2
	MOVD c1+32(FP), R3
	MOVD c2+33(FP), R4
	MOVD c3+34(FP), R5
	AND $0xFF, R3
	AND $0xFF, R4
	AND $0xFF, R5
	VDUP R3, V1.B16
	VDUP R4, V2.B16
	VDUP R5, V3.B16
loop:
	SUB R2, R1, R9
	CMP $16, R9
	BLT tail
	ADD R0, R2, R10
	VLD1 (R10), [V0.B16]
	VCMEQ V1.B16, V0.B16, V5.B16
	VCMEQ V2.B16, V0.B16, V6.B16
	VCMEQ V3.B16, V0.B16, V7.B16
	VORR V6.B16, V5.B16, V5.B16
	VORR V7.B16, V5.B16, V5.B16
	VUMAXV V5.B16, V7
	VMOV V7.S[0], R11
	AND $0xFF, R11
	CMP $0, R11
	BNE hit
	ADD $16, R2, R2
	B loop
hit:
	MOVD $0, R11
hitloop:
	CMP $16, R11
	BGE found
	ADD R10, R11, R12
	MOVBU (R12), R13
	CMP R3, R13
	BEQ found
	CMP R4, R13
	BEQ found
	CMP R5, R13
	BEQ found
	ADD $1, R11, R11
	B hitloop
found:
	ADD R11, R2, R2
	MOVD R2, ret+40(FP)
	RET
tail:
	CMP R1, R2
	BGE notfound
	ADD R0, R2, R10
	MOVBU (R10), R13
	CMP R3, R13
	BEQ tfound
	CMP R4, R13
	BEQ tfound
	CMP R5, R13
	BEQ tfound
	ADD $1, R2, R2
	B tail
tfound:
	MOVD R2, ret+40(FP)
	RET
notfound:
	MOVD $-1, R2
	MOVD R2, ret+40(FP)
	RET

// func indexAny4NEON(data []byte, start int, c1, c2, c3, c4 byte) int
TEXT ·indexAny4NEON(SB), NOSPLIT, $0-48
	MOVD data_base+0(FP), R0
	MOVD data_len+8(FP), R1
	MOVD start+24(FP), R2
	MOVD c1+32(FP), R3
	MOVD c2+33(FP), R4
	MOVD c3+34(FP), R5
	MOVD c4+35(FP), R6
	AND $0xFF, R3
	AND $0xFF, R4
	AND $0xFF, R5
	AND $0xFF, R6
	VDUP R3, V1.B16
	VDUP R4, V2.B16
	VDUP R5, V3.B16
	VDUP R6, V4.B16
loop:
	SUB R2, R1, R9
	CMP $16, R9
	BLT tail
	ADD R0, R2, R10
	VLD1 (R10), [V0.B16]
	VCMEQ V1.B16, V0.B16, V5.B16
	VCMEQ V2.B16, V0.B16, V6.B16
	VCMEQ V3.B16, V0.B16, V7.B16
	VCMEQ V4.B16, V0.B16, V8.B16
	VORR V6.B16, V5.B16, V5.B16
	VORR V8.B16, V7.B16, V7.B16
	VORR V7.B16, V5.B16, V5.B16
	VUMAXV V5.B16, V9
	VMOV V9.S[0], R11
	AND $0xFF, R11
	CMP $0, R11
	BNE hit
	ADD $16, R2, R2
	B loop
hit:
	MOVD $0, R11
hitloop:
	CMP $16, R11
	BGE found
	ADD R10, R11, R12
	MOVBU (R12), R13
	CMP R3, R13
	BEQ found
	CMP R4, R13
	BEQ found
	CMP R5, R13
	BEQ found
	CMP R6, R13
	BEQ found
	ADD $1, R11, R11
	B hitloop
found:
	ADD R11, R2, R2
	MOVD R2, ret+40(FP)
	RET
tail:
	CMP R1, R2
	BGE notfound
	ADD R0, R2, R10
	MOVBU (R10), R13
	CMP R3, R13
	BEQ tfound
	CMP R4, R13
	BEQ tfound
	CMP R5, R13
	BEQ tfound
	CMP R6, R13
	BEQ tfound
	ADD $1, R2, R2
	B tail
tfound:
	MOVD R2, ret+40(FP)
	RET
notfound:
	MOVD $-1, R2
	MOVD R2, ret+40(FP)
	RET
