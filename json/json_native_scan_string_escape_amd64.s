//go:build amd64 && !jsonx_std

#include "textflag.h"

// func stringNeedsEscapeSSE2(s string, escapeHTML bool) (scan int, needs int)
// Scans full 16-byte blocks and returns the bytes scanned cleanly plus whether an escape-needing
// byte was found. | 扫描完整 16 字节块，返回干净扫描的字节数与是否发现需要转义的字节。
TEXT ·stringNeedsEscapeSSE2(SB), NOSPLIT, $0-40
	MOVQ s_base+0(FP), AX
	MOVQ s_len+8(FP), BX
	MOVBLZX escapeHTML+16(FP), R12
	XORQ R8, R8
	MOVOU quote16<>(SB), X1
	MOVOU backslash16<>(SB), X2
	MOVOU ctrl16<>(SB), X3
	MOVOU lt16<>(SB), X8
	MOVOU gt16<>(SB), X9
	MOVOU amp16<>(SB), X10
	PXOR X4, X4
	TESTL R12, R12
	JNE html

loop:
	MOVQ BX, R9
	SUBQ R8, R9
	CMPQ R9, $16
	JL clean
	LEAQ (AX)(R8*1), R10
	MOVOU (R10), X0
	MOVO X0, X5
	PCMPEQB X1, X5
	MOVO X0, X6
	PCMPEQB X2, X6
	POR X6, X5
	MOVO X0, X6
	PMINUB X3, X6
	PCMPEQB X0, X6
	POR X6, X5
	MOVO X4, X6
	PCMPGTB X0, X6
	POR X6, X5
	PMOVMSKB X5, R11
	TESTL R11, R11
	JNE found
	ADDQ $16, R8
	JMP loop

html:
	MOVQ BX, R9
	SUBQ R8, R9
	CMPQ R9, $16
	JL clean
	LEAQ (AX)(R8*1), R10
	MOVOU (R10), X0
	MOVO X0, X5
	PCMPEQB X1, X5
	MOVO X0, X6
	PCMPEQB X2, X6
	POR X6, X5
	MOVO X0, X6
	PMINUB X3, X6
	PCMPEQB X0, X6
	POR X6, X5
	MOVO X4, X6
	PCMPGTB X0, X6
	POR X6, X5
	MOVO X0, X6
	PCMPEQB X8, X6
	POR X6, X5
	MOVO X0, X6
	PCMPEQB X9, X6
	POR X6, X5
	MOVO X0, X6
	PCMPEQB X10, X6
	POR X6, X5
	PMOVMSKB X5, R11
	TESTL R11, R11
	JNE found
	ADDQ $16, R8
	JMP html

found:
	MOVQ R8, scan+24(FP)
	MOVQ $1, needs+32(FP)
	RET

clean:
	MOVQ R8, scan+24(FP)
	MOVQ $0, needs+32(FP)
	RET

DATA quote16<>+0(SB)/8, $0x2222222222222222
DATA quote16<>+8(SB)/8, $0x2222222222222222
GLOBL quote16<>(SB), RODATA, $16

DATA backslash16<>+0(SB)/8, $0x5c5c5c5c5c5c5c5c
DATA backslash16<>+8(SB)/8, $0x5c5c5c5c5c5c5c5c
GLOBL backslash16<>(SB), RODATA, $16

DATA ctrl16<>+0(SB)/8, $0x1f1f1f1f1f1f1f1f
DATA ctrl16<>+8(SB)/8, $0x1f1f1f1f1f1f1f1f
GLOBL ctrl16<>(SB), RODATA, $16

DATA lt16<>+0(SB)/8, $0x3c3c3c3c3c3c3c3c
DATA lt16<>+8(SB)/8, $0x3c3c3c3c3c3c3c3c
GLOBL lt16<>(SB), RODATA, $16

DATA gt16<>+0(SB)/8, $0x3e3e3e3e3e3e3e3e
DATA gt16<>+8(SB)/8, $0x3e3e3e3e3e3e3e3e
GLOBL gt16<>(SB), RODATA, $16

DATA amp16<>+0(SB)/8, $0x2626262626262626
DATA amp16<>+8(SB)/8, $0x2626262626262626
GLOBL amp16<>(SB), RODATA, $16
