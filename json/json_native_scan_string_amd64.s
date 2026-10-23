//go:build amd64 && !jsonx_std

#include "textflag.h"

// func scanStringBodySSE2(data []byte, start int) int
// Returns the start of the first 16-byte block containing a quote, backslash, control byte or
// non-ASCII byte, or the position after the last full clean block. |
// 返回首个含引号、反斜杠、控制字节或非 ASCII 字节的 16 字节块起点；若全部干净，则返回最后一个完整块之后的位置。
TEXT ·scanStringBodySSE2(SB), NOSPLIT, $0-40
	MOVQ data_base+0(FP), AX
	MOVQ data_len+8(FP), BX
	MOVQ start+24(FP), CX
	MOVQ CX, R8
	MOVOU quote16<>(SB), X1
	MOVOU backslash16<>(SB), X2
	MOVOU ctrl16<>(SB), X3
	PXOR X4, X4

loop:
	MOVQ BX, R9
	SUBQ R8, R9
	CMPQ R9, $16
	JL done
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
	JNE done
	ADDQ $16, R8
	JMP loop

done:
	MOVQ R8, ret+32(FP)
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
