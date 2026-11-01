//go:build amd64 && !xml_std

#include "textflag.h"

// func cpuID(eax, ecx uint32) (a, b, c, d uint32)
TEXT ·cpuID(SB), NOSPLIT, $0-24
	MOVL eax+0(FP), AX
	MOVL ecx+4(FP), CX
	CPUID
	MOVL AX, a+8(FP)
	MOVL BX, b+12(FP)
	MOVL CX, c+16(FP)
	MOVL DX, d+20(FP)
	RET

// func xgetbv(index uint32) uint64
TEXT ·xgetbv(SB), NOSPLIT, $0-16
	MOVL index+0(FP), CX
	XGETBV
	SHLQ $32, DX
	ORQ DX, AX
	MOVQ AX, ret+8(FP)
	RET

// func indexByteSSE2(data []byte, start int, c byte) int
TEXT ·indexByteSSE2(SB), NOSPLIT, $0-48
	MOVQ data_base+0(FP), AX
	MOVQ data_len+8(FP), BX
	MOVQ start+24(FP), R8
	MOVBLZX c+32(FP), R12
	MOVD R12, X1
	PUNPCKLBW X1, X1
	PUNPCKLWL X1, X1
	PSHUFD $0, X1, X1
loop:
	MOVQ BX, R9
	SUBQ R8, R9
	CMPQ R9, $16
	JL tail
	LEAQ (AX)(R8*1), R10
	MOVOU (R10), X0
	PCMPEQB X1, X0
	PMOVMSKB X0, R11
	TESTL R11, R11
	JNE hit
	ADDQ $16, R8
	JMP loop
hit:
	BSFL R11, R11
	ADDQ R11, R8
	MOVQ R8, ret+40(FP)
	RET
tail:
	CMPQ R8, BX
	JGE notfound
	MOVBLZX (AX)(R8*1), R11
	CMPB R11, R12
	JE found
	INCQ R8
	JMP tail
found:
	MOVQ R8, ret+40(FP)
	RET
notfound:
	MOVQ $-1, R8
	MOVQ R8, ret+40(FP)
	RET

// func indexAny2SSE2(data []byte, start int, c1, c2 byte) int
TEXT ·indexAny2SSE2(SB), NOSPLIT, $0-48
	MOVQ data_base+0(FP), AX
	MOVQ data_len+8(FP), BX
	MOVQ start+24(FP), R8
	MOVBLZX c1+32(FP), R12
	MOVBLZX c2+33(FP), R13
	MOVD R12, X1
	PUNPCKLBW X1, X1
	PUNPCKLWL X1, X1
	PSHUFD $0, X1, X1
	MOVD R13, X2
	PUNPCKLBW X2, X2
	PUNPCKLWL X2, X2
	PSHUFD $0, X2, X2
loop:
	MOVQ BX, R9
	SUBQ R8, R9
	CMPQ R9, $16
	JL tail
	LEAQ (AX)(R8*1), R10
	MOVOU (R10), X0
	MOVOU X0, X5
	PCMPEQB X1, X0
	PCMPEQB X2, X5
	POR X5, X0
	PMOVMSKB X0, R11
	TESTL R11, R11
	JNE hit
	ADDQ $16, R8
	JMP loop
hit:
	BSFL R11, R11
	ADDQ R11, R8
	MOVQ R8, ret+40(FP)
	RET
tail:
	CMPQ R8, BX
	JGE notfound
	MOVBLZX (AX)(R8*1), R11
	CMPB R11, R12
	JE found
	CMPB R11, R13
	JE found
	INCQ R8
	JMP tail
found:
	MOVQ R8, ret+40(FP)
	RET
notfound:
	MOVQ $-1, R8
	MOVQ R8, ret+40(FP)
	RET

// func indexAny3SSE2(data []byte, start int, c1, c2, c3 byte) int
TEXT ·indexAny3SSE2(SB), NOSPLIT, $0-48
	MOVQ data_base+0(FP), AX
	MOVQ data_len+8(FP), BX
	MOVQ start+24(FP), R8
	MOVBLZX c1+32(FP), R12
	MOVBLZX c2+33(FP), R13
	MOVBLZX c3+34(FP), R14
	MOVD R12, X1
	PUNPCKLBW X1, X1
	PUNPCKLWL X1, X1
	PSHUFD $0, X1, X1
	MOVD R13, X2
	PUNPCKLBW X2, X2
	PUNPCKLWL X2, X2
	PSHUFD $0, X2, X2
	MOVD R14, X3
	PUNPCKLBW X3, X3
	PUNPCKLWL X3, X3
	PSHUFD $0, X3, X3
loop:
	MOVQ BX, R9
	SUBQ R8, R9
	CMPQ R9, $16
	JL tail
	LEAQ (AX)(R8*1), R10
	MOVOU (R10), X0
	MOVOU X0, X5
	MOVOU X0, X6
	PCMPEQB X1, X0
	PCMPEQB X2, X5
	PCMPEQB X3, X6
	POR X5, X0
	POR X6, X0
	PMOVMSKB X0, R11
	TESTL R11, R11
	JNE hit
	ADDQ $16, R8
	JMP loop
hit:
	BSFL R11, R11
	ADDQ R11, R8
	MOVQ R8, ret+40(FP)
	RET
tail:
	CMPQ R8, BX
	JGE notfound
	MOVBLZX (AX)(R8*1), R11
	CMPB R11, R12
	JE found
	CMPB R11, R13
	JE found
	CMPB R11, R14
	JE found
	INCQ R8
	JMP tail
found:
	MOVQ R8, ret+40(FP)
	RET
notfound:
	MOVQ $-1, R8
	MOVQ R8, ret+40(FP)
	RET

// func indexAny4SSE2(data []byte, start int, c1, c2, c3, c4 byte) int
TEXT ·indexAny4SSE2(SB), NOSPLIT, $0-48
	MOVQ data_base+0(FP), AX
	MOVQ data_len+8(FP), BX
	MOVQ start+24(FP), R8
	MOVBLZX c1+32(FP), R12
	MOVBLZX c2+33(FP), R13
	MOVBLZX c3+34(FP), R14
	MOVBLZX c4+35(FP), R15
	MOVD R12, X1
	PUNPCKLBW X1, X1
	PUNPCKLWL X1, X1
	PSHUFD $0, X1, X1
	MOVD R13, X2
	PUNPCKLBW X2, X2
	PUNPCKLWL X2, X2
	PSHUFD $0, X2, X2
	MOVD R14, X3
	PUNPCKLBW X3, X3
	PUNPCKLWL X3, X3
	PSHUFD $0, X3, X3
	MOVD R15, X4
	PUNPCKLBW X4, X4
	PUNPCKLWL X4, X4
	PSHUFD $0, X4, X4
loop:
	MOVQ BX, R9
	SUBQ R8, R9
	CMPQ R9, $16
	JL tail
	LEAQ (AX)(R8*1), R10
	MOVOU (R10), X0
	MOVOU X0, X5
	MOVOU X0, X6
	MOVOU X0, X7
	PCMPEQB X1, X0
	PCMPEQB X2, X5
	PCMPEQB X3, X6
	PCMPEQB X4, X7
	POR X5, X0
	POR X7, X6
	POR X6, X0
	PMOVMSKB X0, R11
	TESTL R11, R11
	JNE hit
	ADDQ $16, R8
	JMP loop
hit:
	BSFL R11, R11
	ADDQ R11, R8
	MOVQ R8, ret+40(FP)
	RET
tail:
	CMPQ R8, BX
	JGE notfound
	MOVBLZX (AX)(R8*1), R11
	CMPB R11, R12
	JE found
	CMPB R11, R13
	JE found
	CMPB R11, R14
	JE found
	CMPB R11, R15
	JE found
	INCQ R8
	JMP tail
found:
	MOVQ R8, ret+40(FP)
	RET
notfound:
	MOVQ $-1, R8
	MOVQ R8, ret+40(FP)
	RET

