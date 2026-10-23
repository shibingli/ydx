//go:build amd64 && !jsonx_std

#include "textflag.h"

// func scanStringBodyAVX2(data []byte, start int) int
// Returns the start of the first 32-byte block containing a quote, backslash, control byte or
// non-ASCII byte, or the position after the last full clean block. |
// 返回首个含引号、反斜杠、控制字节或非 ASCII 字节的 32 字节块起点；若全部干净，则返回最后一个完整块之后的位置。
TEXT ·scanStringBodyAVX2(SB), NOSPLIT, $0-40
	MOVQ data_base+0(FP), AX
	MOVQ data_len+8(FP), BX
	MOVQ start+24(FP), CX
	MOVQ CX, R8
	VMOVDQU quote32<>(SB), Y1
	VMOVDQU backslash32<>(SB), Y2
	VMOVDQU ctrl32<>(SB), Y3
	VPXOR Y4, Y4, Y4

loop:
	MOVQ BX, R9
	SUBQ R8, R9
	CMPQ R9, $32
	JL done
	LEAQ (AX)(R8*1), R10
	VMOVDQU (R10), Y0
	VPCMPEQB Y1, Y0, Y5
	VPCMPEQB Y2, Y0, Y6
	VPOR Y6, Y5, Y5
	VPMINUB Y3, Y0, Y6
	VPCMPEQB Y6, Y0, Y6
	VPOR Y6, Y5, Y5
	VPCMPGTB Y0, Y4, Y6
	VPOR Y6, Y5, Y5
	VPMOVMSKB Y5, R11
	TESTL R11, R11
	JNE done
	ADDQ $32, R8
	JMP loop

done:
	VZEROUPPER
	MOVQ R8, ret+32(FP)
	RET

// func stringNeedsEscapeAVX2(s string, escapeHTML bool) (scan int, needs int)
// Scans full 32-byte blocks and returns the bytes scanned cleanly plus whether an escape-needing
// byte was found. | 扫描完整 32 字节块，返回干净扫描的字节数与是否发现需要转义的字节。
TEXT ·stringNeedsEscapeAVX2(SB), NOSPLIT, $0-40
	MOVQ s_base+0(FP), AX
	MOVQ s_len+8(FP), BX
	MOVBLZX escapeHTML+16(FP), R12
	XORQ R8, R8
	VMOVDQU quote32<>(SB), Y1
	VMOVDQU backslash32<>(SB), Y2
	VMOVDQU ctrl32<>(SB), Y3
	VMOVDQU lt32<>(SB), Y8
	VMOVDQU gt32<>(SB), Y9
	VMOVDQU amp32<>(SB), Y10
	VPXOR Y4, Y4, Y4
	TESTL R12, R12
	JNE html

loop:
	MOVQ BX, R9
	SUBQ R8, R9
	CMPQ R9, $32
	JL clean
	LEAQ (AX)(R8*1), R10
	VMOVDQU (R10), Y0
	VPCMPEQB Y1, Y0, Y5
	VPCMPEQB Y2, Y0, Y6
	VPOR Y6, Y5, Y5
	VPMINUB Y3, Y0, Y6
	VPCMPEQB Y6, Y0, Y6
	VPOR Y6, Y5, Y5
	VPCMPGTB Y0, Y4, Y6
	VPOR Y6, Y5, Y5
	VPMOVMSKB Y5, R11
	TESTL R11, R11
	JNE found
	ADDQ $32, R8
	JMP loop

html:
	MOVQ BX, R9
	SUBQ R8, R9
	CMPQ R9, $32
	JL clean
	LEAQ (AX)(R8*1), R10
	VMOVDQU (R10), Y0
	VPCMPEQB Y1, Y0, Y5
	VPCMPEQB Y2, Y0, Y6
	VPOR Y6, Y5, Y5
	VPMINUB Y3, Y0, Y6
	VPCMPEQB Y6, Y0, Y6
	VPOR Y6, Y5, Y5
	VPCMPGTB Y0, Y4, Y6
	VPOR Y6, Y5, Y5
	VPCMPEQB Y8, Y0, Y6
	VPOR Y6, Y5, Y5
	VPCMPEQB Y9, Y0, Y6
	VPOR Y6, Y5, Y5
	VPCMPEQB Y10, Y0, Y6
	VPOR Y6, Y5, Y5
	VPMOVMSKB Y5, R11
	TESTL R11, R11
	JNE found
	ADDQ $32, R8
	JMP html

found:
	VZEROUPPER
	MOVQ R8, scan+24(FP)
	MOVQ $1, needs+32(FP)
	RET

clean:
	VZEROUPPER
	MOVQ R8, scan+24(FP)
	MOVQ $0, needs+32(FP)
	RET

DATA quote32<>+0(SB)/8, $0x2222222222222222
DATA quote32<>+8(SB)/8, $0x2222222222222222
DATA quote32<>+16(SB)/8, $0x2222222222222222
DATA quote32<>+24(SB)/8, $0x2222222222222222
GLOBL quote32<>(SB), RODATA, $32

DATA backslash32<>+0(SB)/8, $0x5c5c5c5c5c5c5c5c
DATA backslash32<>+8(SB)/8, $0x5c5c5c5c5c5c5c5c
DATA backslash32<>+16(SB)/8, $0x5c5c5c5c5c5c5c5c
DATA backslash32<>+24(SB)/8, $0x5c5c5c5c5c5c5c5c
GLOBL backslash32<>(SB), RODATA, $32

DATA ctrl32<>+0(SB)/8, $0x1f1f1f1f1f1f1f1f
DATA ctrl32<>+8(SB)/8, $0x1f1f1f1f1f1f1f1f
DATA ctrl32<>+16(SB)/8, $0x1f1f1f1f1f1f1f1f
DATA ctrl32<>+24(SB)/8, $0x1f1f1f1f1f1f1f1f
GLOBL ctrl32<>(SB), RODATA, $32

DATA lt32<>+0(SB)/8, $0x3c3c3c3c3c3c3c3c
DATA lt32<>+8(SB)/8, $0x3c3c3c3c3c3c3c3c
DATA lt32<>+16(SB)/8, $0x3c3c3c3c3c3c3c3c
DATA lt32<>+24(SB)/8, $0x3c3c3c3c3c3c3c3c
GLOBL lt32<>(SB), RODATA, $32

DATA gt32<>+0(SB)/8, $0x3e3e3e3e3e3e3e3e
DATA gt32<>+8(SB)/8, $0x3e3e3e3e3e3e3e3e
DATA gt32<>+16(SB)/8, $0x3e3e3e3e3e3e3e3e
DATA gt32<>+24(SB)/8, $0x3e3e3e3e3e3e3e3e
GLOBL gt32<>(SB), RODATA, $32

DATA amp32<>+0(SB)/8, $0x2626262626262626
DATA amp32<>+8(SB)/8, $0x2626262626262626
DATA amp32<>+16(SB)/8, $0x2626262626262626
DATA amp32<>+24(SB)/8, $0x2626262626262626
GLOBL amp32<>(SB), RODATA, $32
