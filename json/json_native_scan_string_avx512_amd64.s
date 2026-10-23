//go:build amd64 && !jsonx_std

#include "textflag.h"

// func scanStringBodyAVX512(data []byte, start int) int
// Returns the start of the first 64-byte block containing a quote, backslash, control byte or
// non-ASCII byte, or the position after the last full clean block. Requires AVX-512F + BW. |
// 返回首个含引号、反斜杠、控制字节或非 ASCII 字节的 64 字节块起点；若全部干净，则返回最后一个完整块之后的位置。需要 AVX-512F + BW。
TEXT ·scanStringBodyAVX512(SB), NOSPLIT, $0-40
	MOVQ data_base+0(FP), AX
	MOVQ data_len+8(FP), BX
	MOVQ start+24(FP), CX
	MOVQ CX, R8
	VMOVDQU64 quote64<>(SB), Z1
	VMOVDQU64 backslash64<>(SB), Z2
	VMOVDQU64 ctrl64<>(SB), Z3

loop:
	MOVQ BX, R9
	SUBQ R8, R9
	CMPQ R9, $64
	JL done
	LEAQ (AX)(R8*1), R10
	VMOVDQU64 (R10), Z0
	VPCMPEQB Z1, Z0, K1
	VPCMPEQB Z2, Z0, K2
	KORQ K2, K1, K1
	VPCMPUB $1, Z3, Z0, K2
	KORQ K2, K1, K1
	VPMOVB2M Z0, K2
	KORQ K2, K1, K1
	KORTESTQ K1, K1
	JNZ done
	ADDQ $64, R8
	JMP loop

done:
	VZEROUPPER
	MOVQ R8, ret+32(FP)
	RET

// func stringNeedsEscapeAVX512(s string, escapeHTML bool) (scan int, needs int)
// Scans full 64-byte blocks and returns the bytes scanned cleanly plus whether an escape-needing
// byte was found. Requires AVX-512F + BW. | 扫描完整 64 字节块，返回干净扫描的字节数与是否发现需要转义的字节。需要 AVX-512F + BW。
TEXT ·stringNeedsEscapeAVX512(SB), NOSPLIT, $0-40
	MOVQ s_base+0(FP), AX
	MOVQ s_len+8(FP), BX
	MOVBLZX escapeHTML+16(FP), R12
	XORQ R8, R8
	VMOVDQU64 quote64<>(SB), Z1
	VMOVDQU64 backslash64<>(SB), Z2
	VMOVDQU64 ctrl64<>(SB), Z3
	VMOVDQU64 lt64<>(SB), Z8
	VMOVDQU64 gt64<>(SB), Z9
	VMOVDQU64 amp64<>(SB), Z10
	TESTL R12, R12
	JNE html

loop:
	MOVQ BX, R9
	SUBQ R8, R9
	CMPQ R9, $64
	JL clean
	LEAQ (AX)(R8*1), R10
	VMOVDQU64 (R10), Z0
	VPCMPEQB Z1, Z0, K1
	VPCMPEQB Z2, Z0, K2
	KORQ K2, K1, K1
	VPCMPUB $1, Z3, Z0, K2
	KORQ K2, K1, K1
	VPMOVB2M Z0, K2
	KORQ K2, K1, K1
	KORTESTQ K1, K1
	JNZ found
	ADDQ $64, R8
	JMP loop

html:
	MOVQ BX, R9
	SUBQ R8, R9
	CMPQ R9, $64
	JL clean
	LEAQ (AX)(R8*1), R10
	VMOVDQU64 (R10), Z0
	VPCMPEQB Z1, Z0, K1
	VPCMPEQB Z2, Z0, K2
	KORQ K2, K1, K1
	VPCMPUB $1, Z3, Z0, K2
	KORQ K2, K1, K1
	VPMOVB2M Z0, K2
	KORQ K2, K1, K1
	VPCMPEQB Z8, Z0, K2
	KORQ K2, K1, K1
	VPCMPEQB Z9, Z0, K2
	KORQ K2, K1, K1
	VPCMPEQB Z10, Z0, K2
	KORQ K2, K1, K1
	KORTESTQ K1, K1
	JNZ found
	ADDQ $64, R8
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

DATA quote64<>+0(SB)/8, $0x2222222222222222
DATA quote64<>+8(SB)/8, $0x2222222222222222
DATA quote64<>+16(SB)/8, $0x2222222222222222
DATA quote64<>+24(SB)/8, $0x2222222222222222
DATA quote64<>+32(SB)/8, $0x2222222222222222
DATA quote64<>+40(SB)/8, $0x2222222222222222
DATA quote64<>+48(SB)/8, $0x2222222222222222
DATA quote64<>+56(SB)/8, $0x2222222222222222
GLOBL quote64<>(SB), RODATA, $64

DATA backslash64<>+0(SB)/8, $0x5c5c5c5c5c5c5c5c
DATA backslash64<>+8(SB)/8, $0x5c5c5c5c5c5c5c5c
DATA backslash64<>+16(SB)/8, $0x5c5c5c5c5c5c5c5c
DATA backslash64<>+24(SB)/8, $0x5c5c5c5c5c5c5c5c
DATA backslash64<>+32(SB)/8, $0x5c5c5c5c5c5c5c5c
DATA backslash64<>+40(SB)/8, $0x5c5c5c5c5c5c5c5c
DATA backslash64<>+48(SB)/8, $0x5c5c5c5c5c5c5c5c
DATA backslash64<>+56(SB)/8, $0x5c5c5c5c5c5c5c5c
GLOBL backslash64<>(SB), RODATA, $64

DATA ctrl64<>+0(SB)/8, $0x1f1f1f1f1f1f1f1f
DATA ctrl64<>+8(SB)/8, $0x1f1f1f1f1f1f1f1f
DATA ctrl64<>+16(SB)/8, $0x1f1f1f1f1f1f1f1f
DATA ctrl64<>+24(SB)/8, $0x1f1f1f1f1f1f1f1f
DATA ctrl64<>+32(SB)/8, $0x1f1f1f1f1f1f1f1f
DATA ctrl64<>+40(SB)/8, $0x1f1f1f1f1f1f1f1f
DATA ctrl64<>+48(SB)/8, $0x1f1f1f1f1f1f1f1f
DATA ctrl64<>+56(SB)/8, $0x1f1f1f1f1f1f1f1f
GLOBL ctrl64<>(SB), RODATA, $64

DATA lt64<>+0(SB)/8, $0x3c3c3c3c3c3c3c3c
DATA lt64<>+8(SB)/8, $0x3c3c3c3c3c3c3c3c
DATA lt64<>+16(SB)/8, $0x3c3c3c3c3c3c3c3c
DATA lt64<>+24(SB)/8, $0x3c3c3c3c3c3c3c3c
DATA lt64<>+32(SB)/8, $0x3c3c3c3c3c3c3c3c
DATA lt64<>+40(SB)/8, $0x3c3c3c3c3c3c3c3c
DATA lt64<>+48(SB)/8, $0x3c3c3c3c3c3c3c3c
DATA lt64<>+56(SB)/8, $0x3c3c3c3c3c3c3c3c
GLOBL lt64<>(SB), RODATA, $64

DATA gt64<>+0(SB)/8, $0x3e3e3e3e3e3e3e3e
DATA gt64<>+8(SB)/8, $0x3e3e3e3e3e3e3e3e
DATA gt64<>+16(SB)/8, $0x3e3e3e3e3e3e3e3e
DATA gt64<>+24(SB)/8, $0x3e3e3e3e3e3e3e3e
DATA gt64<>+32(SB)/8, $0x3e3e3e3e3e3e3e3e
DATA gt64<>+40(SB)/8, $0x3e3e3e3e3e3e3e3e
DATA gt64<>+48(SB)/8, $0x3e3e3e3e3e3e3e3e
DATA gt64<>+56(SB)/8, $0x3e3e3e3e3e3e3e3e
GLOBL gt64<>(SB), RODATA, $64

DATA amp64<>+0(SB)/8, $0x2626262626262626
DATA amp64<>+8(SB)/8, $0x2626262626262626
DATA amp64<>+16(SB)/8, $0x2626262626262626
DATA amp64<>+24(SB)/8, $0x2626262626262626
DATA amp64<>+32(SB)/8, $0x2626262626262626
DATA amp64<>+40(SB)/8, $0x2626262626262626
DATA amp64<>+48(SB)/8, $0x2626262626262626
DATA amp64<>+56(SB)/8, $0x2626262626262626
GLOBL amp64<>(SB), RODATA, $64
