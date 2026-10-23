//go:build amd64

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

// func xgetbv() (eax, edx uint32)
TEXT ·xgetbv(SB), NOSPLIT, $0-8
	MOVL $0, CX
	XGETBV
	MOVL AX, eax+0(FP)
	MOVL DX, edx+4(FP)
	RET

// func indexByteAVX2(s string, c byte, from int) int
// Scans full 32-byte blocks for c. | 以 32 字节块扫描 c。
TEXT ·indexByteAVX2(SB), NOSPLIT, $0-40
	MOVQ s_base+0(FP), AX
	MOVQ s_len+8(FP), BX
	MOVBLZX c+16(FP), CX
	MOVQ from+24(FP), DI
	VMOVD CX, X1
	VPBROADCASTB X1, Y1

loop:
	MOVQ BX, R9
	SUBQ DI, R9
	CMPQ R9, $32
	JL none
	LEAQ (AX)(DI*1), R10
	VMOVDQU (R10), Y0
	VPCMPEQB Y1, Y0, Y2
	VPMOVMSKB Y2, R11
	TESTL R11, R11
	JNE found
	ADDQ $32, DI
	JMP loop

found:
	BSFL R11, R11
	ADDQ DI, R11
	MOVQ R11, ret+32(FP)
	VZEROUPPER
	RET

none:
	MOVQ $-1, R11
	MOVQ R11, ret+32(FP)
	VZEROUPPER
	RET

// func indexByteAVX512(s string, c byte, from int) int
// Scans full 64-byte blocks for c with AVX-512BW. | 用 AVX-512BW 以 64 字节块扫描 c。
TEXT ·indexByteAVX512(SB), NOSPLIT, $0-40
	MOVQ s_base+0(FP), AX
	MOVQ s_len+8(FP), BX
	MOVBLZX c+16(FP), CX
	MOVQ from+24(FP), DI
	VMOVD CX, X1
	VPBROADCASTB X1, Z1

loop:
	MOVQ BX, R9
	SUBQ DI, R9
	CMPQ R9, $64
	JL none
	LEAQ (AX)(DI*1), R10
	VMOVDQU64 (R10), Z0
	VPCMPEQB Z1, Z0, K1
	KMOVQ K1, R11
	TESTQ R11, R11
	JNE found
	ADDQ $64, DI
	JMP loop

found:
	BSFQ R11, R11
	ADDQ DI, R11
	MOVQ R11, ret+32(FP)
	VZEROUPPER
	RET

none:
	MOVQ $-1, R11
	MOVQ R11, ret+32(FP)
	VZEROUPPER
	RET

// func indexByteSetAVX2(s string, t *[128]byte, from int) int
// Scans full 32-byte blocks for any byte in the table set. The table holds four copies of the low
// nibble table followed by four copies of the high nibble table. | 以 32 字节块扫描表集合中的任意字节。
// 表包含低半字节表的四份副本，随后是高半字节表的四份副本。
TEXT ·indexByteSetAVX2(SB), NOSPLIT, $0-40
	MOVQ s_base+0(FP), AX
	MOVQ s_len+8(FP), BX
	MOVQ t+16(FP), SI
	MOVQ from+24(FP), DI
	VMOVDQU 0(SI), Y1
	VMOVDQU 64(SI), Y2
	VMOVDQU mask0F32<>(SB), Y7
	VPXOR Y8, Y8, Y8

loop:
	MOVQ BX, R9
	SUBQ DI, R9
	CMPQ R9, $32
	JL none
	LEAQ (AX)(DI*1), R10
	VMOVDQU (R10), Y0
	VPSRLW $4, Y0, Y3
	VPAND Y7, Y3, Y3
	VPAND Y7, Y0, Y4
	VPSHUFB Y4, Y1, Y5
	VPSHUFB Y3, Y2, Y6
	VPAND Y6, Y5, Y5
	VPCMPEQB Y8, Y5, Y5
	VPMOVMSKB Y5, R11
	NOTL R11
	TESTL R11, R11
	JNE found
	ADDQ $32, DI
	JMP loop

found:
	BSFL R11, R11
	ADDQ DI, R11
	MOVQ R11, ret+32(FP)
	VZEROUPPER
	RET

none:
	MOVQ $-1, R11
	MOVQ R11, ret+32(FP)
	VZEROUPPER
	RET

// func indexByteSetAVX512(s string, t *[128]byte, from int) int
// Scans full 64-byte blocks for any byte in the table set with AVX-512BW. | 用 AVX-512BW 以 64 字节块
// 扫描表集合中的任意字节。
TEXT ·indexByteSetAVX512(SB), NOSPLIT, $0-40
	MOVQ s_base+0(FP), AX
	MOVQ s_len+8(FP), BX
	MOVQ t+16(FP), SI
	MOVQ from+24(FP), DI
	VMOVDQU64 0(SI), Z1
	VMOVDQU64 64(SI), Z2
	VMOVDQU64 mask0F64<>(SB), Z7
	VPXORQ Z8, Z8, Z8

loop:
	MOVQ BX, R9
	SUBQ DI, R9
	CMPQ R9, $64
	JL none
	LEAQ (AX)(DI*1), R10
	VMOVDQU64 (R10), Z0
	VPSRLW $4, Z0, Z3
	VPANDQ Z7, Z3, Z3
	VPANDQ Z7, Z0, Z4
	VPSHUFB Z4, Z1, Z5
	VPSHUFB Z3, Z2, Z6
	VPANDQ Z6, Z5, Z5
	VPCMPEQB Z8, Z5, K1
	KMOVQ K1, R11
	NOTQ R11
	TESTQ R11, R11
	JNE found
	ADDQ $64, DI
	JMP loop

found:
	BSFQ R11, R11
	ADDQ DI, R11
	MOVQ R11, ret+32(FP)
	VZEROUPPER
	RET

none:
	MOVQ $-1, R11
	MOVQ R11, ret+32(FP)
	VZEROUPPER
	RET

// func indexByteSSE42(s string, c byte, from int) int
// Scans full 16-byte blocks for c on SSE4.2 CPUs. PCMPESTRI was measured slower than the byte
// compare loop for both absent and early matches, so this entry shares the faster 16-byte loop; the
// dispatcher still prefers SSE4.2 over SSE4.1. | 在 SSE4.2 CPU 上以 16 字节块扫描 c。实测 PCMPESTRI
// 在无匹配与提前匹配两种情况下都慢于字节比较循环，因此该入口使用更快的 16 字节循环；分发时仍优先
// SSE4.2 而非 SSE4.1。
TEXT ·indexByteSSE42(SB), NOSPLIT, $0-40
	MOVQ s_base+0(FP), AX
	MOVQ s_len+8(FP), BX
	MOVBLZX c+16(FP), CX
	MOVQ from+24(FP), DI
	MOVD CX, X1
	PUNPCKLBW X1, X1
	PUNPCKLWL X1, X1
	PSHUFD $0, X1, X1

loop:
	MOVQ BX, R9
	SUBQ DI, R9
	CMPQ R9, $16
	JL none
	LEAQ (AX)(DI*1), R10
	MOVOU (R10), X0
	PCMPEQB X1, X0
	PMOVMSKB X0, R11
	TESTL R11, R11
	JNE found
	ADDQ $16, DI
	JMP loop

found:
	BSFL R11, R11
	ADDQ DI, R11
	MOVQ R11, ret+32(FP)
	RET

none:
	MOVQ $-1, R11
	MOVQ R11, ret+32(FP)
	RET

// func indexByteSSE41(s string, c byte, from int) int
// Scans full 16-byte blocks for c with SSE4.1 for CPUs without AVX2. | 为不支持 AVX2 的 CPU 用 SSE4.1
// 以 16 字节块扫描 c。
TEXT ·indexByteSSE41(SB), NOSPLIT, $0-40
	MOVQ s_base+0(FP), AX
	MOVQ s_len+8(FP), BX
	MOVBLZX c+16(FP), CX
	MOVQ from+24(FP), DI
	MOVD CX, X1
	PUNPCKLBW X1, X1
	PUNPCKLWL X1, X1
	PSHUFD $0, X1, X1

loop:
	MOVQ BX, R9
	SUBQ DI, R9
	CMPQ R9, $16
	JL none
	LEAQ (AX)(DI*1), R10
	MOVOU (R10), X0
	PCMPEQB X1, X0
	PMOVMSKB X0, R11
	TESTL R11, R11
	JNE found
	ADDQ $16, DI
	JMP loop

found:
	BSFL R11, R11
	ADDQ DI, R11
	MOVQ R11, ret+32(FP)
	RET

none:
	MOVQ $-1, R11
	MOVQ R11, ret+32(FP)
	RET

// func indexByteSetSSE41(s string, t *[128]byte, from int) int
// Scans full 16-byte blocks for any byte in the table set with SSE4.1. | 用 SSE4.1 以 16 字节块扫描表
// 集合中的任意字节。
TEXT ·indexByteSetSSE41(SB), NOSPLIT, $0-40
	MOVQ s_base+0(FP), AX
	MOVQ s_len+8(FP), BX
	MOVQ t+16(FP), SI
	MOVQ from+24(FP), DI
	MOVOU 0(SI), X1
	MOVOU 64(SI), X2
	MOVOU mask0F16<>(SB), X7
	PXOR X8, X8

loop:
	MOVQ BX, R9
	SUBQ DI, R9
	CMPQ R9, $16
	JL none
	LEAQ (AX)(DI*1), R10
	MOVOU (R10), X0
	MOVOU X0, X4
	PSRLW $4, X4
	PAND X7, X4
	PAND X7, X0
	MOVOU X1, X5
	PSHUFB X0, X5
	MOVOU X2, X6
	PSHUFB X4, X6
	PAND X6, X5
	PCMPEQB X8, X5
	PMOVMSKB X5, R11
	XORL $0xFFFF, R11
	TESTL R11, R11
	JNE found
	ADDQ $16, DI
	JMP loop

found:
	BSFL R11, R11
	ADDQ DI, R11
	MOVQ R11, ret+32(FP)
	RET

none:
	MOVQ $-1, R11
	MOVQ R11, ret+32(FP)
	RET

GLOBL mask0F16<>(SB), RODATA, $16
GLOBL mask0F32<>(SB), RODATA, $32

DATA mask0F16<>+0(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA mask0F16<>+8(SB)/8, $0x0F0F0F0F0F0F0F0F
GLOBL mask0F64<>(SB), RODATA, $64

DATA mask0F32<>+0(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA mask0F32<>+8(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA mask0F32<>+16(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA mask0F32<>+24(SB)/8, $0x0F0F0F0F0F0F0F0F

DATA mask0F64<>+0(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA mask0F64<>+8(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA mask0F64<>+16(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA mask0F64<>+24(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA mask0F64<>+32(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA mask0F64<>+40(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA mask0F64<>+48(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA mask0F64<>+56(SB)/8, $0x0F0F0F0F0F0F0F0F

// func indexFoldPairAVX2(s string, c0, c1 byte, from int) int
// Scans full 32-byte blocks for two consecutive bytes whose lowercased forms match c0 and c1. The
// caller passes already-lowercased ASCII letters. | 以 32 字节块扫描连续两个字节，其小写形式分别匹配
// c0 与 c1。调用方传入已小写的 ASCII 字母。
TEXT ·indexFoldPairAVX2(SB), NOSPLIT, $0-40
	MOVQ s_base+0(FP), AX
	MOVQ s_len+8(FP), BX
	MOVBLZX c0+16(FP), CX
	MOVBLZX c1+17(FP), DX
	MOVQ from+24(FP), DI
	VMOVD CX, X1
	VPBROADCASTB X1, Y1
	VMOVD DX, X2
	VPBROADCASTB X2, Y2
	VMOVDQU mask20_32<>(SB), Y3

loop:
	MOVQ BX, R9
	SUBQ DI, R9
	CMPQ R9, $33
	JL none
	LEAQ (AX)(DI*1), R10
	VMOVDQU (R10), Y0
	VMOVDQU 1(R10), Y4
	VPOR Y3, Y0, Y5
	VPOR Y3, Y4, Y6
	VPCMPEQB Y1, Y5, Y7
	VPCMPEQB Y2, Y6, Y8
	VPAND Y8, Y7, Y7
	VPMOVMSKB Y7, R11
	TESTL R11, R11
	JNE found
	ADDQ $32, DI
	JMP loop

found:
	BSFL R11, R11
	ADDQ DI, R11
	MOVQ R11, ret+32(FP)
	VZEROUPPER
	RET

none:
	MOVQ $-1, R11
	MOVQ R11, ret+32(FP)
	VZEROUPPER
	RET

// func indexFoldPairAVX512(s string, c0, c1 byte, from int) int
// Scans full 64-byte blocks for the folded pair with AVX-512BW. | 用 AVX-512BW 以 64 字节块扫描折叠
// 字节对。
TEXT ·indexFoldPairAVX512(SB), NOSPLIT, $0-40
	MOVQ s_base+0(FP), AX
	MOVQ s_len+8(FP), BX
	MOVBLZX c0+16(FP), CX
	MOVBLZX c1+17(FP), DX
	MOVQ from+24(FP), DI
	VMOVD CX, X1
	VPBROADCASTB X1, Z1
	VMOVD DX, X2
	VPBROADCASTB X2, Z2
	VMOVDQU64 mask20_64<>(SB), Z3

loop:
	MOVQ BX, R9
	SUBQ DI, R9
	CMPQ R9, $65
	JL none
	LEAQ (AX)(DI*1), R10
	VMOVDQU64 (R10), Z0
	VMOVDQU64 1(R10), Z4
	VPORQ Z3, Z0, Z5
	VPORQ Z3, Z4, Z6
	VPCMPEQB Z1, Z5, K1
	VPCMPEQB Z2, Z6, K2
	KANDQ K2, K1, K1
	KMOVQ K1, R11
	TESTQ R11, R11
	JNE found
	ADDQ $64, DI
	JMP loop

found:
	BSFQ R11, R11
	ADDQ DI, R11
	MOVQ R11, ret+32(FP)
	VZEROUPPER
	RET

none:
	MOVQ $-1, R11
	MOVQ R11, ret+32(FP)
	VZEROUPPER
	RET

// func indexFoldPairSSE41(s string, c0, c1 byte, from int) int
// Scans full 16-byte blocks for the folded pair with SSE4.1. | 用 SSE4.1 以 16 字节块扫描折叠字节对。
TEXT ·indexFoldPairSSE41(SB), NOSPLIT, $0-40
	MOVQ s_base+0(FP), AX
	MOVQ s_len+8(FP), BX
	MOVBLZX c0+16(FP), CX
	MOVBLZX c1+17(FP), DX
	MOVQ from+24(FP), DI
	MOVD CX, X1
	PUNPCKLBW X1, X1
	PUNPCKLWL X1, X1
	PSHUFD $0, X1, X1
	MOVD DX, X2
	PUNPCKLBW X2, X2
	PUNPCKLWL X2, X2
	PSHUFD $0, X2, X2
	MOVOU mask20_16<>(SB), X3

loop:
	MOVQ BX, R9
	SUBQ DI, R9
	CMPQ R9, $17
	JL none
	LEAQ (AX)(DI*1), R10
	MOVOU (R10), X0
	MOVOU 1(R10), X4
	POR X3, X0
	POR X3, X4
	PCMPEQB X1, X0
	PCMPEQB X2, X4
	PAND X4, X0
	PMOVMSKB X0, R11
	TESTL R11, R11
	JNE found
	ADDQ $16, DI
	JMP loop

found:
	BSFL R11, R11
	ADDQ DI, R11
	MOVQ R11, ret+32(FP)
	RET

none:
	MOVQ $-1, R11
	MOVQ R11, ret+32(FP)
	RET

// func indexByteSetSSE42(s string, t *[128]byte, from int) int
// SSE4.2 CPUs use the same 16-byte nibble-table kernel as SSE4.1. | SSE4.2 CPU 使用与 SSE4.1 相同的
// 16 字节半字节表内核。
TEXT ·indexByteSetSSE42(SB), NOSPLIT, $0-40
	JMP ·indexByteSetSSE41(SB)

// func indexFoldPairSSE42(s string, c0, c1 byte, from int) int
// SSE4.2 CPUs use the same 16-byte folded-pair kernel as SSE4.1. | SSE4.2 CPU 使用与 SSE4.1 相同的
// 16 字节折叠字节对内核对。
TEXT ·indexFoldPairSSE42(SB), NOSPLIT, $0-40
	JMP ·indexFoldPairSSE41(SB)

GLOBL mask20_16<>(SB), RODATA, $16
GLOBL mask20_32<>(SB), RODATA, $32

DATA mask20_16<>+0(SB)/8, $0x2020202020202020
DATA mask20_16<>+8(SB)/8, $0x2020202020202020
GLOBL mask20_64<>(SB), RODATA, $64

DATA mask20_32<>+0(SB)/8, $0x2020202020202020
DATA mask20_32<>+8(SB)/8, $0x2020202020202020
DATA mask20_32<>+16(SB)/8, $0x2020202020202020
DATA mask20_32<>+24(SB)/8, $0x2020202020202020

DATA mask20_64<>+0(SB)/8, $0x2020202020202020
DATA mask20_64<>+8(SB)/8, $0x2020202020202020
DATA mask20_64<>+16(SB)/8, $0x2020202020202020
DATA mask20_64<>+24(SB)/8, $0x2020202020202020
DATA mask20_64<>+32(SB)/8, $0x2020202020202020
DATA mask20_64<>+40(SB)/8, $0x2020202020202020
DATA mask20_64<>+48(SB)/8, $0x2020202020202020
DATA mask20_64<>+56(SB)/8, $0x2020202020202020
