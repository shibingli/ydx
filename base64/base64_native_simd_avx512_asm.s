//go:build amd64 && !b64x_std

#include "textflag.h"

// func encodeAVX512VBMIAsm(dst, src []byte, c *vbmiEncConsts) int
// Encodes complete 48-byte blocks into 64 characters with AVX-512 VBMI and returns the input bytes
// consumed. | 用 AVX-512 VBMI 把完整 48 字节块编码为 64 个字符，返回消耗的输入字节数。
TEXT ·encodeAVX512VBMIAsm(SB), NOSPLIT, $0-64
	MOVQ dst_base+0(FP), AX
	MOVQ dst_len+8(FP), BX
	MOVQ src_base+24(FP), CX
	MOVQ src_len+32(FP), DI
	MOVQ c+48(FP), SI
	XORQ R8, R8
	XORQ R11, R11

	VMOVDQU64 0(SI), Z1
	VMOVDQU64 64(SI), Z2
	VMOVDQU64 128(SI), Z3
	VMOVDQU64 192(SI), Z4
	VMOVDQU64 256(SI), Z5
	VMOVDQU64 320(SI), Z6
	VMOVDQU64 384(SI), Z7
	VMOVDQU64 448(SI), Z8
	VMOVDQU64 512(SI), Z9

loop:
	MOVQ DI, R9
	SUBQ R8, R9
	CMPQ R9, $64
	JL done
	MOVQ BX, R9
	SUBQ R11, R9
	CMPQ R9, $64
	JL done

	LEAQ (CX)(R8*1), R10
	VMOVDQU64 (R10), Z0
	VPERMB Z0, Z1, Z0
	VPANDQ Z2, Z0, Z10
	VPMULHUW Z4, Z10, Z10
	VPANDQ Z3, Z0, Z0
	VPMULLW Z5, Z0, Z0
	VPORQ Z10, Z0, Z10
	VPSUBUSB Z7, Z10, Z11
	VPCMPGTB Z10, Z8, K2
	VMOVDQU8 Z9, K2, Z11
	VPERMB Z6, Z11, Z11
	VPADDB Z10, Z11, Z10
	LEAQ (AX)(R11*1), R10
	VMOVDQU64 Z10, (R10)

	ADDQ $48, R8
	ADDQ $64, R11
	JMP loop

done:
	VZEROUPPER
	MOVQ R8, ret+56(FP)
	RET

// func decodeAVX512VBMI2Asm(dst, src []byte, c *vbmiDecConsts) int
// Decodes complete 64-character blocks into 48 bytes with AVX-512 VBMI2 and returns the characters
// consumed. Invalid characters stop the loop so the scalar path can reject or finish the input. |
// 用 AVX-512 VBMI2 把完整 64 字符块解码为 48 字节，返回消耗的字符数。遇到非法字符时停止循环，
// 由标量路径报错或完成输入。
TEXT ·decodeAVX512VBMI2Asm(SB), NOSPLIT, $0-64
	MOVQ dst_base+0(FP), AX
	MOVQ dst_len+8(FP), BX
	MOVQ src_base+24(FP), CX
	MOVQ src_len+32(FP), DI
	MOVQ c+48(FP), SI
	XORQ R8, R8
	XORQ R11, R11

	MOVQ $0x0FFF0FFF0FFF0FFF, R12
	KMOVQ R12, K3

	VMOVDQU64 0(SI), Z1
	VMOVDQU64 64(SI), Z2
	VMOVDQU64 128(SI), Z3
	VMOVDQU64 192(SI), Z4
	VMOVDQU64 256(SI), Z5
	VMOVDQU64 320(SI), Z6
	VMOVDQU64 384(SI), Z7
	VMOVDQU64 448(SI), Z8
	VMOVDQU64 512(SI), Z9
	VMOVDQU64 576(SI), Z10
	VMOVDQU64 640(SI), Z11
	VMOVDQU64 704(SI), Z12

loop:
	MOVQ DI, R9
	SUBQ R8, R9
	CMPQ R9, $64
	JL done
	MOVQ BX, R9
	SUBQ R11, R9
	CMPQ R9, $48
	JL done

	LEAQ (CX)(R8*1), R10
	VMOVDQU64 (R10), Z0
	VPSRLW $4, Z0, Z13
	VPANDQ Z1, Z13, Z13
	VPANDQ Z2, Z0, Z14
	VPERMB Z3, Z14, Z15
	VPERMB Z4, Z13, Z16
	VPANDQ Z16, Z15, Z17
	VPTESTMQ Z17, Z17, K4
	KORTESTQ K4, K4
	JNZ done
	VPERMB Z5, Z13, Z18
	VPADDB Z0, Z18, Z18
	VPCMPEQB Z10, Z0, K1
	VMOVDQU8 Z8, K1, Z18
	VPCMPEQB Z11, Z0, K2
	VMOVDQU8 Z9, K2, Z18
	VPMADDUBSW Z6, Z18, Z18
	VPSLLD $12, Z18, Z19
	VPSRLD $16, Z18, Z18
	VPORD Z18, Z19, Z18
	VPERMB Z18, Z7, Z18
	LEAQ (AX)(R11*1), R10
	VPCOMPRESSB Z18, K3, (R10)

	ADDQ $64, R8
	ADDQ $48, R11
	JMP loop

done:
	VZEROUPPER
	MOVQ R8, ret+56(FP)
	RET

// func decodeAVX512BWAsm(dst, src []byte, c *bwDecConsts) int
// Decodes complete 64-character blocks into 48 bytes with lane-local AVX-512BW lookups and returns
// the characters consumed. Invalid characters stop the loop for the scalar path. |
// 用按 128 位通道局部的 AVX-512BW 查表把完整 64 字符块解码为 48 字节，返回消耗的字符数；遇到非法
// 字符时停止循环，交给标量路径。
TEXT ·decodeAVX512BWAsm(SB), NOSPLIT, $0-64
	MOVQ dst_base+0(FP), AX
	MOVQ dst_len+8(FP), BX
	MOVQ src_base+24(FP), CX
	MOVQ src_len+32(FP), DI
	MOVQ c+48(FP), SI
	XORQ R8, R8
	XORQ R11, R11

	MOVQ $0x0000FFFFFFFFFFFF, R12
	KMOVQ R12, K5

	VMOVDQU64 0(SI), Z1
	VMOVDQU64 64(SI), Z2
	VMOVDQU64 128(SI), Z3
	VMOVDQU64 192(SI), Z4
	VMOVDQU64 256(SI), Z5
	VMOVDQU64 320(SI), Z6
	VMOVDQU64 384(SI), Z7
	VMOVDQU64 448(SI), Z8
	VMOVDQU64 512(SI), Z9
	VMOVDQU64 576(SI), Z10

loop:
	MOVQ DI, R9
	SUBQ R8, R9
	CMPQ R9, $64
	JL done
	MOVQ BX, R9
	SUBQ R11, R9
	CMPQ R9, $48
	JL done

	LEAQ (CX)(R8*1), R10
	VMOVDQU64 (R10), Z0
	VPSRLW $4, Z0, Z11
	VPANDQ Z1, Z11, Z11
	VPANDQ Z2, Z0, Z12
	VPSHUFB Z12, Z3, Z13
	VPSHUFB Z11, Z4, Z14
	VPANDQ Z14, Z13, Z15
	VPTESTMQ Z15, Z15, K4
	KORTESTQ K4, K4
	JNZ done
	VPSHUFB Z11, Z5, Z16
	VPADDB Z0, Z16, Z16
	VPCMPEQB Z9, Z0, K1
	VMOVDQU8 Z10, K1, Z16
	VPMADDUBSW Z6, Z16, Z16
	VPSLLD $12, Z16, Z17
	VPSRLD $16, Z16, Z16
	VPORD Z16, Z17, Z16
	VPSHUFB Z7, Z16, Z16
	VPERMD Z16, Z8, Z16
	LEAQ (AX)(R11*1), R10
	VMOVDQU8 Z16, K5, (R10)

	ADDQ $64, R8
	ADDQ $48, R11
	JMP loop

done:
	VZEROUPPER
	MOVQ R8, ret+56(FP)
	RET

// func encodeAVX512BWAsm(dst, src []byte, c *bwEncConsts) int
// Encodes complete 48-byte blocks with baseline AVX-512BW (lane-local VPSHUFB) and returns the
// logical input bytes consumed; src includes the four-byte prefix before the first block. |
// 用基础 AVX-512BW（按 128 位通道局部的 VPSHUFB）编码完整 48 字节块，返回消耗的逻辑输入字节数；
// src 包含首块之前的四字节前缀。
TEXT ·encodeAVX512BWAsm(SB), NOSPLIT, $0-64
	MOVQ dst_base+0(FP), AX
	MOVQ dst_len+8(FP), BX
	MOVQ src_base+24(FP), CX
	MOVQ src_len+32(FP), DI
	MOVQ c+48(FP), SI
	XORQ R8, R8
	XORQ R11, R11

	VMOVDQU 0(SI), Y1
	VMOVDQU64 32(SI), Z2
	VMOVDQU64 96(SI), Z3
	VMOVDQU64 160(SI), Z4
	VMOVDQU64 224(SI), Z5
	VMOVDQU64 288(SI), Z6
	VMOVDQU64 352(SI), Z7
	VMOVDQU64 416(SI), Z8
	VMOVDQU64 480(SI), Z9

loop:
	MOVQ DI, R9
	SUBQ R8, R9
	CMPQ R9, $56
	JL done
	MOVQ BX, R9
	SUBQ R11, R9
	CMPQ R9, $64
	JL done

	LEAQ (CX)(R8*1), R10
	VMOVDQU (R10), Y0
	VPSHUFB Y1, Y0, Y0
	VMOVDQU 24(R10), Y10
	VPSHUFB Y1, Y10, Y10
	VINSERTI64X4 $1, Y10, Z0, Z0
	VPANDQ Z2, Z0, Z11
	VPMULHUW Z4, Z11, Z11
	VPANDQ Z3, Z0, Z0
	VPMULLW Z5, Z0, Z0
	VPORQ Z11, Z0, Z11
	VPSUBUSB Z7, Z11, Z12
	VPCMPGTB Z11, Z8, K1
	VMOVDQU8 Z9, K1, Z12
	VPSHUFB Z12, Z6, Z12
	VPADDB Z11, Z12, Z11
	LEAQ (AX)(R11*1), R10
	VMOVDQU64 Z11, (R10)

	ADDQ $48, R8
	ADDQ $64, R11
	JMP loop

done:
	VZEROUPPER
	MOVQ R8, ret+56(FP)
	RET
