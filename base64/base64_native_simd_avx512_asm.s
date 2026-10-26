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

	MOVQ DI, R9
	SUBQ $64, R9
	CMPQ R8, R9
	JG done
loop:
	// Encode has already checked len(dst) >= EncodedLen(len(src)); the loop
	// therefore never runs past the destination. | Encode 已检查
	// len(dst) >= EncodedLen(len(src))，循环不会写越目标。

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
	// The LUT repeats every 16 bytes and the indices are 0..13, so the
	// lane-local shuffle equals the cross-lane lookup but avoids VPERMB. |
	// LUT 每 16 字节重复，索引为 0..13，通道局部 shuffle 与跨通道查表等价，
	// 但避免使用 VPERMB。
	VPSHUFB Z11, Z6, Z11
	VPADDB Z10, Z11, Z10
	LEAQ (AX)(R11*1), R10
	VMOVDQU64 Z10, (R10)

	ADDQ $48, R8
	ADDQ $64, R11
	CMPQ R8, R9
	JLE loop

done:
	MOVQ DI, R14
	SUBQ R8, R14
	CMPQ R14, $48
	JL tailSmall

	// One 48-byte masked block covers the 48..63-byte remainder without reading
	// past src. | 一个 48 字节掩码块处理 48..63 字节余量，且不会读过 src。
	MOVQ $0x0000FFFFFFFFFFFF, R12
	KMOVQ R12, K1
	VPXORQ Z0, Z0, Z0
	LEAQ (CX)(R8*1), R10
	VMOVDQU8 (R10), K1, Z0
	VPERMB Z0, Z1, Z0
	VPANDQ Z2, Z0, Z10
	VPMULHUW Z4, Z10, Z10
	VPANDQ Z3, Z0, Z0
	VPMULLW Z5, Z0, Z0
	VPORQ Z10, Z0, Z10
	VPSUBUSB Z7, Z10, Z11
	VPCMPGTB Z10, Z8, K2
	VMOVDQU8 Z9, K2, Z11
	VPSHUFB Z11, Z6, Z11
	VPADDB Z10, Z11, Z10
	LEAQ (AX)(R11*1), R10
	VMOVDQU64 Z10, (R10)
	ADDQ $48, R8
	ADDQ $64, R11
	SUBQ $48, R14

tailSmall:
	CMPQ R14, $0
	JE tailDone
	// tailMask[rem] selects the remaining input bytes; tailStore[rem] selects
	// exactly RawEncodedLen(rem) output characters. Padding is written by the
	// Go wrapper. | tailMask[rem] 选择剩余输入字节；tailStore[rem] 选择恰好
	// RawEncodedLen(rem) 个输出字符；填充由 Go 包装层写入。
	LEAQ 576(SI), R15
	MOVQ (R15)(R14*8), R12
	KMOVQ R12, K1
	VPXORQ Z0, Z0, Z0
	LEAQ (CX)(R8*1), R10
	VMOVDQU8 (R10), K1, Z0
	VPERMB Z0, Z1, Z0
	VPANDQ Z2, Z0, Z10
	VPMULHUW Z4, Z10, Z10
	VPANDQ Z3, Z0, Z0
	VPMULLW Z5, Z0, Z0
	VPORQ Z10, Z0, Z10
	VPSUBUSB Z7, Z10, Z11
	VPCMPGTB Z10, Z8, K2
	VMOVDQU8 Z9, K2, Z11
	VPSHUFB Z11, Z6, Z11
	VPADDB Z10, Z11, Z10
	LEAQ 1088(SI), R15
	MOVQ (R15)(R14*8), R12
	KMOVQ R12, K3
	LEAQ (AX)(R11*1), R10
	VMOVDQU8 Z10, K3, (R10)
	ADDQ R14, R8

tailDone:
	VZEROUPPER
	MOVQ R8, ret+56(FP)
	RET

// func decodeAVX512BWAsm(dst, src []byte, c *bwDecConsts) int
// Decodes complete 64-character blocks plus a masked 4..63-character tail into 48 bytes with
// lane-local AVX-512BW lookups and returns the characters consumed. Invalid characters stop the
// kernel for the scalar path. | 用按 128 位通道局部的 AVX-512BW 查表把完整 64 字符块和 4..63
// 字符的掩码尾解码为 48 字节，返回消耗的字符数；遇到非法字符时停止内核，交给标量路径。
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

	MOVQ DI, R9
	SUBQ $64, R9
	CMPQ R8, R9
	JG decodeTail
loop:
	// Decode has already checked len(dst) >= DecodedLen(len(src)); the loop
	// therefore never runs past the destination. | Decode 已检查
	// len(dst) >= DecodedLen(len(src))，循环不会写越目标。

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
	JNZ decodeDone
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
	CMPQ R8, R9
	JLE loop

decodeTail:
	// The Go wrapper passes a length that is a multiple of four and excludes
	// the padding group, so the remainder is 0 or 4..63 characters. A masked
	// load zeroes the bytes past the remainder; VPMOVM2B turns the same mask
	// into a byte mask that removes those zero bytes from the validity test.
	// | Go 包装层传入的长度是 4 的倍数并排除了填充组，因此余量为 0 或 4..63
	// 字符。掩码加载把余量之后的字节清零；VPMOVM2B 把同一掩码转成字节掩码，
	// 在合法性检查中排除这些零字节。
	MOVQ DI, R14
	SUBQ R8, R14
	CMPQ R14, $4
	JL decodeDone
	LEAQ 640(SI), R15
	MOVQ (R15)(R14*8), R12
	KMOVQ R12, K1
	VPMOVM2B K1, Z20
	VPXORQ Z0, Z0, Z0
	LEAQ (CX)(R8*1), R10
	VMOVDQU8 (R10), K1, Z0
	VPSRLW $4, Z0, Z11
	VPANDQ Z1, Z11, Z11
	VPANDQ Z2, Z0, Z12
	VPSHUFB Z12, Z3, Z13
	VPSHUFB Z11, Z4, Z14
	VPANDQ Z14, Z13, Z15
	VPANDQ Z20, Z15, Z15
	VPTESTMQ Z15, Z15, K4
	KORTESTQ K4, K4
	JNZ decodeDone
	VPSHUFB Z11, Z5, Z16
	VPADDB Z0, Z16, Z16
	VPCMPEQB Z9, Z0, K2
	VMOVDQU8 Z10, K2, Z16
	VPMADDUBSW Z6, Z16, Z16
	VPSLLD $12, Z16, Z17
	VPSRLD $16, Z16, Z16
	VPORD Z16, Z17, Z16
	VPSHUFB Z7, Z16, Z16
	VPERMD Z16, Z8, Z16
	// Store exactly 3*(rem/4) decoded bytes.
	LEAQ 1152(SI), R15
	MOVQ (R15)(R14*8), R12
	KMOVQ R12, K5
	LEAQ (AX)(R11*1), R10
	VMOVDQU8 Z16, K5, (R10)
	ADDQ R14, R8

decodeDone:
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

	MOVQ DI, R9
	SUBQ $56, R9
	CMPQ R8, R9
	JG done
loop:
	// Encode has already checked len(dst) >= EncodedLen(len(src)); the loop
	// therefore never runs past the destination. | Encode 已检查
	// len(dst) >= EncodedLen(len(src))，循环不会写越目标。

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
	CMPQ R8, R9
	JLE loop

done:
	VZEROUPPER
	MOVQ R8, ret+56(FP)
	RET
