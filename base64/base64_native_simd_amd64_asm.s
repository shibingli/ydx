//go:build amd64 && !b64x_std

#include "textflag.h"

// func encodeAVX2Asm(dst, src []byte, c *avx2EncConsts) int
TEXT ·encodeAVX2Asm(SB), NOSPLIT, $0-64
	MOVQ dst_base+0(FP), AX
	MOVQ dst_len+8(FP), BX
	MOVQ src_base+24(FP), CX
	MOVQ src_len+32(FP), DI
	MOVQ c+48(FP), SI
	XORQ R8, R8
	XORQ R11, R11

	// 128-bit head constants; VEX XMM writes clear the upper YMM halves, so the
	// 256-bit constants are loaded after the head. | 128 位头部常量；VEX XMM 写会清零
	// YMM 高半，因此在头部之后重新加载 256 位常量。
	VMOVDQU 32(SI), X1
	VMOVDQU 64(SI), X2
	VMOVDQU 96(SI), X3
	VMOVDQU 128(SI), X4
	VMOVDQU 160(SI), X0
	VMOVDQU 192(SI), X5
	VMOVDQU 224(SI), X6
	VMOVDQU 256(SI), X7
	VMOVDQU 16(SI), X8

	CMPQ DI, $16
	JL noHead
	CMPQ BX, $16
	JL noHead
	VMOVDQU (CX), X9
	VPSHUFB X8, X9, X9
	VPAND X1, X9, X10
	VPMULHUW X3, X10, X10
	VPAND X2, X9, X9
	VPMULLW X4, X9, X9
	VPOR X10, X9, X9
	VPSUBUSB X5, X9, X10
	VPCMPGTB X9, X6, X11
	VPBLENDVB X11, X7, X10, X10
	VPSHUFB X10, X0, X10
	VPADDB X10, X9, X9
	VMOVDQU X9, (AX)
	MOVQ $12, R8
	MOVQ $16, R11
noHead:
	VMOVDQU 32(SI), Y1
	VMOVDQU 64(SI), Y2
	VMOVDQU 96(SI), Y3
	VMOVDQU 128(SI), Y4
	VMOVDQU 160(SI), Y0
	VMOVDQU 192(SI), Y5
	VMOVDQU 224(SI), Y6
	VMOVDQU 256(SI), Y7
	VMOVDQU 0(SI), Y8

loop:
	MOVQ DI, R9
	SUBQ R8, R9
	CMPQ R9, $28
	JL done
	MOVQ BX, R9
	SUBQ R11, R9
	CMPQ R9, $32
	JL done

	LEAQ -4(CX)(R8*1), R10
	VMOVDQU (R10), Y9
	VPSHUFB Y8, Y9, Y9
	VPAND Y1, Y9, Y10
	VPMULHUW Y3, Y10, Y10
	VPAND Y2, Y9, Y9
	VPMULLW Y4, Y9, Y9
	VPOR Y10, Y9, Y9
	VPSUBUSB Y5, Y9, Y10
	VPCMPGTB Y9, Y6, Y11
	VPBLENDVB Y11, Y7, Y10, Y10
	VPSHUFB Y10, Y0, Y10
	VPADDB Y10, Y9, Y9
	LEAQ (AX)(R11*1), R10
	VMOVDQU Y9, (R10)

	ADDQ $24, R8
	ADDQ $32, R11
	JMP loop
done:
	MOVQ R8, ret+56(FP)
	RET

// func encode32SIMDAsm(dst, src []byte, mode uint64) (int, int)
// Encodes exactly 32 source bytes into 43 characters using two 12-byte heads and one eight-byte
// vector tail, without any scalar tail call, then appends padding when mode bit 1 is set. Mode bit
// 0 selects the URL alphabet and bits 8-15 hold the pad byte. It returns the consumed input and
// produced output, or two zeroes when the slices do not fit. | 用两个 12 字节头部与一个 8 字节
// 向量尾部把恰好 32 个源字节编码为 43 个字符，不调用标量尾部；mode 第 1 位置位时追加填充。
// mode 第 0 位选择 URL 字母表，第 8-15 位保存填充字节。返回消耗的输入与产生的输出；切片不满足
// 长度要求时返回两个 0。
TEXT ·encode32SIMDAsm(SB), NOSPLIT, $0-72
	MOVQ dst_base+0(FP), AX
	MOVQ dst_len+8(FP), BX
	MOVQ src_base+24(FP), CX
	MOVQ src_len+32(FP), DI
	MOVQ mode+48(FP), R12
	CMPQ DI, $32
	JNE len32Fail
	CMPQ BX, $43
	JL len32Fail
	TESTQ $1, R12
	JZ len32Std
	LEAQ ·avx2EncURL(SB), SI
	JMP len32Consts
len32Std:
	LEAQ ·avx2EncStd(SB), SI
len32Consts:

	VMOVDQU 32(SI), X1
	VMOVDQU 64(SI), X2
	VMOVDQU 96(SI), X3
	VMOVDQU 128(SI), X4
	VMOVDQU 160(SI), X0
	VMOVDQU 192(SI), X5
	VMOVDQU 224(SI), X6
	VMOVDQU 256(SI), X7
	VMOVDQU 16(SI), X8

	// First 12 bytes. | 前 12 字节。
	VMOVDQU (CX), X9
	VPSHUFB X8, X9, X9
	VPAND X1, X9, X10
	VPMULHUW X3, X10, X10
	VPAND X2, X9, X9
	VPMULLW X4, X9, X9
	VPOR X10, X9, X9
	VPSUBUSB X5, X9, X10
	VPCMPGTB X9, X6, X11
	VPBLENDVB X11, X7, X10, X10
	VPSHUFB X10, X0, X10
	VPADDB X10, X9, X9
	VMOVDQU X9, (AX)

	// Next 12 bytes. | 接下来 12 字节。
	VMOVDQU 12(CX), X9
	VPSHUFB X8, X9, X9
	VPAND X1, X9, X10
	VPMULHUW X3, X10, X10
	VPAND X2, X9, X9
	VPMULLW X4, X9, X9
	VPOR X10, X9, X9
	VPSUBUSB X5, X9, X10
	VPCMPGTB X9, X6, X11
	VPBLENDVB X11, X7, X10, X10
	VPSHUFB X10, X0, X10
	VPADDB X10, X9, X9
	VMOVDQU X9, 16(AX)

	// Last 8 bytes: select bytes 8..15 of the load at offset 16 and zero the rest, so the
	// head math produces two full groups followed by the two-byte remainder. | 最后 8 字节：
	// 取偏移 16 处加载的第 8..15 字节并将其余字节清零，使头部算法产生两个完整组和两字节余量。
	VMOVDQU 16(CX), X12
	VPSHUFB 288(SI), X12, X9
	VPSHUFB X8, X9, X9
	VPAND X1, X9, X10
	VPMULHUW X3, X10, X10
	VPAND X2, X9, X9
	VPMULLW X4, X9, X9
	VPOR X10, X9, X9
	VPSUBUSB X5, X9, X10
	VPCMPGTB X9, X6, X11
	VPBLENDVB X11, X7, X10, X10
	VPSHUFB X10, X0, X10
	VPADDB X10, X9, X9
	VMOVQ X9, 32(AX)
	VPEXTRW $4, X9, 40(AX)
	VPEXTRB $10, X9, 42(AX)
	MOVQ $43, R13
	TESTQ $2, R12
	JZ len32Store
	MOVQ R12, R14
	SHRQ $8, R14
	MOVB R14, 43(AX)
	MOVQ $44, R13
len32Store:
	MOVQ $32, ret+56(FP)
	MOVQ R13, ret1+64(FP)
	RET
len32Fail:
	XORQ R9, R9
	MOVQ R9, ret+56(FP)
	MOVQ R9, ret1+64(FP)
	RET

// func decodeAVX2Asm(dst, src []byte, c *avx2DecConsts) int
TEXT ·decodeAVX2Asm(SB), NOSPLIT, $0-64
	MOVQ dst_base+0(FP), AX
	MOVQ dst_len+8(FP), BX
	MOVQ src_base+24(FP), CX
	MOVQ src_len+32(FP), DI
	MOVQ c+48(FP), SI
	XORQ R8, R8
	XORQ R11, R11

	VMOVDQU 0(SI), Y3
	VMOVDQU 32(SI), Y4
	VMOVDQU 64(SI), Y5
	VMOVDQU 96(SI), Y6
	VMOVDQU 160(SI), Y8
	VMOVDQU 192(SI), Y9
	VMOVDQU 224(SI), Y10
	VMOVDQU 256(SI), Y0
	VMOVDQU 288(SI), Y1
	VPXOR Y2, Y2, Y2

decLoop:
	MOVQ DI, R9
	SUBQ R8, R9
	CMPQ R9, $32
	JL decDone
	MOVQ BX, R9
	SUBQ R11, R9
	CMPQ R9, $24
	JL decDone

	LEAQ (CX)(R8*1), R10
	VMOVDQU (R10), Y11
	VPSRLW $4, Y11, Y12
	VPAND Y6, Y12, Y12
	VPAND Y6, Y11, Y13
	VPSHUFB Y13, Y3, Y13
	VPSHUFB Y12, Y4, Y14
	VPAND Y14, Y13, Y13
	VPCMPEQB Y2, Y13, Y13
	VPMOVMSKB Y13, R15
	CMPL R15, $-1
	JNE decDone
	VPSHUFB Y12, Y5, Y12
	VPADDB Y12, Y11, Y12
	VPCMPEQB Y0, Y11, Y11
	VPBLENDVB Y11, Y1, Y12, Y11
	VPMADDUBSW Y8, Y11, Y11
	VPSLLD $12, Y11, Y12
	VPSRLD $16, Y11, Y11
	VPOR Y11, Y12, Y11
	VPSHUFB Y9, Y11, Y11
	VPERMD Y11, Y10, Y11
	LEAQ (AX)(R11*1), R10
	VMOVDQU X11, (R10)
	VEXTRACTI128 $1, Y11, X12
	VMOVQ X12, 16(R10)

	ADDQ $32, R8
	ADDQ $24, R11
	JMP decLoop
decDone:
	MOVQ R8, ret+56(FP)
	RET

// func decode32SIMDAsm(dst, src []byte, mode uint64) (int, int)
// Decodes exactly 32 valid characters into 24 bytes with one AVX2 block. Mode bit 0 selects the
// URL alphabet. It returns (32, 24) on success, and (0, 0) when a character is invalid so the
// scalar path can report or finish the input. | 用一个 AVX2 块把恰好 32 个合法字符解码为 24 字节。
// mode 第 0 位选择 URL 字母表。成功返回 (32, 24)；遇到非法字符返回 (0, 0)，由标量路径报错或
// 完成输入。
TEXT ·decode32SIMDAsm(SB), NOSPLIT, $0-72
	MOVQ dst_base+0(FP), AX
	MOVQ dst_len+8(FP), BX
	MOVQ src_base+24(FP), CX
	MOVQ src_len+32(FP), DI
	MOVQ mode+48(FP), R12
	CMPQ DI, $32
	JNE decode32Fail
	CMPQ BX, $24
	JL decode32Fail
	TESTQ $1, R12
	JZ decode32Std
	LEAQ ·avx2DecURL(SB), SI
	JMP decode32Consts
decode32Std:
	LEAQ ·avx2DecStd(SB), SI
decode32Consts:
	VMOVDQU 0(SI), Y3
	VMOVDQU 32(SI), Y4
	VMOVDQU 64(SI), Y5
	VMOVDQU 96(SI), Y6
	VMOVDQU 160(SI), Y8
	VMOVDQU 192(SI), Y9
	VMOVDQU 224(SI), Y10
	VMOVDQU 256(SI), Y0
	VMOVDQU 288(SI), Y1
	VPXOR Y2, Y2, Y2

	VMOVDQU (CX), Y11
	VPSRLW $4, Y11, Y12
	VPAND Y6, Y12, Y12
	VPAND Y6, Y11, Y13
	VPSHUFB Y13, Y3, Y13
	VPSHUFB Y12, Y4, Y14
	VPAND Y14, Y13, Y13
	VPCMPEQB Y2, Y13, Y13
	VPMOVMSKB Y13, R15
	CMPL R15, $-1
	JNE decode32Fail
	VPSHUFB Y12, Y5, Y12
	VPADDB Y12, Y11, Y12
	VPCMPEQB Y0, Y11, Y11
	VPBLENDVB Y11, Y1, Y12, Y11
	VPMADDUBSW Y8, Y11, Y11
	VPSLLD $12, Y11, Y12
	VPSRLD $16, Y11, Y11
	VPOR Y11, Y12, Y11
	VPSHUFB Y9, Y11, Y11
	VPERMD Y11, Y10, Y11
	VMOVDQU X11, (AX)
	VEXTRACTI128 $1, Y11, X12
	VMOVQ X12, 16(AX)

	MOVQ $32, ret+56(FP)
	MOVQ $24, ret1+64(FP)
	RET
decode32Fail:
	XORQ R9, R9
	MOVQ R9, ret+56(FP)
	MOVQ R9, ret1+64(FP)
	RET

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
