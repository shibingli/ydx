//go:build linux && rdma && amd64

#include "textflag.h"

// func callFn(fn, a1, a2, a3 uintptr) uintptr
//
// The System V AMD64 ABI passes the first three integer arguments in DI, SI
// and DX, and requires SP to be 0 mod 16 immediately before CALL (8 mod 16 at
// the C entry). Go ABI0 only guarantees 8-byte stack alignment, so align SP
// dynamically and restore it afterwards. | System V AMD64 ABI 用 DI、SI、DX
// 传递前三个整数参数，并要求 CALL 前 SP 为 16 字节对齐（C 函数入口为 8 mod
// 16）。Go ABI0 仅保证 8 字节对齐，因此动态对齐 SP 并在返回后恢复。
TEXT ·callFn(SB), NOSPLIT, $0-40
	MOVQ fn+0(FP), AX
	MOVQ a1+8(FP), DI
	MOVQ a2+16(FP), SI
	MOVQ a3+24(FP), DX
	MOVQ SP, R10
	TESTQ $15, SP
	JZ callfn_aligned
	SUBQ $8, SP
callfn_aligned:
	SUBQ $16, SP
	MOVQ R10, 0(SP)
	CALL AX
	MOVQ 0(SP), R10
	MOVQ R10, SP
	MOVQ AX, ret+32(FP)
	RET
