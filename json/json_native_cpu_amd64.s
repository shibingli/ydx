//go:build amd64 && !jsonx_std

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
