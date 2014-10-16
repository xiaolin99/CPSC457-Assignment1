section .text
global _start
_start:
loop_start:
	xor eax, eax
	xor ebx, ebx
	inc ebx
	inc eax
	nop
	nop
	add eax, 0x10
	sub eax, 0x10
	imul eax, ebx, 0x11223344
	neg ebx
	jmp loop_start 
