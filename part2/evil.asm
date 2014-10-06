section .data
evil1 db "I'm evil "
evil2 db "ha ha "

section .text
global _evil

_evil:
mov eax, 4
mov ebx, 1
mov ecx, evil1
mov edx, 9 
int 0x80

mov eax, 4
mov ebx, 1
mov ecx, evil2
mov edx, 6
int 0x80
jmp _start

global _start
_start:
