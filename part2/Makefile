all: inject evil

inject: inject.c
	gcc -Wall -g -O2 inject.c -o inject

evil: evil.asm
	nasm -f elf evil.asm
	ld -o evil.dat evil.o

clean:
	rm -rf inject
