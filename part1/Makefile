all: client test test.x

client: itrace.c 
	gcc -Wall -g -O2 itrace.c -o itrace -ludis86
test: test.asm
	nasm -f elf test.asm
test.x: test.o
	ld -o test.x test.o

clean:
	@/bin/rm -f *~ *.o *.x itrace 

