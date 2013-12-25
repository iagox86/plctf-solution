all: sploit

shellcode: shellcode.asm
	nasm shellcode.asm

sploit: sploit.c shellcode
	gcc -Wall -Werror -o sploit sploit.c

clean:
	rm sploit shellcode
