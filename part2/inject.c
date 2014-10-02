#include <stdio.h>
#include <stdlib.h>
#include <string.h> //memset, strncmp, strsignal
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <asm/ptrace-abi.h>
#include <asm/ptrace.h>
#include <udis86.h>

#define L_ENDIAN 0x01 // LSB to the right
#define B_ENDIAN 0x10 // LSB to the left
#define LOC_ENDIAN 0x5 // Endianness 1 byte
#define LOC_PH 0x1C // Program header start 4 bytes
#define LOC_SH 0x20 // Section header start 4 bytes
#define SIZE_PH 0x2A // Program header size 2 bytes
#define SIZE_SH 0x2E // Section header size 2 bytes
#define NUM_PH 0x2C // num entries in Program header 2 bytes
#define NUM_SH 0x30 // num entries in Section header 2 bytes
#define IDX_SNAME 0x32 // index of section header entry that contain section names 2 bytes 



int main(int argc, char* argv[])
{
  FILE *target;
  target = fopen("./a.out", "a+");
  if (!target) {
    printf("unable to open file");
    return 1;
  }
  unsigned char buff;
  unsigned long location = 0;
  unsigned long target_size = 0; 
  fseek (target , 0 , SEEK_END);
  target_size = ftell (target);
  rewind (target);
  printf("target size: %ld Bytes\n", target_size);
  int i;
  for (i = 0; i < target_size; i ++) {
    location = ftell(target);
    printf("%08lx: ", location);
    fread(&buff, 1, 1, target);
    printf("%02x\n", (unsigned int)buff);
  }

  fclose(target);

  return 0;
}
