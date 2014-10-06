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

// some offsets in ELF
#define L_ENDIAN 0x01 // LSB to the right
#define B_ENDIAN 0x10 // LSB to the left
#define LOC_ENDIAN 0x5 // Endianness 1 byte
#define LOC_ENTRY 0x18 // Execution entry 4 bytes (mem location for _start)
#define LEN_LOC_ENTRY 4
#define LOC_PH 0x1C // Program header start 4 bytes
#define LEN_LOC_PH 4
#define LOC_SH 0x20 // Section header start 4 bytes
#define LEN_LOC_SH 4
#define SIZE_PH 0x2A // Program header size 2 bytes
#define LEN_SIZE_PH 2
#define NUM_PH 0x2C // num entries in Program header 2 bytes
#define LEN_NUM_PH 2
#define SIZE_SH 0x2E // Section header size 2 bytes
#define LEN_SIZE_SH 2
#define NUM_SH 0x30 // num entries in Section header 2 bytes
#define LEN_NUM_SH 2
#define IDX_SNAME 0x32 // index of section header entry that contain section names 2 bytes 
#define LEN_IDX_SNAME 2



int main(int argc, char* argv[])
{
  FILE *target;
  target = fopen(argv[1], "a+");
  if (!target) {
    printf("unable to open file");
    return 1;
  }
  long buff = 0;
  unsigned long location = 0;
  unsigned long target_size = 0; 
  fseek (target , 0 , SEEK_END);
  target_size = ftell (target);
  rewind (target);
  
  int i;
  for (i = 0; i*4 < target_size; i ++) {
    location = ftell(target);
    printf("%08lx: ", location);
    buff = 0;
    fread(&buff, 1, 4, target);
    printf("%08lx  ", buff);
    int k;
    unsigned char *str = (unsigned char*)&buff;
    for (k = 0; k < 4; k ++) {
      if(str[k] < 32 || str[k] > 0x7e) str[k] = 0x2e;
    }
    str[4] = '\0';
    
    printf("%s\n", str); 
  }
  printf("target size: %ld Bytes\n", target_size);

  buff = 0;
  fseek(target, LOC_ENTRY, 0);
  fread(&buff, 1, LEN_LOC_ENTRY, target);
  printf("ENTRY = %08lx\n", buff);

  buff = 0;
  fseek(target, LOC_PH, 0);
  fread(&buff, 1, LEN_LOC_PH, target);
  printf("PH offset = %08lx\n", buff);


  unsigned long ph = buff;


  buff = 0;
  fseek(target, SIZE_PH, 0);
  fread(&buff, 1, LEN_SIZE_PH, target);
  printf("PH entry size = %08lx\n", buff);
  


  buff = 0;
  fseek(target, NUM_PH, 0);
  fread(&buff, 1, LEN_NUM_PH, target);
  printf("PH num entries = %08lx\n", buff);
  unsigned long ph_num = buff;

  int n;
  for (n = 0; n < ph_num; n ++) {
    ph = ph + n * 0x20;
    printf("Section %d:\n", n+1);
    fseek(target, ph+4, 0);
    fread(&buff, 1, 4, target);
    printf(" offset = %lx ", buff);
    fseek(target, ph+8, 0);
    fread(&buff, 1, 4, target);
    printf(" v_addr = %lx ", buff);
    fseek(target, ph+12, 0);
    fread(&buff, 1, 4, target);
    printf(" p_addr = %lx ", buff);
    fseek(target, ph+16, 0);
    fread(&buff, 1, 4, target);
    printf(" file_size = %lx ", buff);
    fseek(target, ph+20, 0);
    fread(&buff, 1, 4, target);
    printf(" mem_size = %lx\n", buff);

    
    
  } 

  buff = 0;
  fseek(target, LOC_SH, 0);
  fread(&buff, 1, LEN_LOC_SH, target);
  printf("SH offset = %08lx\n", buff);
  fseek(target, buff, 0);
  
  buff = 0;
  fseek(target, SIZE_SH, 0);
  fread(&buff, 1, LEN_SIZE_SH, target);
  printf("SH entry size = %08lx\n", buff);
  fseek(target, buff, 0);
 
  buff = 0;
  fseek(target, NUM_SH, 0);
  fread(&buff, 1, LEN_NUM_SH, target);
  printf("SH num entries = %08lx\n", buff);
  fseek(target, buff, 0);

  buff = 0;
  fseek(target, IDX_SNAME, 0);
  fread(&buff, 1, LEN_IDX_SNAME, target);
  printf("Index of SH name = %08lx\n", buff);

  fclose(target);

  return 0;
}
