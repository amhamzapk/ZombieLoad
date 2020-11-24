#include <stdio.h>
#include <memory.h>

void maccess(void *p) { asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax"); }

/* Alignment is done so that secret array can start at multiple of 4096
 * as page size
 */
char __attribute__((aligned(4096))) secret[8192];

int main(int argc, char* argv[]) {
  char key = 'X';
  printf("Secret memory address -> %p (Should be 4096 aligned)..\n\n", &secret[0]);
    
  if(argc >= 2) {
    key = argv[1][0];
  } 
  
  printf("Loading secret value '%c'...\n", key);
  
  memset(secret, key, 4096 * 2);
 
  // load value all the time
  while(1) {
	/*
	 * Since 64 is the line size, we are kicking
	 * updating previous line with newly secret
	 * value by loading the secret
	 */
    for(int i = 0; i < 100; i++) maccess(secret + i * 64);
  }
}
