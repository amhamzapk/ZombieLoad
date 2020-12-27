#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <cpuid.h>

#include <memory.h>
#include <sys/mman.h>
#include <immintrin.h>

#define LOAD_WHILE_THRESH      101
#define LOAD_VULNERABLE_THRESH 180
#define LOAD_DETECT_THRESH     20

#define LIMIT_L1 64

void mfence() { asm volatile("mfence"); }
/*
 * NORMAL FLAG MUST BE ON FOR NORMAL MITIAGATE TO WORK
 */
//#define NORMAL
//#define NORMAL_MITIGATE // NORMAL FLAG MUST BE ON FOR THIS TO WORK

/*
 * NORMAL FLAG MUST BE OFF FOR FOLLOWING TO WORK
 * ONLY ONE CAN BE ENABLED AT A TIME
 */
//#define ABORT_DETECTOR
//#define LOAD_DETECTOR
//#define FLUSH_DETECTOR
//#define FLUSH_DETECTOR_NEW
#define NEW_DETECTOR
// ---------------------------------------------------------------------------
unsigned int xbegin() {
  unsigned status;
  asm volatile(".byte 0xc7,0xf8,0x00,0x00,0x00,0x00" : "=a"(status) : "a"(-1UL) : "memory");
  return status;
}
//#include <time.h>

void maccess(void *p) { asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax"); }
// ---------------------------------------------------------------------------
void flush(void *p) { asm volatile("clflush 0(%0)\n" : : "c"(p) : "rax"); }
#include <sched.h>

/* Alignment is done so that secret array can start at multiple of 4096
 * as page size
 */

#define NUM_WAYS  8
#define NUM_SETS  64
#define LINE_SIZE 64
char __attribute__((aligned(4096))) secret[8192];
char __attribute__((aligned(4096))) mem[256 * 4096];
char __attribute__((aligned(4096))) mapping[4096];
char __attribute__((aligned(4096))) mapping_cache_line_set [8] [64 * 64];
char __attribute__((aligned(4096))) mapping_cache_line [64 * 64];
char __attribute__((aligned(4096))) mapping_cache_line2[64 * 64];
char __attribute__((aligned(4096))) mapping_cache_line3[64 * 64];
char __attribute__((aligned(4096))) mapping_cache_line4[64 * 64];
char __attribute__((aligned(4096))) mapping_cache_line5[64 * 64];
char __attribute__((aligned(4096))) mapping_cache_line6[64 * 64];
char __attribute__((aligned(4096))) mapping_cache_line7[64 * 64];
char __attribute__((aligned(4096))) mapping_cache_line8[64 * 64];
char __attribute__((aligned(64)))   mappingl1[1024*32];
long long temp_cnter = 0;
long long another_cnter = 0;
volatile bool abort_flag = 0;
volatile long long aborted = 0;
volatile long long not_aborted = 0;
volatile long long aborted_overall = 0;
volatile long long not_aborted_overall = 0;
volatile long long aborted_arr[LIMIT_L1] = {0};
volatile long long not_aborted_arr[LIMIT_L1] = {0};
volatile int abort_reason[7] = {0};
volatile int abort_reason_l1[64][7] = {0};
long long line_cnter = 0;
int random_cnter = 0;
int taa_cnter = 0;
int no_issue_cnter = 0;
int flush_cnter = 0;
int main(int argc, char* argv[]) {
	  char key = 'X';
	  printf("Secret memory address -> %p (Should be 4096 aligned)..\n\n", &secret[0]);

	  if(argc >= 2) {
	    key = argv[1][0];
	  }

	  printf("Loading secret value '%c'...\n", key);

	  memset(secret, key, 4096 * 2);
  	volatile short ds = 8;
#ifdef NORMAL

	  // load value all the time
	  while(1) {
		/*
		 * Since 64 is the line size, we are kicking
		 * updating previous line with newly secret
		 * value by loading the secret
		 */
//	    for(int i = 0; i < 100; i++)
	    {
	    	int i=0;
#ifndef NORMAL_MITIGATE
	    	maccess(secret + i * 64);
#else
#if 1
	    	maccess(secret + i * 64);
			asm volatile("verw %[ds];" : : [ds] "m" (ds) : "cc");
#else
		    __asm__ __volatile__ (
		    		 	 	 	  "movq (%0), %%rax;"
					  	  	  	  "movq (%%rdi), %%rax;"
								  "verw %[ds];"
		    					  : : "r" (secret + i * 64), [ds] "m" (ds) : "rax"
		    );
#endif


#endif
	    }
	  }
#else
  memset(secret, key, 4096 * 2);
  /* Initialize and flush LUT */
  memset(mem, 0, sizeof(mem));

  for (size_t i = 0; i < 256; i++) {
    flush(mem + i * 4096);
  }
	//
	//  flush(mapping);
	  /* Initialize mapping */
	  memset(mapping, 0, sizeof(mapping));
	  memset(mapping_cache_line, 0, sizeof(mapping_cache_line));
	  memset(mapping_cache_line2, 0, sizeof(mapping_cache_line2));
	  memset(mapping_cache_line3, 0, sizeof(mapping_cache_line3));
	  memset(mapping_cache_line4, 0, sizeof(mapping_cache_line4));
	  memset(mapping_cache_line5, 0, sizeof(mapping_cache_line5));
	  memset(mapping_cache_line6, 0, sizeof(mapping_cache_line6));
	  memset(mapping_cache_line7, 0, sizeof(mapping_cache_line7));
	  memset(mapping_cache_line8, 0, sizeof(mapping_cache_line8));
	  // load value all the time


	  while(1) {
		/*
		 * Since 64 is the line size, we are kicking
		 * updating previous line with newly secret
		 * value by loading the secret
	 */
#ifdef LOAD_DETECTOR

	    __asm__ __volatile__ (
	    		 	 	 	  "movq %3, %%rdi;"				// Move mapping (leak source) to "rdi"
	    					  "clflush (%%rdi);"
							  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
	    					  "xbegin 2f;"				// Start TSX Transaction
	    					  "movq (%%rdi), %%rax;"		// Leak a single byte from mapping (leak source) and speculatively load in rax register
	    					  "xend;"						// End TSX Transaction

							  "movq %0, %%rcx;"
	  	  	  	  	  	  	  "incq %%rcx;"
							  "movq %%rcx, %0;"
	  	  	  	  	  	  	  "jmp 3f;"
							  "2:;"						//
							  "movq %1, %%rdx;"
				  	  	  	  "incq %%rdx;"
							  "movq %%rdx, %1;"
				  	  	  	  "3:;"
	    					  : "=g"(not_aborted), "=g"(aborted) : "r" (secret), "r" (mapping), [ds] "m" (ds), "r"(aborted), "r"(not_aborted) : "rcx", "rdx", "rdi", "rax"
	    );
#endif

#ifdef ABORT_DETECTOR

	    __asm__ __volatile__ (
	    		 	 	 	  "movq %3, %%rdi;"				// Move mapping (leak source) to "rdi"
//	    					  "verw %[ds];"
//	    					  "clflush (%%rdi);"
								  "mov (%%rdi), %%rax;"
	    					  "mfence;"
//	    					  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//				  	  	  	  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//							  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//							  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//							  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//							  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//							  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//							  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//							  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//							  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
	    					  "xbegin 2f;"				// Start TSX Transaction
	    					  "movq (%%rdi), %%rax;"		// Leak a single byte from mapping (leak source) and speculatively load in rax register
	    					  "xend;"						// End TSX Transaction

							  "movq %0, %%rcx;"
	  	  	  	  	  	  	  "incq %%rcx;"
							  "movq %%rcx, %0;"
	  	  	  	  	  	  	  "jmp 3f;"
							  "2:;"						//
							  "movq %1, %%rdx;"
				  	  	  	  "incq %%rdx;"
							  "movq %%rdx, %1;"
				  	  	  	  "3:;"
	    					  : "=g"(not_aborted), "=g"(aborted) : "r" (secret), "r" (mapping), [ds] "m" (ds), "r"(aborted), "r"(not_aborted) : "rcx", "rdx", "rdi", "rax"
	    );
#endif


//	    printf("\n\nmapping_cache_line=%p\n", 	mapping_cache_line);
//	    printf("mapping_cache_line2=%p\n", 		mapping_cache_line2);
//	    printf("mapping_cache_line3=%p\n",      mapping_cache_line3);
//	    printf("mapping_cache_line4=%p\n",      mapping_cache_line4);
//	    printf("mapping_cache_line5=%p\n",      mapping_cache_line5);
//	    printf("mapping_cache_line6=%p\n",      mapping_cache_line6);
//	    printf("mapping_cache_line7=%p\n",      mapping_cache_line7);
//	    printf("mapping_cache_line8=%p\n",      mapping_cache_line8);
//    	maccess(mapping_cache_line + (l1 * 64));
//	    mfence();
//	    maccess(mapping_cache_line2 + (l1 * 64));
//	    mfence();
//	    maccess(mapping_cache_line3 + (l1 * 64));
//	    mfence();
//	    maccess(mapping_cache_line4 + (l1 * 64));
//	    mfence();
//	    maccess(mapping_cache_line5 + (l1 * 64));
//	    mfence();
//	    maccess(mapping_cache_line6 + (l1 * 64));
//	    mfence();
//	    maccess(mapping_cache_line7 + (l1 * 64));
//	    mfence();
//	    maccess(mapping_cache_line8 + (l1 * 64));
//	    mfence();
//	    while (1);
#ifdef NEW_DETECTOR

//	    volatile int local_abort_reason = -1;
//	    __asm__ __volatile__ (
//	    		 	 	 	  "movq %4, %%rdi;"				// Move mapping (leak source) to "rdi"
////	    					  "verw %[ds];"
////	    					  "clflush (%%rdi);"
////							  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
////							  "mov (%%rdi), %%rax;"
////	    					  "mfence;"
//	    					  "xbegin 2f;"				// Start TSX Transaction
////				  "clflush (%%rdi);"
////	    		"mfence;"
//	    					  "movq (%%rdi), %%rax;"		// Leak a single byte from mapping (leak source) and speculatively load in rax register
//	    					  "xend;"						// End TSX Transaction
//							  "movq %1, %%rcx;"
//	  	  	  	  	  	  	  "incq %%rcx;"
//							  "movq %%rcx, %1;"
//	  	  	  	  	  	  	  "jmp 3f;"
//							  "2:;"						//ABORTED
////	    					  "movq $1, %%rax;"
//				  	  	  	  "mov %%eax, %0;"
//							  "movq %2, %%rdx;"
//				  	  	  	  "incq %%rdx;"
//							  "movq %%rdx, %2;"
//				  	  	  	  "3:;"
//	    					  : "=g" (local_abort_reason), "=g"(not_aborted), "=g"(aborted) : "r" (secret), "r" (mapping), [ds] "m" (ds), "r"(aborted), "r"(not_aborted) : "rcx", "rdx", "rdi", "rax"
//	    );
//	    if (local_abort_reason > -1) {
//	    	if (local_abort_reason == 0) {
//	    		abort_reason[6]++;
//
//	    	} else {
//		    	for (int i=0; i<6; i++) {
//		    		if (local_abort_reason & (1<<i)) {
//		    			abort_reason[i]++;
//		    		}
//		    	}
//	    	}
////	    	abort_reason[local_abort_reason]++;
//	    }


	    for (int l1=0; l1<64; l1++) {

    	    volatile int local_abort_reason = 0;
			maccess(mapping_cache_line + (l1 * 64));
			maccess(mapping_cache_line2 + (l1 * 64));
			maccess(mapping_cache_line3 + (l1 * 64));
			maccess(mapping_cache_line4 + (l1 * 64));
			maccess(mapping_cache_line5 + (l1 * 64));
			maccess(mapping_cache_line6 + (l1 * 64));
			maccess(mapping_cache_line7 + (l1 * 64));
			maccess(mapping_cache_line8 + (l1 * 64));
			mfence();
    	    __asm__ __volatile__ (
    	    					  "xbegin 2f;"				// Start TSX Transaction
//    	    					  "movq $100, %%rcx;"
//    	    					  "L1:;"
//    	    					  "decq %%rcx;"
//    	    					  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//								  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//								  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//								  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//								  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//								  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//								  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//								  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//								  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//								  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//    	    					  "jnz L1;"
    	    					  "movq (%3), %%rax;"		// Leak a single byte from mapping (leak source) and speculatively load in rax register
					  	  	  	  "movq (%4), %%rax;"
								  "movq (%5), %%rax;"
								  "movq (%6), %%rax;"
								  "movq (%7), %%rax;"
								  "movq (%8), %%rax;"
								  "movq (%9), %%rax;"
								  "movq (%10), %%rax;"
    	    					  "xend;"						// End TSX Transaction
    							  "movq %1, %%rcx;"
    	  	  	  	  	  	  	  "incq %%rcx;"
    							  "movq %%rcx, %1;"
    	  	  	  	  	  	  	  "jmp 3f;"
    							  "2:;"						//ABORTED
    				  	  	  	  "mov %%eax, %0;"
    							  "movq %2, %%rdx;"
    				  	  	  	  "incq %%rdx;"
    							  "movq %%rdx, %2;"
    				  	  	  	  "3:;"
    	    					  : "=g" (local_abort_reason), "=g"(not_aborted), "=g"(aborted) : "r" (mapping_cache_line + (l1*64)),"r" (mapping_cache_line2 + (l1*64)),"r" (mapping_cache_line3 + (l1*64)),"r" (mapping_cache_line4 + (l1*64)),"r" (mapping_cache_line5 + (l1*64)),"r" (mapping_cache_line6 + (l1*64)),"r" (mapping_cache_line7 + (l1*64)),"r" (mapping_cache_line8 + (l1*64)), [ds] "m" (ds), "r"(aborted), "r"(not_aborted) : "rcx", "rdx", "rdi", "rax"
    	    );
    	    if (local_abort_reason & (1<<2)) {
    	    		abort_reason_l1[l1][2]++;
    	    		aborted_overall++;
    	    }
    	    aborted_arr[l1] += aborted;
    	    not_aborted_arr[l1] += not_aborted;
    	    not_aborted_overall += not_aborted;
    	    aborted = 0;
    	    not_aborted = 0;
	    }

#endif

#ifdef FLUSH_DETECTOR

	    volatile int temp_ctr = 0;

	    for (int i=0; i< LIMIT_L1 * 64; i+=64) {
//			__asm__ __volatile__ (
//								  "movq %0, %%rdi;"				// Move mapping (leak source) to "rdi"
//								  "clflush (%%rdi);"
//	//							  "mov (%%rdi), %%rax;"
//								  : :  "r" (mapping_cache_line + i), [ds] "m" (ds) : "rdi", "rax"
//			);

			flush(mapping_cache_line + i);
			mfence();
			__asm__ __volatile__ (
								  "movq %3, %%rdi;"				// Move mapping (leak source) to "rdi"
//								  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
								  "xbegin 2f;"				// Start TSX Transaction
								  "movq (%%rdi), %%rax;"		// Leak a single byte from mapping (leak source) and speculatively load in rax register
								  "xend;"						// End TSX Transaction

								  "movq %0, %%rcx;"
								  "incq %%rcx;"
								  "movq %%rcx, %0;"
								  "jmp 3f;"
								  "2:;"						//
								  "movq %1, %%rdx;"
								  "incq %%rdx;"
								  "movq %%rdx, %1;"
								  "3:;"
								  : "=g"(not_aborted_arr[temp_ctr]), "=g"(aborted_arr[temp_ctr]) : [ds] "m" (ds), "r" (mapping_cache_line + i), "r"(aborted_arr[temp_ctr]), "r"(not_aborted_arr[temp_ctr]) : "rcx", "rdx", "rdi", "rax"
			);
			temp_ctr++;
	    }
#if 0 // Single
	    __asm__ __volatile__ (
	    		 	 	 	  "movq %0, %%rdi;"				// Move mapping (leak source) to "rdi"
	    					  "clflush (%%rdi);"
//							  "mov (%%rdi), %%rax;"
	    					  : :  "r" (mapping_cache_line), [ds] "m" (ds) : "rdi", "rax"
	    );

	    maccess(mapping_cache_line);
	    __asm__ __volatile__ (
	 	 	 	  	  	  	  "movq %3, %%rdi;"				// Move mapping (leak source) to "rdi"
							  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//							  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//							  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//							  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//							  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//							  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//							  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//							  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//							  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
//							  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
	    					  "xbegin 2f;"				// Start TSX Transaction
	    					  "movq (%%rdi), %%rax;"		// Leak a single byte from mapping (leak source) and speculatively load in rax register
	    					  "xend;"						// End TSX Transaction

							  "movq %0, %%rcx;"
	  	  	  	  	  	  	  "incq %%rcx;"
							  "movq %%rcx, %0;"
	  	  	  	  	  	  	  "jmp 3f;"
							  "2:;"						//
							  "movq %1, %%rdx;"
				  	  	  	  "incq %%rdx;"
							  "movq %%rdx, %1;"
				  	  	  	  "3:;"
	    					  : "=g"(not_aborted), "=g"(aborted) : [ds] "m" (ds), "r" (mapping_cache_line), "r"(aborted), "r"(not_aborted) : "rcx", "rdx", "rdi", "rax"
	    );
#endif
#endif


#ifdef FLUSH_DETECTOR_NEW

	    volatile int temp_ctr = 0;

	    for (int i=0; i< LIMIT_L1 * 64; i+=64) {
//			__asm__ __volatile__ (
//								  "movq %0, %%rdi;"				// Move mapping (leak source) to "rdi"
//								  "clflush (%%rdi);"
//	//							  "mov (%%rdi), %%rax;"
//								  : :  "r" (mapping_cache_line + i), [ds] "m" (ds) : "rdi", "rax"
//			);

//			flush(mapping_cache_line + i);
	    	maccess(mapping_cache_line + i);
			mfence();
			__asm__ __volatile__ (
								  "movq %3, %%rdi;"				// Move mapping (leak source) to "rdi"
//								  "nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;""nop;"
								  "xbegin 2f;"				// Start TSX Transaction
								  "movq (%%rdi), %%rax;"		// Leak a single byte from mapping (leak source) and speculatively load in rax register
								  "xend;"						// End TSX Transaction

								  "movq %0, %%rcx;"
								  "incq %%rcx;"
								  "movq %%rcx, %0;"
								  "jmp 3f;"
								  "2:;"						//
								  "movq %1, %%rdx;"
								  "incq %%rdx;"
								  "movq %%rdx, %1;"
								  "3:;"
								  : "=g"(not_aborted_arr[temp_ctr]), "=g"(aborted_arr[temp_ctr]) : [ds] "m" (ds), "r" (mapping_cache_line + i), "r"(aborted_arr[temp_ctr]), "r"(not_aborted_arr[temp_ctr]) : "rcx", "rdx", "rdi", "rax"
			);
			temp_ctr++;
	    }
#endif
//	    if (++temp_cnter > 10000)
#ifdef ABORT_DETECTOR

	    if (++temp_cnter > 10000000)
	    {
	    	temp_cnter = 0;
	    	float abrt_per = (float) (aborted * 50000) / not_aborted;
	    	if (abrt_per < LOAD_DETECT_THRESH) {
				printf("TAA Not Detected {Frequency: %f%% (Detection Range > %d%%)}\n", abrt_per, LOAD_DETECT_THRESH);
	    	}
	    	else {
				printf("TAA Detected {Frequency: %f%% (Detection Range > %d%%)}\n", abrt_per, LOAD_DETECT_THRESH);
	    	}
#endif
#ifdef NEW_DETECTOR
#if 0
	    if (++temp_cnter > 10000000)
	    {
	    	temp_cnter = 0;
	    	double abrt_per = (double) ((double)(abort_reason[2] ) / (unsigned long long)not_aborted) * 100000;
//	    	if (abrt_per < LOAD_DETECT_THRESH) {
////				printf("TAA Not Detected {Frequency: %f%% (Detection Range > %d%%)}\n", abrt_per, LOAD_DETECT_THRESH);
//	    	}
//	    	else {
////				printf("TAA Detected {Frequency: %f%% (Detection Range > %d%%)}\n", abrt_per, LOAD_DETECT_THRESH);
//	    	}
			  "movq (%5), %%rax;"
			  "movq (%6), %%rax;"
			  "movq (%7), %%rax;"
			  "movq (%8), %%rax;"
			  "movq (%9), %%rax;"
			  "movq (%10), %%rax;"
	    	printf("LINE # %lld\n", line_cnter%64);
	    	for (int i=0; i<7; i++) {
	    		if (i == 6) {
		    		printf("*%d,  \t", abort_reason[i]);
	    		}
	    		else {
		    		printf("%d,  \t", abort_reason[i]);
	    		}
	    		abort_reason[i] = 0;
	    	}
    		printf("**%lld,\t", not_aborted);
	    	printf("\n");
	    	line_cnter++;
#else

		    if (++temp_cnter > 200000)
		    {
		    	temp_cnter = 0;

		    	int max = 0;
		    	int max2 = 0;
		    	int idx = 0;
		    	int idx2 = 0;
		    	for (int i=0; i<64; i++) {
//		    		printf("L-%d=%d, ", i, abort_reason_l1[i][2]);
		    		if (abort_reason_l1[i][2] > max) {
		    			max2 = max;
		    			max = abort_reason_l1[i][2];
		    			idx = i;
		    		}
		    		else if (abort_reason_l1[i][2] > max2) {
		    			max2 = abort_reason_l1[i][2];
		    			idx2 = i;
		    		}
//		    		else if (aborted_arr[i])
//		    		printf("L-%d=%lld, ", i, aborted_arr[i]);
		    		aborted_arr[i] = 0;
		    		abort_reason_l1[i][2] = 0;
		    	}
		    	double abrt_per = (double) ((double)(aborted_overall ) / (unsigned long long)not_aborted_overall) * 100000;
//		    	printf("L-%d=%d, \t L-%d=%d, \t diff=%d, \t %lld, %lld, %f", idx, max, idx2, max2, max-max2, aborted_overall, not_aborted_overall, abrt_per);
//		    	printf("\n\n");
		    	aborted_overall = 0;
		    	not_aborted_overall = 0;

		    	aborted_overall = 0;
		    	not_aborted_overall = 0;

		    	int diff = max - max2;
		    	if (((diff > 50) && (max2 < 100)) ||
		    			((diff > 1000) && (max2 > 100))) {
		    		printf("Sibling Core continuously flushing Cache Line - %d... :| \t\t== %d\n", idx, flush_cnter);
		    		flush_cnter = (flush_cnter + 1) % 1000000;
		    		no_issue_cnter = 0;
		    		taa_cnter = 0;
		    	}
		    	else if (abrt_per > 100) {
		    		printf("TAA is detected on Sibling Core... :( \t\t\t\t\t== %d\n", taa_cnter);
		    		taa_cnter = (taa_cnter + 1) % 1000000;
		    		flush_cnter = 0;
		    		no_issue_cnter = 0;
		    	}
		    	else {
		    		printf("NO ISSUE... :) \t\t\t\t\t\t\t\t== %d\n", no_issue_cnter);
		    		no_issue_cnter = (no_issue_cnter + 1) % 1000000;
		    		flush_cnter = 0;
		    		taa_cnter = 0;
		    	}
//		  	  for (int l3 = 0; l3<(NUM_SETS*NUM_WAYS); l3+=64) {
//
//					maccess(mapping_cache_line + (l3));
//					mfence();
//					maccess(mapping_cache_line2 + (l3));
//					mfence();
//					maccess(mapping_cache_line3 + (l3));
//					mfence();
//					maccess(mapping_cache_line4 + (l3));
//					mfence();
//					maccess(mapping_cache_line5 + (l3));
//					mfence();
//					maccess(mapping_cache_line6 + (l3));
//					mfence();
//					maccess(mapping_cache_line7 + (l3));
//					mfence();
//					maccess(mapping_cache_line8 + (l3));
//					mfence();
//
//		  			flush(mapping_cache_line + l3);
//		  			flush(mapping_cache_line2 + l3);
//		  			flush(mapping_cache_line3 + l3);
//		  			flush(mapping_cache_line4 + l3);
//		  			flush(mapping_cache_line5 + l3);
//		  			flush(mapping_cache_line6 + l3);
//		  			flush(mapping_cache_line7 + l3);
//		  			flush(mapping_cache_line8 + l3);
//		  	  }
#endif
#endif
#ifdef LOAD_DETECTOR

		if (++temp_cnter > 50000)
		{
			temp_cnter = 0;
	    	float abrt_per = (float) (aborted * 100) / not_aborted;
	    	if (abrt_per < LOAD_WHILE_THRESH) {
				printf("while(1), busy wait detected on hyperthread {Frequency: %f%%}\n", abrt_per);
	    	}
	    	else if (abrt_per < LOAD_VULNERABLE_THRESH) {
				printf("Some vulnerable activity detected on Hyperthread {Frequency: %f%%}\n", abrt_per);
	    	}
	    	else {
				printf("Hyperthread not Vulnerable {Frequency: %f%%}\n", abrt_per);
	    	}
#endif
#ifdef FLUSH_DETECTOR_NEW

		if (++temp_cnter > 50000)
		{
			temp_cnter = 0;
#if 0
	    	float abrt_per = (float) (aborted * 100) / not_aborted;
	    	printf("Detection Threshold => %f%% (Mapping=%p, Mapping_Line=%p, Mapping_L1=%p)\n", abrt_per*100, mapping, mapping_cache_line, mappingl1);
#else


	    	volatile float tt1 = 0;
	    	volatile float tt2 = 0;
	    	for (int i=0; i<LIMIT_L1; i++) {
	    		float abrt_per = (float) (aborted_arr[i] * 100) / not_aborted_arr[i];
//	    		printf("%.2f,\t", abrt_per*100);
	    		aborted_arr[i] = 0;
	    		not_aborted_arr[i] = 0;
	    		tt1 += abrt_per;
//	    		tt2 += not_aborted_arr[i];
	    	}
#define FR_WHILE 5
#define FR_FLUSH 12
#define FR_NORMAL 20
	    	float avrg_abort = tt1 / LIMIT_L1 * 100;
	    	if (avrg_abort < 6) {
				printf("Hyperthreaded Core is not Vulnerable {Frequency: %f%%}\n", avrg_abort);
	    	}
	    	else if (avrg_abort < 15) {
				printf("while(1), busy wait detected on Hyperthreaded Core {Frequency: %f%%}\n", avrg_abort);
	    	}
	    	else if (avrg_abort < 25){
				printf("Flush Reload Attack Detected on Hyperthreaded Core {Frequency: %f%%}\n", avrg_abort);
	    	}
	    	else {
				printf("TAA Detected on Hyperthreaded Core {Frequency: %f%%}\n", avrg_abort);
	    	}
//			printf("Detected Threshold => %f", avrg_abort);
	    	printf("\n");
#endif
//	    	if (abrt_per < LOAD_WHILE_THRESH) {
//				printf("while(1), busy wait detected on hyperthread {Frequency: %f%%}\n", abrt_per);
//	    	}
//	    	else if (abrt_per < LOAD_VULNERABLE_THRESH) {
//				printf("Some vulnerable activity detected on Hyperthread {Frequency: %f%%}\n", abrt_per);
//	    	}
//	    	else {
//				printf("Hyperthread not Vulnerable {Frequency: %f%%}\n", abrt_per);
//	    	}
#endif


#ifdef FLUSH_DETECTOR

		if (++temp_cnter > 50000)
		{
			temp_cnter = 0;
#if 0
	    	float abrt_per = (float) (aborted * 100) / not_aborted;
	    	printf("Detection Threshold => %f%% (Mapping=%p, Mapping_Line=%p, Mapping_L1=%p)\n", abrt_per*100, mapping, mapping_cache_line, mappingl1);
#else


	    	volatile float tt1 = 0;
	    	volatile float tt2 = 0;
	    	for (int i=0; i<LIMIT_L1; i++) {
	    		float abrt_per = (float) (aborted_arr[i] * 100) / not_aborted_arr[i];
//	    		printf("%.2f,\t", abrt_per*100);
	    		aborted_arr[i] = 0;
	    		not_aborted_arr[i] = 0;
	    		tt1 += abrt_per;
//	    		tt2 += not_aborted_arr[i];
	    	}
#define FR_WHILE 5
#define FR_FLUSH 12
#define FR_NORMAL 20
	    	float avrg_abort = tt1 / LIMIT_L1 * 100;
	    	if (avrg_abort < 6) {
				printf("Hyperthreaded Core is not Vulnerable {Frequency: %f%%}\n", avrg_abort);
	    	}
	    	else if (avrg_abort < 15) {
				printf("while(1), busy wait detected on Hyperthreaded Core {Frequency: %f%%}\n", avrg_abort);
	    	}
	    	else if (avrg_abort < 25){
				printf("Flush Reload Attack Detected on Hyperthreaded Core {Frequency: %f%%}\n", avrg_abort);
	    	}
	    	else {
				printf("TAA Detected on Hyperthreaded Core {Frequency: %f%%}\n", avrg_abort);
	    	}
//			printf("Detected Threshold => %f", avrg_abort);
	    	printf("\n");
#endif
//	    	if (abrt_per < LOAD_WHILE_THRESH) {
//				printf("while(1), busy wait detected on hyperthread {Frequency: %f%%}\n", abrt_per);
//	    	}
//	    	else if (abrt_per < LOAD_VULNERABLE_THRESH) {
//				printf("Some vulnerable activity detected on Hyperthread {Frequency: %f%%}\n", abrt_per);
//	    	}
//	    	else {
//				printf("Hyperthread not Vulnerable {Frequency: %f%%}\n", abrt_per);
//	    	}
#endif
			aborted = 0;
			not_aborted = 0;
	    }
  }
#endif
}
