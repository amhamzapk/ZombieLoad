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
 * NORMAL FLAG MUST BE OF FOR FOLLOWING TO WORK
 * ONLY ONE CAN BE ENABLED AT A TIME
 */
//#define ABORT_DETECTOR
//#define LOAD_DETECTOR
#define FLUSH_DETECTOR

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
char __attribute__((aligned(4096))) secret[8192];
char __attribute__((aligned(4096))) mem[256 * 4096];
char __attribute__((aligned(4096)))/*__attribute__((aligned(4096)))*/ mapping[4096];
char __attribute__((aligned(4096)))/*__attribute__((aligned(4096)))*/ mapping_cache_line[64 * LIMIT_L1];
char __attribute__((aligned(64)))   mappingl1[1024*32];
long long temp_cnter = 0;
long long another_cnter = 0;
volatile bool abort_flag = 0;
volatile long long aborted = 0;
volatile long long not_aborted = 0;
volatile long long aborted_arr[LIMIT_L1] = {0};
volatile long long not_aborted_arr[LIMIT_L1] = {0};
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
//								  "mov (%%rdi), %%rax;"
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

#ifdef FLUSH_DETECTOR

	    volatile int temp_ctr = 0;

	    for (int i=0; i< LIMIT_L1 * 64; i+=64) {
//			__asm__ __volatile__ (
//								  "movq %0, %%rdi;"				// Move mapping (leak source) to "rdi"
//								  "clflush (%%rdi);"
//	//							  "mov (%%rdi), %%rax;"
//								  : :  "r" (mapping_cache_line + i), [ds] "m" (ds) : "rdi", "rax"
//			);

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
	    	if (avrg_abort < FR_WHILE) {
				printf("while(1), busy wait detected on Hyperthreaded Core {Frequency: %f%%}\n", avrg_abort);
	    	}
	    	else if (avrg_abort < FR_FLUSH) {
				printf("Flush Reload Attack Detected on Hyperthreaded Core {Frequency: %f%%}\n", avrg_abort);
	    	}
	    	else {
				printf("Hyperthreaded Core is not Vulnerable {Frequency: %f%%}\n", avrg_abort);
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
