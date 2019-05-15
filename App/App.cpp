/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdint.h>
#include <math.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#define NUM_ITER 2000000
//#define NUM_ITER 100

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

unsigned cycles_low, cycles_high, cycles_low1, cycles_high1, cycles_low2, cycles_high2;

int enclaveLess0=0,enclave0To100=0,enclave100To200=0,enclave200To300=0,enclave300To400=0,enclave400To500=0,enclave500Above=0;
int normLess0=0,norm0To100=0,norm100To200=0,norm200To300=0,norm300To400=0,norm400To500=0,norm500Above=0;
long double perfOverheadAvr_val=0.0, perfOverhead=0.0, perfOverheadNon_Encl=0.0, missdurationAvr_val=0.0,hitdurationAvr_val=0.0, perfOverheadNon_Encl_Avr_val;


typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;


/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}


/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if(ret != SGX_SUCCESS ) {
	print_error_message(ret);
        return -1;
    }

    return 0;
}


/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}


/* OCall functions */
void ocall_Start_Timer()
{
    asm volatile ("CPUID\n\t"
	        "RDTSC\n\t"
	        "mov %%edx, %0\n\t"
	        "mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low)::
	        "%rax", "%rbx", "%rcx", "%rdx");
}


void local_load_cache_hit(double *M1) {
	int temp;
	ocall_Start_Timer();
	temp = M1[0];
} 


void local_load_cache_miss(double *M1) {
	int temp;
	asm volatile ("clflush (%0)" :: "r"(M1)); 
	ocall_Start_Timer();
	temp = M1[0];
} 


void missDurationsEnclaveCall(double *missDurationArr)
{
        double *M1;
	size_t size_m1 = 100 * sizeof(double);	
        srand(time(NULL));
        uint64_t startmiss=0, starthit=0, endmiss=0, endhit=0, missduration=0, hitduration=0;
	long double perfOverheadAvr_val=0.0, perfOverhead=0.0, missdurationAvr_val=0.0,hitdurationAvr_val=0.0;

	for(int iter=1; iter<NUM_ITER+1; iter++) {


                M1 = (double*) malloc(100 * sizeof(double));
		if(!M1) {
			printf("malloc failed on iteration %i\n", iter);
			continue;
		}
                for(int i=0; i<100; i++) {
                        *(M1 + i) = (double) (rand() % 100);
                }

		ecall_load_cache_miss(global_eid, M1, size_m1);      
		asm volatile("RDTSCP\n\t"
	        "mov %%edx, %0\n\t"
	        "mov %%eax, %1\n\t"
	        "CPUID\n\t": "=r" (cycles_high2), "=r" (cycles_low2)::
	        "%rax", "%rbx", "%rcx", "%rdx");	
	        startmiss = ( ((uint64_t)cycles_high << 32) | cycles_low ); 
	        endmiss = ( ((uint64_t)cycles_high2 << 32) | cycles_low2 );
	       	missduration = endmiss - startmiss;

		free(M1);
		*(missDurationArr+(iter-1)) = (double)missduration;
		missdurationAvr_val= missdurationAvr_val+((missduration-missdurationAvr_val)/iter);
		if(iter % 400000 == 0) 
			printf("Iteration num: %d: Cache Miss duration for enclave current average %Lf \n", iter, missdurationAvr_val);
	}
	printf("Average Miss duration for enclave: %Lf \n\n",missdurationAvr_val);
}


void hitDurationsEnclaveCall(double *hitDurationArr)
{
        double *M1;
	size_t size_m1 = 100 * sizeof(double);	
        srand(time(NULL));
        uint64_t startmiss=0, starthit=0, endmiss=0, endhit=0, missduration=0, hitduration=0;
	long double perfOverheadAvr_val=0.0, perfOverhead=0.0, missdurationAvr_val=0.0,hitdurationAvr_val=0.0;

	for(int iter=1; iter<NUM_ITER+1; iter++) {


                M1 = (double*) malloc(100 * sizeof(double));
		if(!M1) {
			printf("malloc failed on iteration %i\n", iter);
			continue;
		}
                for(int i=0; i<100; i++) {
                        *(M1 + i) = (double) (rand() % 100);
                }

		ecall_load_cache_hit(global_eid, M1, size_m1);      
		asm volatile("RDTSCP\n\t"
	        "mov %%edx, %0\n\t"
	        "mov %%eax, %1\n\t"
	        "CPUID\n\t": "=r" (cycles_high2), "=r" (cycles_low2)::
	        "%rax", "%rbx", "%rcx", "%rdx");	
	        starthit = ( ((uint64_t)cycles_high << 32) | cycles_low ); 
	        endhit = ( ((uint64_t)cycles_high2 << 32) | cycles_low2 );
	       	hitduration = endhit - starthit;

		free(M1);
		*(hitDurationArr+(iter-1)) = (double)hitduration;
		hitdurationAvr_val = hitdurationAvr_val+((hitduration-hitdurationAvr_val)/iter);
		if(iter % 400000 == 0) 
			printf("Iteration num: %d: Cache Hit for enclave current average %Lf \n", iter, hitdurationAvr_val);
	}
	printf("Average Hit duration for enclave: %Lf \n\n",hitdurationAvr_val);
}


void perfCalcArr(double *missdurationArr, double *hitdurationArr){
	
        double missduration, hitduration;
	for(int iter=1; iter<NUM_ITER+1; iter++) {	
		missduration = *(missdurationArr+(iter-1));
		hitduration = *(hitdurationArr+(iter-1));
		if(missduration < hitduration){					
			perfOverhead =-(long double)(hitduration-missduration);
		}else{			
			perfOverhead = (long double)(missduration-hitduration);
		}
		missdurationAvr_val= missdurationAvr_val+((missduration-missdurationAvr_val)/iter);
		hitdurationAvr_val= hitdurationAvr_val+((hitduration-hitdurationAvr_val)/iter);
		perfOverheadAvr_val = perfOverheadAvr_val + ((perfOverhead - perfOverheadAvr_val)/iter);



		if(iter % 400000 == 0) 
		printf("Enclave Perf Ovehead Cache Miss and hit Iteration %i: current average %Lf :: current Perf ovehead:%Lf ::missduration%f ::hitduration %f \n", iter, perfOverheadAvr_val, perfOverhead, missduration, hitduration);		
		if(perfOverhead<0)
			enclaveLess0++;
		if(perfOverhead>=0 && perfOverhead<100)
			enclave0To100++;
		else if(perfOverhead>=100 && perfOverhead<200 )
			enclave100To200++;
		else if(perfOverhead>=200 && perfOverhead<300 )
			enclave200To300++;
		else if(perfOverhead>=300 && perfOverhead<400 )
			enclave300To400++;
		else if(perfOverhead>=400 && perfOverhead<500 )
			enclave400To500++;
		else if(perfOverhead>=500)
			enclave500Above++;
	}
}



void missDurationsNonEnclaveCall(double *missDurationArrNonEnc)
{
        double *M1;
	size_t size_m1 = 100 * sizeof(double);	
        srand(time(NULL));
        uint64_t startmiss=0, starthit=0, endmiss=0, endhit=0, missduration=0, hitduration=0;
	long double perfOverheadAvr_val=0.0, perfOverhead=0.0, missdurationAvr_val=0.0,hitdurationAvr_val=0.0;

	for(int iter=1; iter<NUM_ITER+1; iter++) {


                M1 = (double*) malloc(100 * sizeof(double));
		if(!M1) {
			printf("malloc failed on iteration %i\n", iter);
			continue;
		}
                for(int i=0; i<100; i++) {
                        *(M1 + i) = (double) (rand() % 100);
                }

		local_load_cache_miss(M1);      
		asm volatile("RDTSCP\n\t"
	        "mov %%edx, %0\n\t"
	        "mov %%eax, %1\n\t"
	        "CPUID\n\t": "=r" (cycles_high2), "=r" (cycles_low2)::
	        "%rax", "%rbx", "%rcx", "%rdx");	
	        startmiss = ( ((uint64_t)cycles_high << 32) | cycles_low ); 
	        endmiss = ( ((uint64_t)cycles_high2 << 32) | cycles_low2 );
	       	missduration = endmiss - startmiss;

		free(M1);
		*(missDurationArrNonEnc+(iter-1)) = (double)missduration;
		missdurationAvr_val= missdurationAvr_val+((missduration-missdurationAvr_val)/iter);

		if(iter % 400000 == 0) 
			printf("Iteration num: %d: Cache Miss for Non- enclave current average %Lf \n", iter, missdurationAvr_val);
	}
	printf("Average Miss duration for Non-enclave: %Lf \n\n",missdurationAvr_val);
}


void hitDurationsNonEnclaveCall(double *hitDurationArrNonEnc)
{
        double *M1;
	size_t size_m1 = 100 * sizeof(double);	
        srand(time(NULL));
        uint64_t startmiss=0, starthit=0, endmiss=0, endhit=0, missduration=0, hitduration=0;
	long double perfOverheadAvr_val=0.0, perfOverhead=0.0, missdurationAvr_val=0.0,hitdurationAvr_val=0.0;

	for(int iter=1; iter<NUM_ITER+1; iter++) {


                M1 = (double*) malloc(100 * sizeof(double));
		if(!M1) {
			printf("malloc failed on iteration %i\n", iter);
			continue;
		}
                for(int i=0; i<100; i++) {
                        *(M1 + i) = (double) (rand() % 100);
                }

		local_load_cache_hit(M1);      
		asm volatile("RDTSCP\n\t"
	        "mov %%edx, %0\n\t"
	        "mov %%eax, %1\n\t"
	        "CPUID\n\t": "=r" (cycles_high2), "=r" (cycles_low2)::
	        "%rax", "%rbx", "%rcx", "%rdx");	
	        starthit = ( ((uint64_t)cycles_high << 32) | cycles_low ); 
	        endhit = ( ((uint64_t)cycles_high2 << 32) | cycles_low2 );
	       	hitduration = endhit - starthit;

		free(M1);
		*(hitDurationArrNonEnc+(iter-1)) = (double)hitduration;
		hitdurationAvr_val = hitdurationAvr_val+((hitduration-hitdurationAvr_val)/iter);

		if(iter % 400000 == 0) 
			printf("Iteration num: %d: Cache Hit for Non- enclave current average %Lf \n", iter, hitdurationAvr_val);
	}
	printf("Average Hit duration for Non-enclave: %Lf \n\n",hitdurationAvr_val);
}



void perfCalcArrNonEnclave(double *missDurationArrNonEnc, double *hitDurationArrNonEnc){
	
        double missduration, hitduration;
	for(int iter=1; iter<NUM_ITER+1; iter++) {	
		missduration = *(missDurationArrNonEnc+(iter-1));
		hitduration = *(hitDurationArrNonEnc+(iter-1));
				       	



		perfOverheadNon_Encl = (long double)(missduration-hitduration);
		if(missduration < hitduration){			
			perfOverheadNon_Encl = (long double)(hitduration-missduration);
		}
		perfOverheadNon_Encl_Avr_val = perfOverheadNon_Encl_Avr_val + (perfOverheadNon_Encl - perfOverheadNon_Encl_Avr_val)/iter;



		if(iter % 400000 == 0) 
			printf("Non Enclave Perf Ovehead Cache Miss and hit Non Enclave Iteration %i: current average %Lf :: current Perf ovehead:%Lf \n", iter, perfOverheadNon_Encl_Avr_val, perfOverheadNon_Encl);
		if(perfOverhead<0)
			normLess0++;
		else if(perfOverhead>=0 && perfOverhead<100 )
			norm0To100++;
		else if(perfOverhead>=100 && perfOverhead<200 )
			norm100To200++;
		else if(perfOverhead>=200 && perfOverhead<300 )
			norm200To300++;
		else if(perfOverhead>=300 && perfOverhead<400 )
			norm300To400++;
		else if(perfOverhead>=400 && perfOverhead<500 )
			norm400To500++;
		else if(perfOverhead>=500)
			norm500Above++;
		
	}

}


void rdtscpOverhead(){
        uint64_t start=0, end=0, duration=0, hitduration=0;
        double durationAvr_val=0;
	for(int iter=1; iter<NUM_ITER+1; iter++) {

		asm volatile ("CPUID\n\t"
	        "RDTSC\n\t"
	        "mov %%edx, %0\n\t"
	        "mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low)::
	        "%rax", "%rbx", "%rcx", "%rdx");
		asm volatile("RDTSCP\n\t"
	        "mov %%edx, %0\n\t"
	        "mov %%eax, %1\n\t"
	        "CPUID\n\t": "=r" (cycles_high2), "=r" (cycles_low2)::
	        "%rax", "%rbx", "%rcx", "%rdx");	
	        start = ( ((uint64_t)cycles_high << 32) | cycles_low ); 
	        end = ( ((uint64_t)cycles_high2 << 32) | cycles_low2 );
	       	duration = end - start;

		durationAvr_val = durationAvr_val+((duration-durationAvr_val)/iter);
	}
	printf("Average rdtscp Overhead duration : %f \n\n",durationAvr_val);
	
}


//Application Entry point//
int SGX_CDECL main()
{
	double *missDurationArr, *hitDurationArr, *missDurationArrNonEnc, *hitDurationArrNonEnc;
	ocall_Start_Timer();
	ocall_Start_Timer();
	asm volatile ("CPUID\n\t"
	        "RDTSC\n\t":::
	        "%rax", "%rbx", "%rcx", "%rdx");

	if(initialize_enclave() < 0){
		printf("Failed to initialize enclave.\n");
		return -1; 
	}

	missDurationArr = (double*) malloc(NUM_ITER * sizeof(double));
	hitDurationArr = (double*) malloc(NUM_ITER * sizeof(double));
	missDurationArrNonEnc = (double*) malloc(NUM_ITER * sizeof(double));
	hitDurationArrNonEnc = (double*) malloc(NUM_ITER * sizeof(double));

	for(int i=0; i<NUM_ITER; i++) {
               *(missDurationArr + i) = (double) (0);
               *(hitDurationArr + i) = (double) (0);
               *(missDurationArrNonEnc + i) = (double) (0);
               *(hitDurationArrNonEnc + i) = (double) (0);
	}

	
	//calcuations
	rdtscpOverhead();
	missDurationsEnclaveCall(missDurationArr);
	hitDurationsEnclaveCall(hitDurationArr);
	perfCalcArr(missDurationArr, hitDurationArr);
	printf("Enclave Performance Ovehead as difference between Cache Miss and hit %d iterations: Average cycles %Lf\n\n", NUM_ITER, perfOverheadAvr_val);
	// Destroying the enclave
	sgx_destroy_enclave(global_eid);

	
	missDurationsNonEnclaveCall(missDurationArrNonEnc);
	hitDurationsNonEnclaveCall(hitDurationArrNonEnc);
	perfCalcArrNonEnclave(missDurationArrNonEnc, hitDurationArrNonEnc);
	printf("Non Enclave Performance Ovehead as difference between Cache Miss and hit %d iterations: Average cycles %Lf\n\n", NUM_ITER, perfOverheadNon_Encl_Avr_val);	


	printf("Caclculating Memory Encryption Overhead as the difference between the Enclave and Non \n");
	printf("Memory Encryption Overhead successfully calculated taking : %Lf : cycles \n", perfOverheadAvr_val - perfOverheadNon_Encl_Avr_val);


	/*printf("::::Printing out the statistics calculated::::\n");
	printf("Period \t\t\t Enclave \t\t Non-Enclave\n");
	printf("Negative \t\t %d \t\t %d\n",enclaveLess0, normLess0);
	printf("   0-100 \t\t %d \t\t %d\n",enclave0To100, norm0To100);
	printf(" 100-200 \t\t %d \t\t %d\n",enclave100To200, norm100To200);
	printf(" 200-300 \t\t %d \t\t %d\n",enclave200To300, norm200To300);
	printf(" 300-400 \t\t %d \t\t %d\n",enclave300To400, norm300To400);
	printf(" 400-500 \t\t %d \t\t %d\n",enclave400To500, norm400To500);
	printf("Great500 \t\t %d \t\t %d\n",enclave500Above, norm500Above);		*/
	return 0;
}
