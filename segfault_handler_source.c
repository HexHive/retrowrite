#include <stdio.h>
#include <signal.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <stdlib.h>

#define REG_PC 32

void handler(int sig, siginfo_t *info, void *uap)
{

    // TODO: boundary check on only executable pages

    ucontext_t* context = uap;
    puts("SIGSEGV signal caught by handler!");
    int instruction_bytes = *(int*)context->uc_mcontext.regs[REG_PC];
    //printf("\nUH-OH LOOKS LIKE SOMEONE at 0x%llx TRIED TO READ AN EXECUTABLE ONLY PAGE AT ADDRESS %p!\n\n", context->uc_mcontext.regs[REG_PC], info->si_addr);
    //printf("instruction bytes: %x\n", instruction_bytes);
    if ( ! (instruction_bytes & 0x3fc00000) == 0x39400000 \
      && ! (instruction_bytes & 0x3f000000) == 0x18000000  \
      && ! (instruction_bytes & 0x3f600000) == 0x38600000) {
        puts("error in segfault handler: data_inside_text instruction not supported\n");
        exit(1);
    }
    int reg_to_read_into = instruction_bytes & 0x0000001f;
    context->uc_mcontext.regs[reg_to_read_into] = 1;
    context->uc_mcontext.regs[REG_PC] += 4;
    
/*
// file:///Users/fontana/Downloads/ISA_A64_xml_A_profile-2022-03_OPT.pdf

   3         2         1
  10987654321098765432109876543210
// ldr immediate, unsigned offset
0b00111111110000000000000000000000 // mask ('0x3fc00000')
0b00111001010000000000000000000000 // correct result ('0x39400000')
'0b 1110010100'

// ldr literal
0b00111111000000000000000000000000 // mask ('0x3f000000')
0b00011000000000000000000000000000 // correct result ('0x18000000')

// ldr register
0b00111111011000000000000000000000 // mask ('0x3f600000')
0b00111000011000000000000000000000 // correct result ('0x38600000')

// I think bit 26 tells us if it is floating point or not
*/


    // TODO: post index and pre-index are not supported!!!
    // TODO: ldp not supported
    // TODO: ldrb not supported
    // TODO: ldrsb not supported
    // TODO: ldrh not supported
    // TODO: ldrsh not supported
    // TODO: ldrw not supported
    // TODO: ldrsw not supported
    // TODO: ldraa (ptr auth) not supported
    // https://developer.arm.com/documentation/ddi0596/2020-12/Base-Instructions/LDR--immediate---Load-Register--immediate--
    // ldr:    1	x	1	1	1	0	0	0	0	1	1
    //         1	x	1	1	1	0	0	0	0	1	1	Rm	option	S	1	0	Rn	Rt
    // ldrb :  0	0	1	1	1	0	0	0	0	1	1
    // ldrh :  0	1	1	1	1	0	0	0	0	1	1
    // ldrsh:  0	1	1	1	1	0	0	0	0	1	1
    // ldrsw:  1	0	1	1	1	0	0	0	1	0	1
    // pre-index
    // ldr:    1	x	1	1	1	0	0	0	0	1	0	imm9	1	1	Rn	Rt
    // post-index
    // ldr:    1	x	1	1	1	0	0	0	0	1	0	imm9	0	1	Rn	Rt
    // unsigned offset
    // ldr:    1	x	1	1	1	0	0	1	0	1	imm12	            Rn	Rt
    return;
}

void register_handler() {
    struct sigaction sa;
    sa.sa_sigaction = handler;
    sigemptyset (&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    sigaction (SIGSEGV, &sa, 0);
}

int main () {
    register_handler();
    void *ciao = mmap((void*)0x4000000, 0x1000, PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0); // no PROT_READ!!!
    printf("Exec-only page mapped at: %p\n", (int*)ciao);
    printf("Now triggering an invalid read...\n");
    long long a = *(long long*)ciao; // this should trigger a segfault
    printf("recovered! value read: 0x%llx\n", a); 
}

