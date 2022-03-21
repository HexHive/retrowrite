.section .fini_array
	.quad asan.module_dtor
.section .rodata
.align 4
.type	_IO_stdin_used_2000,@object
.globl _IO_stdin_used_2000
_IO_stdin_used_2000: # 2000 -- 2004
.LC2000:
	.byte 0x1
.LC2001:
	.byte 0x0
.LC2002:
	.byte 0x2
.LC2003:
	.byte 0x0
.LC2004:
	.byte 0x77
.LC2005:
	.byte 0x68
.LC2006:
	.byte 0x61
.LC2007:
	.byte 0x74
.LC2008:
	.byte 0x20
.LC2009:
	.byte 0x74
.LC200a:
	.byte 0x68
.LC200b:
	.byte 0x65
.LC200c:
	.byte 0x20
.LC200d:
	.byte 0x66
.LC200e:
	.byte 0x75
.LC200f:
	.byte 0x63
.LC2010:
	.byte 0x6b
.LC2011:
	.byte 0x20
.LC2012:
	.byte 0x25
.LC2013:
	.byte 0x73
.LC2014:
	.byte 0x0
.section .init_array
.align 8
	.quad asan.module_ctor
.section .data
.align 8
.LC4030:
	.byte 0x0
.LC4031:
	.byte 0x0
.LC4032:
	.byte 0x0
.LC4033:
	.byte 0x0
.LC4034:
	.byte 0x0
.LC4035:
	.byte 0x0
.LC4036:
	.byte 0x0
.LC4037:
	.byte 0x0
.LC4038:
	.quad .LC4038
.section .bss
.align 1
.type	completed.0_4040,@object
.globl completed.0_4040
completed.0_4040: # 4040 -- 4041
.LC4040:
	.byte 0x0
.LC4041:
	.byte 0x0
.LC4042:
	.byte 0x0
.LC4043:
	.byte 0x0
.LC4044:
	.byte 0x0
.LC4045:
	.byte 0x0
.LC4046:
	.byte 0x0
.LC4047:
	.byte 0x0
.section .text
.align 16
	.text
.globl func
.type func, @function
func:
.L1160:
.LC1160:
	pushq %rbp
.LC1161:
	movq %rsp, %rbp
.LC1164:
	subq $0x10, %rsp
.LC1168:
	movl $0x100, %edi
.LC116d:
	callq malloc@PLT
.LC1172:
.LC_ASAN_ENTER_1172: # 1172: movq %rax, -8(%rbp): ['rdi', 'rsi']
		leaq  -8(%rbp), %rsi
	movq %rsi, %rdi
	shrq $3, %rdi
	cmpb $0, 2147450880(%rdi)
	je .LC_ASAN_EX_4466
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4466:
	movq %rax, -8(%rbp)
.LC1176:
.LC_ASAN_ENTER_1176: # 1176: movq -8(%rbp), %rsi: ['rdi', 'rsi']
		leaq -8(%rbp), %rsi
	movq %rsi, %rdi
	shrq $3, %rdi
	cmpb $0, 2147450880(%rdi)
	je .LC_ASAN_EX_4470
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4470:
	movq -8(%rbp), %rsi
.LC117a:
	leaq .LC2012(%rip), %rdi
.LC1181:
	movb $0, %al
.LC1183:
	callq __isoc99_scanf@PLT
.LC1188:
.LC_ASAN_ENTER_1188: # 1188: movl $0, -0xc(%rbp): ['rax']
		pushq %rdi
leaq 8(%rsp), %rsp
	leaq  -0xc(%rbp), %rdi
	movq %rdi, %rax
	shrq $3, %rax
	movb 2147450880(%rax), %al
	testb %al, %al
	je .LC_ASAN_EX_4488
	andl $7, %edi
	addl $3, %edi
	movsbl %al, %eax
	cmpl %eax, %edi
	jl .LC_ASAN_EX_4488
	callq __asan_report_load4@PLT
.LC_ASAN_EX_4488:
leaq -8(%rsp), %rsp
	popq %rdi
	movl $0, -0xc(%rbp)
.L118f:
.LC118f:
.LC_ASAN_ENTER_118f: # 118f: cmpl $0x101, -0xc(%rbp): ['rax']
		pushq %rdi
leaq 8(%rsp), %rsp
	leaq  -0xc(%rbp), %rdi
	movq %rdi, %rax
	shrq $3, %rax
	movb 2147450880(%rax), %al
	testb %al, %al
	je .LC_ASAN_EX_4495
	andl $7, %edi
	addl $3, %edi
	movsbl %al, %eax
	cmpl %eax, %edi
	jl .LC_ASAN_EX_4495
	callq __asan_report_load4@PLT
.LC_ASAN_EX_4495:
leaq -8(%rsp), %rsp
	popq %rdi
	cmpl $0x101, -0xc(%rbp)
.LC1196:
	jge .L11b8
.LC119c:
.LC_ASAN_ENTER_119c: # 119c: movl -0xc(%rbp), %eax: ['rcx', 'rdx', 'rax']
		leaq -0xc(%rbp), %rdx
	movq %rdx, %rcx
	shrq $3, %rcx
	movb 2147450880(%rcx), %cl
	testb %cl, %cl
	je .LC_ASAN_EX_4508
	andl $7, %edx
	addl $3, %edx
	movsbl %cl, %ecx
	cmpl %ecx, %edx
	jl .LC_ASAN_EX_4508
	callq __asan_report_load4@PLT
.LC_ASAN_EX_4508:
	movl -0xc(%rbp), %eax
.LC119f:
.LC_ASAN_ENTER_119f: # 119f: movq -8(%rbp), %rcx: ['rcx', 'rdx']
		leaq -8(%rbp), %rdx
	movq %rdx, %rcx
	shrq $3, %rcx
	cmpb $0, 2147450880(%rcx)
	je .LC_ASAN_EX_4511
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4511:
	movq -8(%rbp), %rcx
.LC11a3:
.LC_ASAN_ENTER_11a3: # 11a3: movslq -0xc(%rbp), %rdx: ['rdx']
		pushq %rdi
leaq 8(%rsp), %rsp
	leaq -0xc(%rbp), %rdi
	movq %rdi, %rdx
	shrq $3, %rdx
	movb 2147450880(%rdx), %dl
	testb %dl, %dl
	je .LC_ASAN_EX_4515
	andl $7, %edi
	addl $3, %edi
	movsbl %dl, %edx
	cmpl %edx, %edi
	jl .LC_ASAN_EX_4515
	callq __asan_report_load4@PLT
.LC_ASAN_EX_4515:
leaq -8(%rsp), %rsp
	popq %rdi
	movslq -0xc(%rbp), %rdx
.LC11a7:
.LC_ASAN_ENTER_11a7: # 11a7: movb %al, (%rcx, %rdx): []
		pushq %rdi
	pushq %rsi
leaq 16(%rsp), %rsp
	leaq  (%rcx, %rdx), %rdi
	movq %rdi, %rsi
	shrq $3, %rsi
	movb 2147450880(%rsi), %sil
	testb %sil, %sil
	je .LC_ASAN_EX_4519
	andl $7, %edi
	movsbl %sil, %esi
	cmpl %esi, %edi
	jl .LC_ASAN_EX_4519
	callq __asan_report_load1@PLT
.LC_ASAN_EX_4519:
leaq -16(%rsp), %rsp
	popq %rsi
	popq %rdi
	movb %al, (%rcx, %rdx)
.LC11aa:
.LC_ASAN_ENTER_11aa: # 11aa: movl -0xc(%rbp), %eax: ['rax']
		pushq %rdi
leaq 8(%rsp), %rsp
	leaq -0xc(%rbp), %rdi
	movq %rdi, %rax
	shrq $3, %rax
	movb 2147450880(%rax), %al
	testb %al, %al
	je .LC_ASAN_EX_4522
	andl $7, %edi
	addl $3, %edi
	movsbl %al, %eax
	cmpl %eax, %edi
	jl .LC_ASAN_EX_4522
	callq __asan_report_load4@PLT
.LC_ASAN_EX_4522:
leaq -8(%rsp), %rsp
	popq %rdi
	movl -0xc(%rbp), %eax
.LC11ad:
	addl $1, %eax
.LC11b0:
.LC_ASAN_ENTER_11b0: # 11b0: movl %eax, -0xc(%rbp): []
		pushq %rdi
	pushq %rsi
leaq 16(%rsp), %rsp
	leaq  -0xc(%rbp), %rdi
	movq %rdi, %rsi
	shrq $3, %rsi
	movb 2147450880(%rsi), %sil
	testb %sil, %sil
	je .LC_ASAN_EX_4528
	andl $7, %edi
	addl $3, %edi
	movsbl %sil, %esi
	cmpl %esi, %edi
	jl .LC_ASAN_EX_4528
	callq __asan_report_load4@PLT
.LC_ASAN_EX_4528:
leaq -16(%rsp), %rsp
	popq %rsi
	popq %rdi
	movl %eax, -0xc(%rbp)
.LC11b3:
	jmp .L118f
.L11b8:
.LC11b8:
.LC_ASAN_ENTER_11b8: # 11b8: movq -8(%rbp), %rax: ['rax']
		pushq %rdi
leaq 8(%rsp), %rsp
	leaq -8(%rbp), %rdi
	movq %rdi, %rax
	shrq $3, %rax
	cmpb $0, 2147450880(%rax)
	je .LC_ASAN_EX_4536
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4536:
leaq -8(%rsp), %rsp
	popq %rdi
	movq -8(%rbp), %rax
.LC11bc:
	addq $0x10, %rsp
.LC11c0:
	popq %rbp
.LC11c1:
	retq 
.size func,.-func
	.text
.globl main
.type main, @function
main:
.L11d0:
.LC11d0:
	pushq %rbp
.LC11d1:
	movq %rsp, %rbp
.LC11d4:
	subq $0x20, %rsp
.LC11d8:
.LC_ASAN_ENTER_11d8: # 11d8: movl %edi, -4(%rbp): []
		pushq %rdi
	pushq %rsi
leaq 16(%rsp), %rsp
	leaq  -4(%rbp), %rdi
	movq %rdi, %rsi
	shrq $3, %rsi
	movb 2147450880(%rsi), %sil
	testb %sil, %sil
	je .LC_ASAN_EX_4568
	andl $7, %edi
	addl $3, %edi
	movsbl %sil, %esi
	cmpl %esi, %edi
	jl .LC_ASAN_EX_4568
	callq __asan_report_load4@PLT
.LC_ASAN_EX_4568:
leaq -16(%rsp), %rsp
	popq %rsi
	popq %rdi
	movl %edi, -4(%rbp)
.LC11db:
.LC_ASAN_ENTER_11db: # 11db: movq %rsi, -0x10(%rbp): []
		pushq %rdi
	pushq %rsi
leaq 16(%rsp), %rsp
	leaq  -0x10(%rbp), %rdi
	movq %rdi, %rsi
	shrq $3, %rsi
	cmpb $0, 2147450880(%rsi)
	je .LC_ASAN_EX_4571
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4571:
leaq -16(%rsp), %rsp
	popq %rsi
	popq %rdi
	movq %rsi, -0x10(%rbp)
.LC11df:
	callq .L1160
.LC11e4:
	leaq .LC2004(%rip), %rdi
.LC11eb:
	movq %rax, %rsi
.LC11ee:
	movb $0, %al
.LC11f0:
	callq printf@PLT
.LC11f5:
	xorl %ecx, %ecx
.LC11f7:
.LC_ASAN_ENTER_11f7: # 11f7: movl %eax, -0x14(%rbp): []
		pushq %rdi
	pushq %rsi
leaq 16(%rsp), %rsp
	leaq  -0x14(%rbp), %rdi
	movq %rdi, %rsi
	shrq $3, %rsi
	movb 2147450880(%rsi), %sil
	testb %sil, %sil
	je .LC_ASAN_EX_4599
	andl $7, %edi
	addl $3, %edi
	movsbl %sil, %esi
	cmpl %esi, %edi
	jl .LC_ASAN_EX_4599
	callq __asan_report_load4@PLT
.LC_ASAN_EX_4599:
leaq -16(%rsp), %rsp
	popq %rsi
	popq %rdi
	movl %eax, -0x14(%rbp)
.LC11fa:
	movl %ecx, %eax
.LC11fc:
	addq $0x20, %rsp
.LC1200:
	popq %rbp
.LC1201:
	retq 
.size main,.-main
	.text
.local asan.module_ctor
.type asan.module_ctor, @function
asan.module_ctor:
    .align    16, 0x90
# BB#0:
    pushq    %rax
.Ltmp11:
    callq    __asan_init@PLT
    popq    %rax
    retq
.size asan.module_ctor,.-asan.module_ctor
	.text
.local asan.module_dtor
.type asan.module_dtor, @function
asan.module_dtor:
    .align    16, 0x90
# BB#0:
    pushq    %rax
.Ltmp12:
    popq    %rax
    retq
.size asan.module_dtor,.-asan.module_dtor
