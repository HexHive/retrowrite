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
.type	_ZTS5Shape_2004,@object
.globl _ZTS5Shape_2004
_ZTS5Shape_2004: # 2004 -- 200b
.LC2004:
	.byte 0x35
.LC2005:
	.byte 0x53
.LC2006:
	.byte 0x68
.LC2007:
	.byte 0x61
.LC2008:
	.byte 0x70
.LC2009:
	.byte 0x65
.LC200a:
	.byte 0x0
.type	_ZTS9Rectangle_200b,@object
.globl _ZTS9Rectangle_200b
_ZTS9Rectangle_200b: # 200b -- 2016
.LC200b:
	.byte 0x39
.LC200c:
	.byte 0x52
.LC200d:
	.byte 0x65
.LC200e:
	.byte 0x63
.LC200f:
	.byte 0x74
.LC2010:
	.byte 0x61
.LC2011:
	.byte 0x6e
.LC2012:
	.byte 0x67
.LC2013:
	.byte 0x6c
.LC2014:
	.byte 0x65
.LC2015:
	.byte 0x0
.section .init_array
.align 8
	.quad asan.module_ctor
.section .data.rel.ro
.align 8
.type	_ZTV5Shape_3d70,@object
.globl _ZTV5Shape_3d70
_ZTV5Shape_3d70: # 3d70 -- 3d88
.LC3d70:
	.byte 0x0
.LC3d71:
	.byte 0x0
.LC3d72:
	.byte 0x0
.LC3d73:
	.byte 0x0
.LC3d74:
	.byte 0x0
.LC3d75:
	.byte 0x0
.LC3d76:
	.byte 0x0
.LC3d77:
	.byte 0x0
.LC3d78:
	.quad .LC3d88
.LC3d80:
	.quad .LC1280
.type	_ZTI5Shape_3d88,@object
.globl _ZTI5Shape_3d88
_ZTI5Shape_3d88: # 3d88 -- 3d98
.LC3d88:
	.byte 0x0
.LC3d89:
	.byte 0x0
.LC3d8a:
	.byte 0x0
.LC3d8b:
	.byte 0x0
.LC3d8c:
	.byte 0x0
.LC3d8d:
	.byte 0x0
.LC3d8e:
	.byte 0x0
.LC3d8f:
	.byte 0x0
.LC3d90:
	.quad .LC2004
.type	_ZTV9Rectangle_3d98,@object
.globl _ZTV9Rectangle_3d98
_ZTV9Rectangle_3d98: # 3d98 -- 3db0
.LC3d98:
	.byte 0x0
.LC3d99:
	.byte 0x0
.LC3d9a:
	.byte 0x0
.LC3d9b:
	.byte 0x0
.LC3d9c:
	.byte 0x0
.LC3d9d:
	.byte 0x0
.LC3d9e:
	.byte 0x0
.LC3d9f:
	.byte 0x0
.LC3da0:
	.quad .LC3db0
.LC3da8:
	.quad .LC1290
.type	_ZTI9Rectangle_3db0,@object
.globl _ZTI9Rectangle_3db0
_ZTI9Rectangle_3db0: # 3db0 -- 3dc8
.LC3db0:
	.byte 0x0
.LC3db1:
	.byte 0x0
.LC3db2:
	.byte 0x0
.LC3db3:
	.byte 0x0
.LC3db4:
	.byte 0x0
.LC3db5:
	.byte 0x0
.LC3db6:
	.byte 0x0
.LC3db7:
	.byte 0x0
.LC3db8:
	.quad .LC200b
.LC3dc0:
	.quad .LC3d88
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
.type	completed.8060_4040,@object
.globl completed.8060_4040
completed.8060_4040: # 4040 -- 4041
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
.globl main
.type main, @function
main:
.L1160:
.LC1160:
	pushq %rbp
.LC1161:
	movq %rsp, %rbp
.LC1164:
	subq $0x30, %rsp
.LC1168:
.LC_ASAN_ENTER_1168: # 1168: movl $0, -4(%rbp): []
		pushq %rdi
	pushq %rsi
leaq 16(%rsp), %rsp
	leaq  -4(%rbp), %rdi
	movq %rdi, %rsi
	shrq $3, %rsi
	movb 2147450880(%rsi), %sil
	testb %sil, %sil
	je .LC_ASAN_EX_4456
	andl $7, %edi
	addl $3, %edi
	movsbl %sil, %esi
	cmpl %esi, %edi
	jl .LC_ASAN_EX_4456
	callq __asan_report_load4@PLT
.LC_ASAN_EX_4456:
leaq -16(%rsp), %rsp
	popq %rsi
	popq %rdi
	movl $0, -4(%rbp)
.LC116f:
.LC_ASAN_ENTER_116f: # 116f: movl %edi, -8(%rbp): []
		pushq %rdi
	pushq %rsi
leaq 16(%rsp), %rsp
	leaq  -8(%rbp), %rdi
	movq %rdi, %rsi
	shrq $3, %rsi
	movb 2147450880(%rsi), %sil
	testb %sil, %sil
	je .LC_ASAN_EX_4463
	andl $7, %edi
	addl $3, %edi
	movsbl %sil, %esi
	cmpl %esi, %edi
	jl .LC_ASAN_EX_4463
	callq __asan_report_load4@PLT
.LC_ASAN_EX_4463:
leaq -16(%rsp), %rsp
	popq %rsi
	popq %rdi
	movl %edi, -8(%rbp)
.LC1172:
.LC_ASAN_ENTER_1172: # 1172: movq %rsi, -0x10(%rbp): ['rdi']
		pushq %rsi
leaq 8(%rsp), %rsp
	leaq  -0x10(%rbp), %rsi
	movq %rsi, %rdi
	shrq $3, %rdi
	cmpb $0, 2147450880(%rdi)
	je .LC_ASAN_EX_4466
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4466:
leaq -8(%rsp), %rsp
	popq %rsi
	movq %rsi, -0x10(%rbp)
.LC1176:
.LC_ASAN_ENTER_1176: # 1176: cmpl $0, -8(%rbp): ['rdi']
		pushq %rsi
leaq 8(%rsp), %rsp
	leaq  -8(%rbp), %rsi
	movq %rsi, %rdi
	shrq $3, %rdi
	movb 2147450880(%rdi), %dil
	testb %dil, %dil
	je .LC_ASAN_EX_4470
	andl $7, %esi
	addl $3, %esi
	movsbl %dil, %edi
	cmpl %edi, %esi
	jl .LC_ASAN_EX_4470
	callq __asan_report_load4@PLT
.LC_ASAN_EX_4470:
leaq -8(%rsp), %rsp
	popq %rsi
	cmpl $0, -8(%rbp)
.LC117a:
	jne .L11b6
.LC1180:
	movl $8, %edi
.LC1185:
	callq _Znwm@PLT
.LC118a:
	xorl %esi, %esi
.LC118c:
	movq %rax, %rcx
.LC118f:
	movq %rcx, %rdi
.LC1192:
	movl $8, %edx
.LC1197:
.LC_ASAN_ENTER_1197: # 1197: movq %rax, -0x20(%rbp): []
		pushq %rdi
	pushq %rsi
leaq 16(%rsp), %rsp
	leaq  -0x20(%rbp), %rdi
	movq %rdi, %rsi
	shrq $3, %rsi
	cmpb $0, 2147450880(%rsi)
	je .LC_ASAN_EX_4503
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4503:
leaq -16(%rsp), %rsp
	popq %rsi
	popq %rdi
	movq %rax, -0x20(%rbp)
.LC119b:
	callq memset@PLT
.LC11a0:
.LC_ASAN_ENTER_11a0: # 11a0: movq -0x20(%rbp), %rdi: ['rdi']
		pushq %rsi
leaq 8(%rsp), %rsp
	leaq -0x20(%rbp), %rsi
	movq %rsi, %rdi
	shrq $3, %rdi
	cmpb $0, 2147450880(%rdi)
	je .LC_ASAN_EX_4512
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4512:
leaq -8(%rsp), %rsp
	popq %rsi
	movq -0x20(%rbp), %rdi
.LC11a4:
	callq .L1220
.LC11a9:
.LC_ASAN_ENTER_11a9: # 11a9: movq -0x20(%rbp), %rax: ['rdi', 'rcx', 'rax']
		leaq -0x20(%rbp), %rcx
	movq %rcx, %rdi
	shrq $3, %rdi
	cmpb $0, 2147450880(%rdi)
	je .LC_ASAN_EX_4521
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4521:
	movq -0x20(%rbp), %rax
.LC11ad:
.LC_ASAN_ENTER_11ad: # 11ad: movq %rax, -0x18(%rbp): ['rdi', 'rcx']
		leaq  -0x18(%rbp), %rcx
	movq %rcx, %rdi
	shrq $3, %rdi
	cmpb $0, 2147450880(%rdi)
	je .LC_ASAN_EX_4525
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4525:
	movq %rax, -0x18(%rbp)
.LC11b1:
	jmp .L11e7
.L11b6:
.LC11b6:
	movl $8, %edi
.LC11bb:
	callq _Znwm@PLT
.LC11c0:
	xorl %esi, %esi
.LC11c2:
	movq %rax, %rcx
.LC11c5:
	movq %rcx, %rdi
.LC11c8:
	movl $8, %edx
.LC11cd:
.LC_ASAN_ENTER_11cd: # 11cd: movq %rax, -0x28(%rbp): []
		pushq %rdi
	pushq %rsi
leaq 16(%rsp), %rsp
	leaq  -0x28(%rbp), %rdi
	movq %rdi, %rsi
	shrq $3, %rsi
	cmpb $0, 2147450880(%rsi)
	je .LC_ASAN_EX_4557
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4557:
leaq -16(%rsp), %rsp
	popq %rsi
	popq %rdi
	movq %rax, -0x28(%rbp)
.LC11d1:
	callq memset@PLT
.LC11d6:
.LC_ASAN_ENTER_11d6: # 11d6: movq -0x28(%rbp), %rdi: ['rdi']
		pushq %rsi
leaq 8(%rsp), %rsp
	leaq -0x28(%rbp), %rsi
	movq %rsi, %rdi
	shrq $3, %rdi
	cmpb $0, 2147450880(%rdi)
	je .LC_ASAN_EX_4566
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4566:
leaq -8(%rsp), %rsp
	popq %rsi
	movq -0x28(%rbp), %rdi
.LC11da:
	callq .L1240
.LC11df:
.LC_ASAN_ENTER_11df: # 11df: movq -0x28(%rbp), %rax: ['rdi', 'rcx', 'rax']
		leaq -0x28(%rbp), %rcx
	movq %rcx, %rdi
	shrq $3, %rdi
	cmpb $0, 2147450880(%rdi)
	je .LC_ASAN_EX_4575
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4575:
	movq -0x28(%rbp), %rax
.LC11e3:
.LC_ASAN_ENTER_11e3: # 11e3: movq %rax, -0x18(%rbp): ['rdi', 'rcx']
		leaq  -0x18(%rbp), %rcx
	movq %rcx, %rdi
	shrq $3, %rdi
	cmpb $0, 2147450880(%rdi)
	je .LC_ASAN_EX_4579
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4579:
	movq %rax, -0x18(%rbp)
.L11e7:
.LC11e7:
.LC_ASAN_ENTER_11e7: # 11e7: movq -0x18(%rbp), %rax: ['rdi', 'rcx', 'rax']
		leaq -0x18(%rbp), %rcx
	movq %rcx, %rdi
	shrq $3, %rdi
	cmpb $0, 2147450880(%rdi)
	je .LC_ASAN_EX_4583
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4583:
	movq -0x18(%rbp), %rax
.LC11eb:
.LC_ASAN_ENTER_11eb: # 11eb: movq (%rax), %rcx: ['rdi', 'rcx']
		leaq (%rax), %rcx
	movq %rcx, %rdi
	shrq $3, %rdi
	cmpb $0, 2147450880(%rdi)
	je .LC_ASAN_EX_4587
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4587:
	movq (%rax), %rcx
.LC11ee:
	movq %rax, %rdi
.LC11f1:
.LC_ASAN_ENTER_11f1: # 11f1: callq *(%rcx): []
		pushq %rdi
	pushq %rsi
leaq 16(%rsp), %rsp
	leaq (%rcx), %rdi
	movq %rdi, %rsi
	shrq $3, %rsi
	cmpb $0, 2147450880(%rsi)
	je .LC_ASAN_EX_4593
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4593:
leaq -16(%rsp), %rsp
	popq %rsi
	popq %rdi
	callq *(%rcx)
.LC11f3:
.LC_ASAN_ENTER_11f3: # 11f3: movq -0x18(%rbp), %rax: ['rax']
		pushq %rdi
leaq 8(%rsp), %rsp
	leaq -0x18(%rbp), %rdi
	movq %rdi, %rax
	shrq $3, %rax
	cmpb $0, 2147450880(%rax)
	je .LC_ASAN_EX_4595
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4595:
leaq -8(%rsp), %rsp
	popq %rdi
	movq -0x18(%rbp), %rax
.LC11f7:
	cmpq $0, %rax
.LC11fb:
.LC_ASAN_ENTER_11fb: # 11fb: movq %rax, -0x30(%rbp): []
		pushq %rdi
	pushq %rsi
	pushf
leaq 24(%rsp), %rsp
	leaq  -0x30(%rbp), %rdi
	movq %rdi, %rsi
	shrq $3, %rsi
	cmpb $0, 2147450880(%rsi)
	je .LC_ASAN_EX_4603
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4603:
leaq -24(%rsp), %rsp
	popf
	popq %rsi
	popq %rdi
	movq %rax, -0x30(%rbp)
.LC11ff:
	je .L1211
.LC1205:
.LC_ASAN_ENTER_1205: # 1205: movq -0x30(%rbp), %rax: ['rdi', 'rax']
		leaq -0x30(%rbp), %rax
	movq %rax, %rdi
	shrq $3, %rdi
	cmpb $0, 2147450880(%rdi)
	je .LC_ASAN_EX_4613
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4613:
	movq -0x30(%rbp), %rax
.LC1209:
	movq %rax, %rdi
.LC120c:
	callq _ZdlPv@PLT
.L1211:
.LC1211:
.LC_ASAN_ENTER_1211: # 1211: movl -4(%rbp), %eax: ['rax']
		pushq %rdi
leaq 8(%rsp), %rsp
	leaq -4(%rbp), %rdi
	movq %rdi, %rax
	shrq $3, %rax
	movb 2147450880(%rax), %al
	testb %al, %al
	je .LC_ASAN_EX_4625
	andl $7, %edi
	addl $3, %edi
	movsbl %al, %eax
	cmpl %eax, %edi
	jl .LC_ASAN_EX_4625
	callq __asan_report_load4@PLT
.LC_ASAN_EX_4625:
leaq -8(%rsp), %rsp
	popq %rdi
	movl -4(%rbp), %eax
.LC1214:
	addq $0x30, %rsp
.LC1218:
	popq %rbp
.LC1219:
	retq 
.size main,.-main
	.text
.local _ZN5ShapeC2Ev
.type _ZN5ShapeC2Ev, @function
_ZN5ShapeC2Ev:
.L1220:
.LC1220:
	pushq %rbp
.LC1221:
	movq %rsp, %rbp
.LC1224:
	leaq .LC3d70(%rip), %rax
.LC122b:
	addq $0x10, %rax
.LC1231:
.LC_ASAN_ENTER_1231: # 1231: movq %rdi, -8(%rbp): ['rcx']
		pushq %rdi
leaq 8(%rsp), %rsp
	leaq  -8(%rbp), %rdi
	movq %rdi, %rcx
	shrq $3, %rcx
	cmpb $0, 2147450880(%rcx)
	je .LC_ASAN_EX_4657
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4657:
leaq -8(%rsp), %rsp
	popq %rdi
	movq %rdi, -8(%rbp)
.LC1235:
.LC_ASAN_ENTER_1235: # 1235: movq -8(%rbp), %rcx: ['rcx']
		pushq %rdi
leaq 8(%rsp), %rsp
	leaq -8(%rbp), %rdi
	movq %rdi, %rcx
	shrq $3, %rcx
	cmpb $0, 2147450880(%rcx)
	je .LC_ASAN_EX_4661
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4661:
leaq -8(%rsp), %rsp
	popq %rdi
	movq -8(%rbp), %rcx
.LC1239:
.LC_ASAN_ENTER_1239: # 1239: movq %rax, (%rcx): ['rbp']
		pushq %rdi
leaq 8(%rsp), %rsp
	leaq  (%rcx), %rdi
	movq %rdi, %rbp
	shrq $3, %rbp
	cmpb $0, 2147450880(%rbp)
	je .LC_ASAN_EX_4665
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4665:
leaq -8(%rsp), %rsp
	popq %rdi
	movq %rax, (%rcx)
.LC123c:
	popq %rbp
.LC123d:
	retq 
.size _ZN5ShapeC2Ev,.-_ZN5ShapeC2Ev
	.text
.local _ZN9RectangleC2Ev
.type _ZN9RectangleC2Ev, @function
_ZN9RectangleC2Ev:
.L1240:
.LC1240:
	pushq %rbp
.LC1241:
	movq %rsp, %rbp
.LC1244:
	subq $0x10, %rsp
.LC1248:
.LC_ASAN_ENTER_1248: # 1248: movq %rdi, -8(%rbp): ['rcx', 'rax']
		leaq  -8(%rbp), %rax
	movq %rax, %rcx
	shrq $3, %rcx
	cmpb $0, 2147450880(%rcx)
	je .LC_ASAN_EX_4680
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4680:
	movq %rdi, -8(%rbp)
.LC124c:
.LC_ASAN_ENTER_124c: # 124c: movq -8(%rbp), %rax: ['rdi', 'rcx', 'rax']
		leaq -8(%rbp), %rcx
	movq %rcx, %rdi
	shrq $3, %rdi
	cmpb $0, 2147450880(%rdi)
	je .LC_ASAN_EX_4684
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4684:
	movq -8(%rbp), %rax
.LC1250:
	movq %rax, %rcx
.LC1253:
	movq %rcx, %rdi
.LC1256:
.LC_ASAN_ENTER_1256: # 1256: movq %rax, -0x10(%rbp): []
		pushq %rdi
	pushq %rsi
leaq 16(%rsp), %rsp
	leaq  -0x10(%rbp), %rdi
	movq %rdi, %rsi
	shrq $3, %rsi
	cmpb $0, 2147450880(%rsi)
	je .LC_ASAN_EX_4694
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4694:
leaq -16(%rsp), %rsp
	popq %rsi
	popq %rdi
	movq %rax, -0x10(%rbp)
.LC125a:
	callq .L1220
.LC125f:
	leaq .LC3d98(%rip), %rax
.LC1266:
	addq $0x10, %rax
.LC126c:
.LC_ASAN_ENTER_126c: # 126c: movq -0x10(%rbp), %rcx: ['rcx']
		pushq %rdi
leaq 8(%rsp), %rsp
	leaq -0x10(%rbp), %rdi
	movq %rdi, %rcx
	shrq $3, %rcx
	cmpb $0, 2147450880(%rcx)
	je .LC_ASAN_EX_4716
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4716:
leaq -8(%rsp), %rsp
	popq %rdi
	movq -0x10(%rbp), %rcx
.LC1270:
.LC_ASAN_ENTER_1270: # 1270: movq %rax, (%rcx): ['rbp']
		pushq %rdi
leaq 8(%rsp), %rsp
	leaq  (%rcx), %rdi
	movq %rdi, %rbp
	shrq $3, %rbp
	cmpb $0, 2147450880(%rbp)
	je .LC_ASAN_EX_4720
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4720:
leaq -8(%rsp), %rsp
	popq %rdi
	movq %rax, (%rcx)
.LC1273:
	addq $0x10, %rsp
.LC1277:
	popq %rbp
.LC1278:
	retq 
.size _ZN9RectangleC2Ev,.-_ZN9RectangleC2Ev
	.text
.local _ZN5Shape4drawEv
.type _ZN5Shape4drawEv, @function
_ZN5Shape4drawEv:
.L1280:
.LC1280:
	pushq %rbp
.LC1281:
	movq %rsp, %rbp
.LC1284:
.LC_ASAN_ENTER_1284: # 1284: movq %rdi, -8(%rbp): []
		pushq %rdi
	pushq %rsi
leaq 16(%rsp), %rsp
	leaq  -8(%rbp), %rdi
	movq %rdi, %rsi
	shrq $3, %rsi
	cmpb $0, 2147450880(%rsi)
	je .LC_ASAN_EX_4740
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4740:
leaq -16(%rsp), %rsp
	popq %rsi
	popq %rdi
	movq %rdi, -8(%rbp)
.LC1288:
	popq %rbp
.LC1289:
	retq 
.size _ZN5Shape4drawEv,.-_ZN5Shape4drawEv
	.text
.local _ZN9Rectangle4drawEv
.type _ZN9Rectangle4drawEv, @function
_ZN9Rectangle4drawEv:
.L1290:
.LC1290:
	pushq %rbp
.LC1291:
	movq %rsp, %rbp
.LC1294:
.LC_ASAN_ENTER_1294: # 1294: movq %rdi, -8(%rbp): []
		pushq %rdi
	pushq %rsi
leaq 16(%rsp), %rsp
	leaq  -8(%rbp), %rdi
	movq %rdi, %rsi
	shrq $3, %rsi
	cmpb $0, 2147450880(%rsi)
	je .LC_ASAN_EX_4756
	callq __asan_report_load8@PLT
.LC_ASAN_EX_4756:
leaq -16(%rsp), %rsp
	popq %rsi
	popq %rdi
	movq %rdi, -8(%rbp)
.LC1298:
	popq %rbp
.LC1299:
	retq 
.size _ZN9Rectangle4drawEv,.-_ZN9Rectangle4drawEv
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
