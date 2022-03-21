	.file	"exception.cpp"
	.text
	.section	.rodata
	.type	_ZStL19piecewise_construct, @object
	.size	_ZStL19piecewise_construct, 1
_ZStL19piecewise_construct:
	.zero	1
	.local	_ZStL8__ioinit
	.comm	_ZStL8__ioinit,1,1
	.section	.text._ZN13ExceptionCodeC2Ei,"axG",@progbits,_ZN13ExceptionCodeC5Ei,comdat
	.align 2
	.weak	_ZN13ExceptionCodeC2Ei
	.type	_ZN13ExceptionCodeC2Ei, @function
_ZN13ExceptionCodeC2Ei:
.LFB1752:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	movl	%esi, -12(%rbp)
	movq	-8(%rbp), %rax
	movl	-12(%rbp), %edx
	movl	%edx, (%rax)
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1752:
	.size	_ZN13ExceptionCodeC2Ei, .-_ZN13ExceptionCodeC2Ei
	.weak	_ZN13ExceptionCodeC1Ei
	.set	_ZN13ExceptionCodeC1Ei,_ZN13ExceptionCodeC2Ei
	.section	.text._ZN17ShapeProgramErrorC2EiPKc,"axG",@progbits,_ZN17ShapeProgramErrorC5EiPKc,comdat
	.align 2
	.weak	_ZN17ShapeProgramErrorC2EiPKc
	.type	_ZN17ShapeProgramErrorC2EiPKc, @function
_ZN17ShapeProgramErrorC2EiPKc:
.LFB1756:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$32, %rsp
	movq	%rdi, -8(%rbp)
	movl	%esi, -12(%rbp)
	movq	%rdx, -24(%rbp)
	movq	-8(%rbp), %rax
	movq	-24(%rbp), %rdx
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	_ZNSt13runtime_errorC2EPKc@PLT
	movq	-8(%rbp), %rax
	leaq	16(%rax), %rdx
	movl	-12(%rbp), %eax
	movl	%eax, %esi
	movq	%rdx, %rdi
	call	_ZN13ExceptionCodeC2Ei
	leaq	16+_ZTV17ShapeProgramError(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1756:
	.size	_ZN17ShapeProgramErrorC2EiPKc, .-_ZN17ShapeProgramErrorC2EiPKc
	.weak	_ZN17ShapeProgramErrorC1EiPKc
	.set	_ZN17ShapeProgramErrorC1EiPKc,_ZN17ShapeProgramErrorC2EiPKc
	.section	.rodata
.LC0:
	.string	"ERROR CODE %d: %s"
	.section	.text._ZNK17ShapeProgramError4whatEv,"axG",@progbits,_ZNK17ShapeProgramError4whatEv,comdat
	.align 2
	.weak	_ZNK17ShapeProgramError4whatEv
	.type	_ZNK17ShapeProgramError4whatEv, @function
_ZNK17ShapeProgramError4whatEv:
.LFB1758:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZNKSt13runtime_error4whatEv@PLT
	movq	%rax, %rdx
	movq	-8(%rbp), %rax
	movl	16(%rax), %eax
	movq	-8(%rbp), %rcx
	leaq	20(%rcx), %rdi
	movq	%rdx, %r8
	movl	%eax, %ecx
	leaq	.LC0(%rip), %rdx
	movl	$1025, %esi
	movl	$0, %eax
	call	snprintf@PLT
	movq	-8(%rbp), %rax
	addq	$20, %rax
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1758:
	.size	_ZNK17ShapeProgramError4whatEv, .-_ZNK17ShapeProgramError4whatEv
	.section	.text._ZN6ObjectC2Ev,"axG",@progbits,_ZN6ObjectC5Ev,comdat
	.align 2
	.weak	_ZN6ObjectC2Ev
	.type	_ZN6ObjectC2Ev, @function
_ZN6ObjectC2Ev:
.LFB1760:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	leaq	16+_ZTV6Object(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1760:
	.size	_ZN6ObjectC2Ev, .-_ZN6ObjectC2Ev
	.weak	_ZN6ObjectC1Ev
	.set	_ZN6ObjectC1Ev,_ZN6ObjectC2Ev
	.section	.rodata
.LC1:
	.string	"Object name is too large"
	.section	.text._ZN6Object8set_nameEPKc,"axG",@progbits,_ZN6Object8set_nameEPKc,comdat
	.align 2
	.weak	_ZN6Object8set_nameEPKc
	.type	_ZN6Object8set_nameEPKc, @function
_ZN6Object8set_nameEPKc:
.LFB1762:
	.cfi_startproc
	.cfi_personality 0x9b,DW.ref.__gxx_personality_v0
	.cfi_lsda 0x1b,.LLSDA1762
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%r12
	pushq	%rbx
	subq	$32, %rsp
	.cfi_offset 12, -24
	.cfi_offset 3, -32
	movq	%rdi, -40(%rbp)
	movq	%rsi, -48(%rbp)
	movq	-48(%rbp), %rax
	movq	%rax, %rdi
	call	strlen@PLT
	movq	%rax, -24(%rbp)
	cmpq	$255, -24(%rbp)
	jbe	.L7
	movl	$1048, %edi
	call	__cxa_allocate_exception@PLT
	movq	%rax, %rbx
	leaq	.LC1(%rip), %rdx
	movl	$101, %esi
	movq	%rbx, %rdi
.LEHB0:
	call	_ZN17ShapeProgramErrorC1EiPKc
.LEHE0:
	leaq	_ZN17ShapeProgramErrorD1Ev(%rip), %rdx
	leaq	_ZTI17ShapeProgramError(%rip), %rsi
	movq	%rbx, %rdi
.LEHB1:
	call	__cxa_throw@PLT
.L7:
	movq	-24(%rbp), %rax
	addq	$1, %rax
	movl	$1, %esi
	movq	%rax, %rdi
	call	calloc@PLT
	movq	%rax, %rdx
	movq	-40(%rbp), %rax
	movq	%rdx, 8(%rax)
	movq	-40(%rbp), %rax
	movq	8(%rax), %rax
	movq	-48(%rbp), %rdx
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	strcpy@PLT
	jmp	.L10
.L9:
	endbr64
	movq	%rax, %r12
	movq	%rbx, %rdi
	call	__cxa_free_exception@PLT
	movq	%r12, %rax
	movq	%rax, %rdi
	call	_Unwind_Resume@PLT
.LEHE1:
.L10:
	addq	$32, %rsp
	popq	%rbx
	popq	%r12
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1762:
	.globl	__gxx_personality_v0
	.section	.gcc_except_table._ZN6Object8set_nameEPKc,"aG",@progbits,_ZN6Object8set_nameEPKc,comdat
.LLSDA1762:
	.byte	0xff
	.byte	0xff
	.byte	0x1
	.uleb128 .LLSDACSE1762-.LLSDACSB1762
.LLSDACSB1762:
	.uleb128 .LEHB0-.LFB1762
	.uleb128 .LEHE0-.LEHB0
	.uleb128 .L9-.LFB1762
	.uleb128 0
	.uleb128 .LEHB1-.LFB1762
	.uleb128 .LEHE1-.LEHB1
	.uleb128 0
	.uleb128 0
.LLSDACSE1762:
	.section	.text._ZN6Object8set_nameEPKc,"axG",@progbits,_ZN6Object8set_nameEPKc,comdat
	.size	_ZN6Object8set_nameEPKc, .-_ZN6Object8set_nameEPKc
	.section	.text._ZN6ObjectD2Ev,"axG",@progbits,_ZN6ObjectD5Ev,comdat
	.align 2
	.weak	_ZN6ObjectD2Ev
	.type	_ZN6ObjectD2Ev, @function
_ZN6ObjectD2Ev:
.LFB1767:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	leaq	16+_ZTV6Object(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	movq	-8(%rbp), %rax
	movq	8(%rax), %rax
	testq	%rax, %rax
	je	.L13
	movq	-8(%rbp), %rax
	movq	8(%rax), %rax
	movq	%rax, %rdi
	call	free@PLT
	movq	-8(%rbp), %rax
	movq	$0, 8(%rax)
.L13:
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1767:
	.size	_ZN6ObjectD2Ev, .-_ZN6ObjectD2Ev
	.weak	_ZN6ObjectD1Ev
	.set	_ZN6ObjectD1Ev,_ZN6ObjectD2Ev
	.section	.text._ZN6ObjectD0Ev,"axG",@progbits,_ZN6ObjectD5Ev,comdat
	.align 2
	.weak	_ZN6ObjectD0Ev
	.type	_ZN6ObjectD0Ev, @function
_ZN6ObjectD0Ev:
.LFB1769:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN6ObjectD1Ev
	movq	-8(%rbp), %rax
	movl	$16, %esi
	movq	%rax, %rdi
	call	_ZdlPvm@PLT
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1769:
	.size	_ZN6ObjectD0Ev, .-_ZN6ObjectD0Ev
	.section	.text._ZN6Object4nameEv,"axG",@progbits,_ZN6Object4nameEv,comdat
	.align 2
	.weak	_ZN6Object4nameEv
	.type	_ZN6Object4nameEv, @function
_ZN6Object4nameEv:
.LFB1770:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movq	8(%rax), %rax
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1770:
	.size	_ZN6Object4nameEv, .-_ZN6Object4nameEv
	.section	.text._ZN11RegularNGonC2Ei,"axG",@progbits,_ZN11RegularNGonC5Ei,comdat
	.align 2
	.weak	_ZN11RegularNGonC2Ei
	.type	_ZN11RegularNGonC2Ei, @function
_ZN11RegularNGonC2Ei:
.LFB1772:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	movl	%esi, -12(%rbp)
	leaq	16+_ZTV11RegularNGon(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	movq	-8(%rbp), %rax
	movl	-12(%rbp), %edx
	movl	%edx, 8(%rax)
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1772:
	.size	_ZN11RegularNGonC2Ei, .-_ZN11RegularNGonC2Ei
	.weak	_ZN11RegularNGonC1Ei
	.set	_ZN11RegularNGonC1Ei,_ZN11RegularNGonC2Ei
	.section	.text._ZN11RegularNGonD2Ev,"axG",@progbits,_ZN11RegularNGonD5Ev,comdat
	.align 2
	.weak	_ZN11RegularNGonD2Ev
	.type	_ZN11RegularNGonD2Ev, @function
_ZN11RegularNGonD2Ev:
.LFB1775:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	leaq	16+_ZTV11RegularNGon(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1775:
	.size	_ZN11RegularNGonD2Ev, .-_ZN11RegularNGonD2Ev
	.weak	_ZN11RegularNGonD1Ev
	.set	_ZN11RegularNGonD1Ev,_ZN11RegularNGonD2Ev
	.section	.text._ZN11RegularNGonD0Ev,"axG",@progbits,_ZN11RegularNGonD5Ev,comdat
	.align 2
	.weak	_ZN11RegularNGonD0Ev
	.type	_ZN11RegularNGonD0Ev, @function
_ZN11RegularNGonD0Ev:
.LFB1777:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN11RegularNGonD1Ev
	movq	-8(%rbp), %rax
	movl	$16, %esi
	movq	%rax, %rdi
	call	_ZdlPvm@PLT
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1777:
	.size	_ZN11RegularNGonD0Ev, .-_ZN11RegularNGonD0Ev
	.section	.text._ZN5ShapeC2Ev,"axG",@progbits,_ZN5ShapeC5Ev,comdat
	.align 2
	.weak	_ZN5ShapeC2Ev
	.type	_ZN5ShapeC2Ev, @function
_ZN5ShapeC2Ev:
.LFB1779:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN6ObjectC2Ev
	leaq	16+_ZTV5Shape(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1779:
	.size	_ZN5ShapeC2Ev, .-_ZN5ShapeC2Ev
	.weak	_ZN5ShapeC1Ev
	.set	_ZN5ShapeC1Ev,_ZN5ShapeC2Ev
	.section	.text._ZN5ShapeD2Ev,"axG",@progbits,_ZN5ShapeD5Ev,comdat
	.align 2
	.weak	_ZN5ShapeD2Ev
	.type	_ZN5ShapeD2Ev, @function
_ZN5ShapeD2Ev:
.LFB1782:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	leaq	16+_ZTV5Shape(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN6ObjectD2Ev
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1782:
	.size	_ZN5ShapeD2Ev, .-_ZN5ShapeD2Ev
	.weak	_ZN5ShapeD1Ev
	.set	_ZN5ShapeD1Ev,_ZN5ShapeD2Ev
	.section	.text._ZN5ShapeD0Ev,"axG",@progbits,_ZN5ShapeD5Ev,comdat
	.align 2
	.weak	_ZN5ShapeD0Ev
	.type	_ZN5ShapeD0Ev, @function
_ZN5ShapeD0Ev:
.LFB1784:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN5ShapeD1Ev
	movq	-8(%rbp), %rax
	movl	$16, %esi
	movq	%rax, %rdi
	call	_ZdlPvm@PLT
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1784:
	.size	_ZN5ShapeD0Ev, .-_ZN5ShapeD0Ev
	.section	.text._ZN13ParallelogramC2Eii,"axG",@progbits,_ZN13ParallelogramC5Eii,comdat
	.align 2
	.weak	_ZN13ParallelogramC2Eii
	.type	_ZN13ParallelogramC2Eii, @function
_ZN13ParallelogramC2Eii:
.LFB1786:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movl	%esi, -12(%rbp)
	movl	%edx, -16(%rbp)
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN5ShapeC2Ev
	leaq	16+_ZTV13Parallelogram(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	movq	-8(%rbp), %rax
	movl	-12(%rbp), %edx
	movl	%edx, 16(%rax)
	movq	-8(%rbp), %rax
	movl	-16(%rbp), %edx
	movl	%edx, 20(%rax)
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1786:
	.size	_ZN13ParallelogramC2Eii, .-_ZN13ParallelogramC2Eii
	.weak	_ZN13ParallelogramC1Eii
	.set	_ZN13ParallelogramC1Eii,_ZN13ParallelogramC2Eii
	.section	.text._ZN13ParallelogramD2Ev,"axG",@progbits,_ZN13ParallelogramD5Ev,comdat
	.align 2
	.weak	_ZN13ParallelogramD2Ev
	.type	_ZN13ParallelogramD2Ev, @function
_ZN13ParallelogramD2Ev:
.LFB1789:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	leaq	16+_ZTV13Parallelogram(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN5ShapeD2Ev
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1789:
	.size	_ZN13ParallelogramD2Ev, .-_ZN13ParallelogramD2Ev
	.weak	_ZN13ParallelogramD1Ev
	.set	_ZN13ParallelogramD1Ev,_ZN13ParallelogramD2Ev
	.section	.text._ZN13ParallelogramD0Ev,"axG",@progbits,_ZN13ParallelogramD5Ev,comdat
	.align 2
	.weak	_ZN13ParallelogramD0Ev
	.type	_ZN13ParallelogramD0Ev, @function
_ZN13ParallelogramD0Ev:
.LFB1791:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN13ParallelogramD1Ev
	movq	-8(%rbp), %rax
	movl	$24, %esi
	movq	%rax, %rdi
	call	_ZdlPvm@PLT
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1791:
	.size	_ZN13ParallelogramD0Ev, .-_ZN13ParallelogramD0Ev
	.section	.text._ZN13Parallelogram4areaEv,"axG",@progbits,_ZN13Parallelogram4areaEv,comdat
	.align 2
	.weak	_ZN13Parallelogram4areaEv
	.type	_ZN13Parallelogram4areaEv, @function
_ZN13Parallelogram4areaEv:
.LFB1792:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movl	16(%rax), %edx
	movq	-8(%rbp), %rax
	movl	20(%rax), %eax
	imull	%edx, %eax
	cvtsi2sdl	%eax, %xmm0
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1792:
	.size	_ZN13Parallelogram4areaEv, .-_ZN13Parallelogram4areaEv
	.section	.text._ZN13Parallelogram13circumferenceEv,"axG",@progbits,_ZN13Parallelogram13circumferenceEv,comdat
	.align 2
	.weak	_ZN13Parallelogram13circumferenceEv
	.type	_ZN13Parallelogram13circumferenceEv, @function
_ZN13Parallelogram13circumferenceEv:
.LFB1793:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movl	16(%rax), %edx
	movq	-8(%rbp), %rax
	movl	20(%rax), %eax
	addl	%edx, %eax
	addl	%eax, %eax
	cvtsi2sdl	%eax, %xmm0
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1793:
	.size	_ZN13Parallelogram13circumferenceEv, .-_ZN13Parallelogram13circumferenceEv
	.section	.text._ZN9RectangleC2Eii,"axG",@progbits,_ZN9RectangleC5Eii,comdat
	.align 2
	.weak	_ZN9RectangleC2Eii
	.type	_ZN9RectangleC2Eii, @function
_ZN9RectangleC2Eii:
.LFB1795:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movl	%esi, -12(%rbp)
	movl	%edx, -16(%rbp)
	movq	-8(%rbp), %rax
	movl	-16(%rbp), %edx
	movl	-12(%rbp), %ecx
	movl	%ecx, %esi
	movq	%rax, %rdi
	call	_ZN13ParallelogramC2Eii
	leaq	16+_ZTV9Rectangle(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1795:
	.size	_ZN9RectangleC2Eii, .-_ZN9RectangleC2Eii
	.weak	_ZN9RectangleC1Eii
	.set	_ZN9RectangleC1Eii,_ZN9RectangleC2Eii
	.section	.text._ZN9RectangleD2Ev,"axG",@progbits,_ZN9RectangleD5Ev,comdat
	.align 2
	.weak	_ZN9RectangleD2Ev
	.type	_ZN9RectangleD2Ev, @function
_ZN9RectangleD2Ev:
.LFB1798:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	leaq	16+_ZTV9Rectangle(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN13ParallelogramD2Ev
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1798:
	.size	_ZN9RectangleD2Ev, .-_ZN9RectangleD2Ev
	.weak	_ZN9RectangleD1Ev
	.set	_ZN9RectangleD1Ev,_ZN9RectangleD2Ev
	.section	.text._ZN9RectangleD0Ev,"axG",@progbits,_ZN9RectangleD5Ev,comdat
	.align 2
	.weak	_ZN9RectangleD0Ev
	.type	_ZN9RectangleD0Ev, @function
_ZN9RectangleD0Ev:
.LFB1800:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN9RectangleD1Ev
	movq	-8(%rbp), %rax
	movl	$24, %esi
	movq	%rax, %rdi
	call	_ZdlPvm@PLT
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1800:
	.size	_ZN9RectangleD0Ev, .-_ZN9RectangleD0Ev
	.section	.text._ZN6SquareC2Ei,"axG",@progbits,_ZN6SquareC5Ei,comdat
	.align 2
	.weak	_ZN6SquareC2Ei
	.type	_ZN6SquareC2Ei, @function
_ZN6SquareC2Ei:
.LFB1802:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movl	%esi, -12(%rbp)
	movq	-8(%rbp), %rax
	movl	-12(%rbp), %edx
	movl	-12(%rbp), %ecx
	movl	%ecx, %esi
	movq	%rax, %rdi
	call	_ZN9RectangleC2Eii
	movq	-8(%rbp), %rax
	addq	$24, %rax
	movl	$4, %esi
	movq	%rax, %rdi
	call	_ZN11RegularNGonC2Ei
	leaq	16+_ZTV6Square(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	leaq	64+_ZTV6Square(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, 24(%rax)
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1802:
	.size	_ZN6SquareC2Ei, .-_ZN6SquareC2Ei
	.weak	_ZN6SquareC1Ei
	.set	_ZN6SquareC1Ei,_ZN6SquareC2Ei
	.section	.text._ZN6SquareD2Ev,"axG",@progbits,_ZN6SquareD5Ev,comdat
	.align 2
	.weak	_ZN6SquareD2Ev
	.type	_ZN6SquareD2Ev, @function
_ZN6SquareD2Ev:
.LFB1805:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	leaq	16+_ZTV6Square(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	leaq	64+_ZTV6Square(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, 24(%rax)
	movq	-8(%rbp), %rax
	addq	$24, %rax
	movq	%rax, %rdi
	call	_ZN11RegularNGonD2Ev
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN9RectangleD2Ev
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1805:
	.size	_ZN6SquareD2Ev, .-_ZN6SquareD2Ev
	.set	.LTHUNK0,_ZN6SquareD2Ev
	.weak	_ZThn24_N6SquareD1Ev
	.type	_ZThn24_N6SquareD1Ev, @function
_ZThn24_N6SquareD1Ev:
.LFB2339:
	.cfi_startproc
	endbr64
	subq	$24, %rdi
	jmp	.LTHUNK0
	.cfi_endproc
.LFE2339:
	.size	_ZThn24_N6SquareD1Ev, .-_ZThn24_N6SquareD1Ev
	.weak	_ZN6SquareD1Ev
	.set	_ZN6SquareD1Ev,_ZN6SquareD2Ev
	.section	.text._ZN6SquareD0Ev,"axG",@progbits,_ZN6SquareD5Ev,comdat
	.align 2
	.weak	_ZN6SquareD0Ev
	.type	_ZN6SquareD0Ev, @function
_ZN6SquareD0Ev:
.LFB1807:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN6SquareD1Ev
	movq	-8(%rbp), %rax
	movl	$40, %esi
	movq	%rax, %rdi
	call	_ZdlPvm@PLT
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1807:
	.size	_ZN6SquareD0Ev, .-_ZN6SquareD0Ev
	.set	.LTHUNK1,_ZN6SquareD0Ev
	.weak	_ZThn24_N6SquareD0Ev
	.type	_ZThn24_N6SquareD0Ev, @function
_ZThn24_N6SquareD0Ev:
.LFB2340:
	.cfi_startproc
	endbr64
	subq	$24, %rdi
	jmp	.LTHUNK1
	.cfi_endproc
.LFE2340:
	.size	_ZThn24_N6SquareD0Ev, .-_ZThn24_N6SquareD0Ev
	.section	.text._ZN6Square13circumferenceEv,"axG",@progbits,_ZN6Square13circumferenceEv,comdat
	.align 2
	.weak	_ZN6Square13circumferenceEv
	.type	_ZN6Square13circumferenceEv, @function
_ZN6Square13circumferenceEv:
.LFB1808:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movl	32(%rax), %edx
	movq	-8(%rbp), %rax
	movl	16(%rax), %eax
	imull	%edx, %eax
	cvtsi2sdl	%eax, %xmm0
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1808:
	.size	_ZN6Square13circumferenceEv, .-_ZN6Square13circumferenceEv
	.section	.text._ZN8TriangleC2Eii,"axG",@progbits,_ZN8TriangleC5Eii,comdat
	.align 2
	.weak	_ZN8TriangleC2Eii
	.type	_ZN8TriangleC2Eii, @function
_ZN8TriangleC2Eii:
.LFB1810:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movl	%esi, -12(%rbp)
	movl	%edx, -16(%rbp)
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN5ShapeC2Ev
	movq	-8(%rbp), %rax
	addq	$16, %rax
	movl	$3, %esi
	movq	%rax, %rdi
	call	_ZN11RegularNGonC2Ei
	leaq	16+_ZTV8Triangle(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	leaq	64+_ZTV8Triangle(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, 16(%rax)
	movq	-8(%rbp), %rax
	movl	-12(%rbp), %edx
	movl	%edx, 28(%rax)
	movq	-8(%rbp), %rax
	movl	-16(%rbp), %edx
	movl	%edx, 32(%rax)
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1810:
	.size	_ZN8TriangleC2Eii, .-_ZN8TriangleC2Eii
	.weak	_ZN8TriangleC1Eii
	.set	_ZN8TriangleC1Eii,_ZN8TriangleC2Eii
	.section	.text._ZN8TriangleD2Ev,"axG",@progbits,_ZN8TriangleD5Ev,comdat
	.align 2
	.weak	_ZN8TriangleD2Ev
	.type	_ZN8TriangleD2Ev, @function
_ZN8TriangleD2Ev:
.LFB1813:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	leaq	16+_ZTV8Triangle(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	leaq	64+_ZTV8Triangle(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, 16(%rax)
	movq	-8(%rbp), %rax
	addq	$16, %rax
	movq	%rax, %rdi
	call	_ZN11RegularNGonD2Ev
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN5ShapeD2Ev
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1813:
	.size	_ZN8TriangleD2Ev, .-_ZN8TriangleD2Ev
	.set	.LTHUNK2,_ZN8TriangleD2Ev
	.weak	_ZThn16_N8TriangleD1Ev
	.type	_ZThn16_N8TriangleD1Ev, @function
_ZThn16_N8TriangleD1Ev:
.LFB2341:
	.cfi_startproc
	endbr64
	subq	$16, %rdi
	jmp	.LTHUNK2
	.cfi_endproc
.LFE2341:
	.size	_ZThn16_N8TriangleD1Ev, .-_ZThn16_N8TriangleD1Ev
	.weak	_ZN8TriangleD1Ev
	.set	_ZN8TriangleD1Ev,_ZN8TriangleD2Ev
	.section	.text._ZN8TriangleD0Ev,"axG",@progbits,_ZN8TriangleD5Ev,comdat
	.align 2
	.weak	_ZN8TriangleD0Ev
	.type	_ZN8TriangleD0Ev, @function
_ZN8TriangleD0Ev:
.LFB1815:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN8TriangleD1Ev
	movq	-8(%rbp), %rax
	movl	$40, %esi
	movq	%rax, %rdi
	call	_ZdlPvm@PLT
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1815:
	.size	_ZN8TriangleD0Ev, .-_ZN8TriangleD0Ev
	.set	.LTHUNK3,_ZN8TriangleD0Ev
	.weak	_ZThn16_N8TriangleD0Ev
	.type	_ZThn16_N8TriangleD0Ev, @function
_ZThn16_N8TriangleD0Ev:
.LFB2342:
	.cfi_startproc
	endbr64
	subq	$16, %rdi
	jmp	.LTHUNK3
	.cfi_endproc
.LFE2342:
	.size	_ZThn16_N8TriangleD0Ev, .-_ZThn16_N8TriangleD0Ev
	.section	.text._ZN8Triangle4areaEv,"axG",@progbits,_ZN8Triangle4areaEv,comdat
	.align 2
	.weak	_ZN8Triangle4areaEv
	.type	_ZN8Triangle4areaEv, @function
_ZN8Triangle4areaEv:
.LFB1816:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movl	28(%rax), %eax
	cvtsi2sdl	%eax, %xmm1
	movsd	.LC2(%rip), %xmm0
	mulsd	%xmm0, %xmm1
	movq	-8(%rbp), %rax
	movl	32(%rax), %eax
	cvtsi2sdl	%eax, %xmm0
	mulsd	%xmm1, %xmm0
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1816:
	.size	_ZN8Triangle4areaEv, .-_ZN8Triangle4areaEv
	.section	.rodata
.LC3:
	.string	"TEST TEST TEST!"
	.section	.text._ZN8Triangle13circumferenceEv,"axG",@progbits,_ZN8Triangle13circumferenceEv,comdat
	.align 2
	.weak	_ZN8Triangle13circumferenceEv
	.type	_ZN8Triangle13circumferenceEv, @function
_ZN8Triangle13circumferenceEv:
.LFB1817:
	.cfi_startproc
	.cfi_personality 0x9b,DW.ref.__gxx_personality_v0
	.cfi_lsda 0x1b,.LLSDA1817
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%r12
	pushq	%rbx
	subq	$16, %rsp
	.cfi_offset 12, -24
	.cfi_offset 3, -32
	movq	%rdi, -24(%rbp)
	movl	$1048, %edi
	call	__cxa_allocate_exception@PLT
	movq	%rax, %rbx
	leaq	.LC3(%rip), %rdx
	movl	$100, %esi
	movq	%rbx, %rdi
.LEHB2:
	call	_ZN17ShapeProgramErrorC1EiPKc
.LEHE2:
	leaq	_ZN17ShapeProgramErrorD1Ev(%rip), %rdx
	leaq	_ZTI17ShapeProgramError(%rip), %rsi
	movq	%rbx, %rdi
.LEHB3:
	call	__cxa_throw@PLT
.L45:
	endbr64
	movq	%rax, %r12
	movq	%rbx, %rdi
	call	__cxa_free_exception@PLT
	movq	%r12, %rax
	movq	%rax, %rdi
	call	_Unwind_Resume@PLT
.LEHE3:
	.cfi_endproc
.LFE1817:
	.section	.gcc_except_table._ZN8Triangle13circumferenceEv,"aG",@progbits,_ZN8Triangle13circumferenceEv,comdat
.LLSDA1817:
	.byte	0xff
	.byte	0xff
	.byte	0x1
	.uleb128 .LLSDACSE1817-.LLSDACSB1817
.LLSDACSB1817:
	.uleb128 .LEHB2-.LFB1817
	.uleb128 .LEHE2-.LEHB2
	.uleb128 .L45-.LFB1817
	.uleb128 0
	.uleb128 .LEHB3-.LFB1817
	.uleb128 .LEHE3-.LEHB3
	.uleb128 0
	.uleb128 0
.LLSDACSE1817:
	.section	.text._ZN8Triangle13circumferenceEv,"axG",@progbits,_ZN8Triangle13circumferenceEv,comdat
	.size	_ZN8Triangle13circumferenceEv, .-_ZN8Triangle13circumferenceEv
	.section	.text._ZN6CircleC2Ei,"axG",@progbits,_ZN6CircleC5Ei,comdat
	.align 2
	.weak	_ZN6CircleC2Ei
	.type	_ZN6CircleC2Ei, @function
_ZN6CircleC2Ei:
.LFB1819:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movl	%esi, -12(%rbp)
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN5ShapeC2Ev
	leaq	16+_ZTV6Circle(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	movq	-8(%rbp), %rax
	movl	-12(%rbp), %edx
	movl	%edx, 16(%rax)
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1819:
	.size	_ZN6CircleC2Ei, .-_ZN6CircleC2Ei
	.weak	_ZN6CircleC1Ei
	.set	_ZN6CircleC1Ei,_ZN6CircleC2Ei
	.section	.text._ZN6CircleD2Ev,"axG",@progbits,_ZN6CircleD5Ev,comdat
	.align 2
	.weak	_ZN6CircleD2Ev
	.type	_ZN6CircleD2Ev, @function
_ZN6CircleD2Ev:
.LFB1822:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	leaq	16+_ZTV6Circle(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN5ShapeD2Ev
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1822:
	.size	_ZN6CircleD2Ev, .-_ZN6CircleD2Ev
	.weak	_ZN6CircleD1Ev
	.set	_ZN6CircleD1Ev,_ZN6CircleD2Ev
	.section	.text._ZN6CircleD0Ev,"axG",@progbits,_ZN6CircleD5Ev,comdat
	.align 2
	.weak	_ZN6CircleD0Ev
	.type	_ZN6CircleD0Ev, @function
_ZN6CircleD0Ev:
.LFB1824:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN6CircleD1Ev
	movq	-8(%rbp), %rax
	movl	$24, %esi
	movq	%rax, %rdi
	call	_ZdlPvm@PLT
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1824:
	.size	_ZN6CircleD0Ev, .-_ZN6CircleD0Ev
	.section	.text._ZN6Circle4areaEv,"axG",@progbits,_ZN6Circle4areaEv,comdat
	.align 2
	.weak	_ZN6Circle4areaEv
	.type	_ZN6Circle4areaEv, @function
_ZN6Circle4areaEv:
.LFB1825:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	pxor	%xmm0, %xmm0
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1825:
	.size	_ZN6Circle4areaEv, .-_ZN6Circle4areaEv
	.section	.text._ZN6Circle13circumferenceEv,"axG",@progbits,_ZN6Circle13circumferenceEv,comdat
	.align 2
	.weak	_ZN6Circle13circumferenceEv
	.type	_ZN6Circle13circumferenceEv, @function
_ZN6Circle13circumferenceEv:
.LFB1826:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movl	16(%rax), %eax
	addl	%eax, %eax
	cvtsi2sdl	%eax, %xmm1
	movsd	.LC5(%rip), %xmm0
	mulsd	%xmm1, %xmm0
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1826:
	.size	_ZN6Circle13circumferenceEv, .-_ZN6Circle13circumferenceEv
	.section	.text._ZN8PentagonC2Ei,"axG",@progbits,_ZN8PentagonC5Ei,comdat
	.align 2
	.weak	_ZN8PentagonC2Ei
	.type	_ZN8PentagonC2Ei, @function
_ZN8PentagonC2Ei:
.LFB1828:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movl	%esi, -12(%rbp)
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN5ShapeC2Ev
	movq	-8(%rbp), %rax
	addq	$16, %rax
	movl	$1, %esi
	movq	%rax, %rdi
	call	_ZN11RegularNGonC2Ei
	leaq	16+_ZTV8Pentagon(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	leaq	64+_ZTV8Pentagon(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, 16(%rax)
	movq	-8(%rbp), %rax
	movl	-12(%rbp), %edx
	movl	%edx, 28(%rax)
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1828:
	.size	_ZN8PentagonC2Ei, .-_ZN8PentagonC2Ei
	.weak	_ZN8PentagonC1Ei
	.set	_ZN8PentagonC1Ei,_ZN8PentagonC2Ei
	.section	.text._ZN8PentagonD2Ev,"axG",@progbits,_ZN8PentagonD5Ev,comdat
	.align 2
	.weak	_ZN8PentagonD2Ev
	.type	_ZN8PentagonD2Ev, @function
_ZN8PentagonD2Ev:
.LFB1831:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	leaq	16+_ZTV8Pentagon(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	leaq	64+_ZTV8Pentagon(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, 16(%rax)
	movq	-8(%rbp), %rax
	addq	$16, %rax
	movq	%rax, %rdi
	call	_ZN11RegularNGonD2Ev
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN5ShapeD2Ev
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1831:
	.size	_ZN8PentagonD2Ev, .-_ZN8PentagonD2Ev
	.set	.LTHUNK4,_ZN8PentagonD2Ev
	.weak	_ZThn16_N8PentagonD1Ev
	.type	_ZThn16_N8PentagonD1Ev, @function
_ZThn16_N8PentagonD1Ev:
.LFB2343:
	.cfi_startproc
	endbr64
	subq	$16, %rdi
	jmp	.LTHUNK4
	.cfi_endproc
.LFE2343:
	.size	_ZThn16_N8PentagonD1Ev, .-_ZThn16_N8PentagonD1Ev
	.weak	_ZN8PentagonD1Ev
	.set	_ZN8PentagonD1Ev,_ZN8PentagonD2Ev
	.section	.text._ZN8PentagonD0Ev,"axG",@progbits,_ZN8PentagonD5Ev,comdat
	.align 2
	.weak	_ZN8PentagonD0Ev
	.type	_ZN8PentagonD0Ev, @function
_ZN8PentagonD0Ev:
.LFB1833:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN8PentagonD1Ev
	movq	-8(%rbp), %rax
	movl	$32, %esi
	movq	%rax, %rdi
	call	_ZdlPvm@PLT
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1833:
	.size	_ZN8PentagonD0Ev, .-_ZN8PentagonD0Ev
	.set	.LTHUNK5,_ZN8PentagonD0Ev
	.weak	_ZThn16_N8PentagonD0Ev
	.type	_ZThn16_N8PentagonD0Ev, @function
_ZThn16_N8PentagonD0Ev:
.LFB2344:
	.cfi_startproc
	endbr64
	subq	$16, %rdi
	jmp	.LTHUNK5
	.cfi_endproc
.LFE2344:
	.size	_ZThn16_N8PentagonD0Ev, .-_ZThn16_N8PentagonD0Ev
	.section	.text._ZSt4sqrtIiEN9__gnu_cxx11__enable_ifIXsrSt12__is_integerIT_E7__valueEdE6__typeES3_,"axG",@progbits,_ZSt4sqrtIiEN9__gnu_cxx11__enable_ifIXsrSt12__is_integerIT_E7__valueEdE6__typeES3_,comdat
	.weak	_ZSt4sqrtIiEN9__gnu_cxx11__enable_ifIXsrSt12__is_integerIT_E7__valueEdE6__typeES3_
	.type	_ZSt4sqrtIiEN9__gnu_cxx11__enable_ifIXsrSt12__is_integerIT_E7__valueEdE6__typeES3_, @function
_ZSt4sqrtIiEN9__gnu_cxx11__enable_ifIXsrSt12__is_integerIT_E7__valueEdE6__typeES3_:
.LFB1838:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movl	%edi, -4(%rbp)
	cvtsi2sdl	-4(%rbp), %xmm0
	call	sqrt@PLT
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1838:
	.size	_ZSt4sqrtIiEN9__gnu_cxx11__enable_ifIXsrSt12__is_integerIT_E7__valueEdE6__typeES3_, .-_ZSt4sqrtIiEN9__gnu_cxx11__enable_ifIXsrSt12__is_integerIT_E7__valueEdE6__typeES3_
	.section	.rodata
.LC6:
	.string	"n should be 5 for a pentagon"
	.section	.text._ZN8Pentagon4areaEv,"axG",@progbits,_ZN8Pentagon4areaEv,comdat
	.align 2
	.weak	_ZN8Pentagon4areaEv
	.type	_ZN8Pentagon4areaEv, @function
_ZN8Pentagon4areaEv:
.LFB1834:
	.cfi_startproc
	.cfi_personality 0x9b,DW.ref.__gxx_personality_v0
	.cfi_lsda 0x1b,.LLSDA1834
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%r12
	pushq	%rbx
	subq	$32, %rsp
	.cfi_offset 12, -24
	.cfi_offset 3, -32
	movq	%rdi, -24(%rbp)
	movq	-24(%rbp), %rax
	movl	24(%rax), %eax
	cmpl	$1, %eax
	jne	.L59
	movl	$16, %edi
	call	__cxa_allocate_exception@PLT
	movq	%rax, %rbx
	leaq	.LC6(%rip), %rsi
	movq	%rbx, %rdi
.LEHB4:
	call	_ZNSt16invalid_argumentC1EPKc@PLT
.LEHE4:
	movq	_ZNSt16invalid_argumentD1Ev@GOTPCREL(%rip), %rax
	movq	%rax, %rdx
	leaq	_ZTISt16invalid_argument(%rip), %rsi
	movq	%rbx, %rdi
.LEHB5:
	call	__cxa_throw@PLT
.L59:
	movq	-24(%rbp), %rax
	movl	24(%rax), %eax
	leal	-1(%rax), %ecx
	movl	$1, %eax
	cltd
	idivl	%ecx
	cvtsi2sdl	%eax, %xmm2
	movsd	%xmm2, -32(%rbp)
	movq	-24(%rbp), %rax
	movl	24(%rax), %eax
	cvtsi2sdl	%eax, %xmm3
	movsd	%xmm3, -40(%rbp)
	movq	-24(%rbp), %rax
	movl	24(%rax), %eax
	cvtsi2sdl	%eax, %xmm4
	movsd	%xmm4, -48(%rbp)
	movl	$5, %edi
	call	_ZSt4sqrtIiEN9__gnu_cxx11__enable_ifIXsrSt12__is_integerIT_E7__valueEdE6__typeES3_
	addsd	%xmm0, %xmm0
	addsd	-48(%rbp), %xmm0
	mulsd	-40(%rbp), %xmm0
	call	sqrt@PLT
	mulsd	-32(%rbp), %xmm0
	movsd	%xmm0, -32(%rbp)
	movq	-24(%rbp), %rax
	movl	28(%rax), %eax
	movl	$2, %esi
	movl	%eax, %edi
	call	_ZSt3powIiiEN9__gnu_cxx11__promote_2IT_T0_NS0_9__promoteIS2_XsrSt12__is_integerIS2_E7__valueEE6__typeENS4_IS3_XsrS5_IS3_E7__valueEE6__typeEE6__typeES2_S3_
	mulsd	-32(%rbp), %xmm0
	jmp	.L63
.L62:
	endbr64
	movq	%rax, %r12
	movq	%rbx, %rdi
	call	__cxa_free_exception@PLT
	movq	%r12, %rax
	movq	%rax, %rdi
	call	_Unwind_Resume@PLT
.LEHE5:
.L63:
	addq	$32, %rsp
	popq	%rbx
	popq	%r12
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1834:
	.section	.gcc_except_table._ZN8Pentagon4areaEv,"aG",@progbits,_ZN8Pentagon4areaEv,comdat
.LLSDA1834:
	.byte	0xff
	.byte	0xff
	.byte	0x1
	.uleb128 .LLSDACSE1834-.LLSDACSB1834
.LLSDACSB1834:
	.uleb128 .LEHB4-.LFB1834
	.uleb128 .LEHE4-.LEHB4
	.uleb128 .L62-.LFB1834
	.uleb128 0
	.uleb128 .LEHB5-.LFB1834
	.uleb128 .LEHE5-.LEHB5
	.uleb128 0
	.uleb128 0
.LLSDACSE1834:
	.section	.text._ZN8Pentagon4areaEv,"axG",@progbits,_ZN8Pentagon4areaEv,comdat
	.size	_ZN8Pentagon4areaEv, .-_ZN8Pentagon4areaEv
	.section	.text._ZN8Pentagon13circumferenceEv,"axG",@progbits,_ZN8Pentagon13circumferenceEv,comdat
	.align 2
	.weak	_ZN8Pentagon13circumferenceEv
	.type	_ZN8Pentagon13circumferenceEv, @function
_ZN8Pentagon13circumferenceEv:
.LFB1839:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movl	24(%rax), %edx
	movq	-8(%rbp), %rax
	movl	28(%rax), %eax
	imull	%edx, %eax
	cvtsi2sdl	%eax, %xmm0
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1839:
	.size	_ZN8Pentagon13circumferenceEv, .-_ZN8Pentagon13circumferenceEv
	.section	.text._ZN7HexagonC2Ei,"axG",@progbits,_ZN7HexagonC5Ei,comdat
	.align 2
	.weak	_ZN7HexagonC2Ei
	.type	_ZN7HexagonC2Ei, @function
_ZN7HexagonC2Ei:
.LFB1841:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movl	%esi, -12(%rbp)
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN5ShapeC2Ev
	movq	-8(%rbp), %rax
	addq	$16, %rax
	movl	$6, %esi
	movq	%rax, %rdi
	call	_ZN11RegularNGonC2Ei
	leaq	16+_ZTV7Hexagon(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	leaq	64+_ZTV7Hexagon(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, 16(%rax)
	movq	-8(%rbp), %rax
	movl	-12(%rbp), %edx
	movl	%edx, 28(%rax)
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1841:
	.size	_ZN7HexagonC2Ei, .-_ZN7HexagonC2Ei
	.weak	_ZN7HexagonC1Ei
	.set	_ZN7HexagonC1Ei,_ZN7HexagonC2Ei
	.section	.text._ZN7HexagonD2Ev,"axG",@progbits,_ZN7HexagonD5Ev,comdat
	.align 2
	.weak	_ZN7HexagonD2Ev
	.type	_ZN7HexagonD2Ev, @function
_ZN7HexagonD2Ev:
.LFB1844:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	leaq	16+_ZTV7Hexagon(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	leaq	64+_ZTV7Hexagon(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, 16(%rax)
	movq	-8(%rbp), %rax
	addq	$16, %rax
	movq	%rax, %rdi
	call	_ZN11RegularNGonD2Ev
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN5ShapeD2Ev
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1844:
	.size	_ZN7HexagonD2Ev, .-_ZN7HexagonD2Ev
	.set	.LTHUNK6,_ZN7HexagonD2Ev
	.weak	_ZThn16_N7HexagonD1Ev
	.type	_ZThn16_N7HexagonD1Ev, @function
_ZThn16_N7HexagonD1Ev:
.LFB2345:
	.cfi_startproc
	endbr64
	subq	$16, %rdi
	jmp	.LTHUNK6
	.cfi_endproc
.LFE2345:
	.size	_ZThn16_N7HexagonD1Ev, .-_ZThn16_N7HexagonD1Ev
	.weak	_ZN7HexagonD1Ev
	.set	_ZN7HexagonD1Ev,_ZN7HexagonD2Ev
	.section	.text._ZN7HexagonD0Ev,"axG",@progbits,_ZN7HexagonD5Ev,comdat
	.align 2
	.weak	_ZN7HexagonD0Ev
	.type	_ZN7HexagonD0Ev, @function
_ZN7HexagonD0Ev:
.LFB1846:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN7HexagonD1Ev
	movq	-8(%rbp), %rax
	movl	$32, %esi
	movq	%rax, %rdi
	call	_ZdlPvm@PLT
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1846:
	.size	_ZN7HexagonD0Ev, .-_ZN7HexagonD0Ev
	.set	.LTHUNK7,_ZN7HexagonD0Ev
	.weak	_ZThn16_N7HexagonD0Ev
	.type	_ZThn16_N7HexagonD0Ev, @function
_ZThn16_N7HexagonD0Ev:
.LFB2346:
	.cfi_startproc
	endbr64
	subq	$16, %rdi
	jmp	.LTHUNK7
	.cfi_endproc
.LFE2346:
	.size	_ZThn16_N7HexagonD0Ev, .-_ZThn16_N7HexagonD0Ev
	.section	.text._ZN7Hexagon4areaEv,"axG",@progbits,_ZN7Hexagon4areaEv,comdat
	.align 2
	.weak	_ZN7Hexagon4areaEv
	.type	_ZN7Hexagon4areaEv, @function
_ZN7Hexagon4areaEv:
.LFB1847:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$32, %rsp
	movq	%rdi, -24(%rbp)
	movq	-24(%rbp), %rax
	movl	28(%rax), %eax
	movl	$2, %esi
	movl	%eax, %edi
	call	_ZSt3powIiiEN9__gnu_cxx11__promote_2IT_T0_NS0_9__promoteIS2_XsrSt12__is_integerIS2_E7__valueEE6__typeENS4_IS3_XsrS5_IS3_E7__valueEE6__typeEE6__typeES2_S3_
	movsd	.LC7(%rip), %xmm1
	mulsd	%xmm1, %xmm0
	movsd	%xmm0, -8(%rbp)
	movsd	-8(%rbp), %xmm0
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1847:
	.size	_ZN7Hexagon4areaEv, .-_ZN7Hexagon4areaEv
	.section	.text._ZN7Hexagon13circumferenceEv,"axG",@progbits,_ZN7Hexagon13circumferenceEv,comdat
	.align 2
	.weak	_ZN7Hexagon13circumferenceEv
	.type	_ZN7Hexagon13circumferenceEv, @function
_ZN7Hexagon13circumferenceEv:
.LFB1848:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movl	24(%rax), %edx
	movq	-8(%rbp), %rax
	movl	28(%rax), %eax
	imull	%edx, %eax
	cvtsi2sdl	%eax, %xmm0
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1848:
	.size	_ZN7Hexagon13circumferenceEv, .-_ZN7Hexagon13circumferenceEv
	.section	.rodata
.LC8:
	.string	"Circle"
.LC9:
	.string	"Rectangle"
.LC10:
	.string	"Parallelogram"
.LC11:
	.string	"Square"
.LC12:
	.string	"Triangle"
	.align 8
.LC13:
	.ascii	"Hex"
	.string	"agonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagonHexagon"
.LC14:
	.string	"Pentagon"
.LC15:
	.string	"Unknown Shape Type"
	.text
	.globl	_Z11createshapec
	.type	_Z11createshapec, @function
_Z11createshapec:
.LFB1849:
	.cfi_startproc
	.cfi_personality 0x9b,DW.ref.__gxx_personality_v0
	.cfi_lsda 0x1b,.LLSDA1849
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%r12
	pushq	%rbx
	subq	$32, %rsp
	.cfi_offset 12, -24
	.cfi_offset 3, -32
	movl	%edi, %eax
	movb	%al, -36(%rbp)
	movsbl	-36(%rbp), %eax
	subl	$67, %eax
	cmpl	$17, %eax
	ja	.L74
	movl	%eax, %eax
	leaq	0(,%rax,4), %rdx
	leaq	.L76(%rip), %rax
	movl	(%rdx,%rax), %eax
	cltq
	leaq	.L76(%rip), %rdx
	addq	%rdx, %rax
	notrack jmp	*%rax
	.section	.rodata
	.align 4
	.align 4
.L76:
	.long	.L82-.L76
	.long	.L74-.L76
	.long	.L74-.L76
	.long	.L74-.L76
	.long	.L81-.L76
	.long	.L80-.L76
	.long	.L74-.L76
	.long	.L74-.L76
	.long	.L74-.L76
	.long	.L74-.L76
	.long	.L74-.L76
	.long	.L74-.L76
	.long	.L74-.L76
	.long	.L79-.L76
	.long	.L74-.L76
	.long	.L78-.L76
	.long	.L77-.L76
	.long	.L75-.L76
	.text
.L82:
	movl	$24, %edi
.LEHB6:
	call	_Znwm@PLT
	movq	%rax, %rbx
	movl	$4, %esi
	movq	%rbx, %rdi
	call	_ZN6CircleC1Ei
	movq	%rbx, -24(%rbp)
	movq	-24(%rbp), %rax
	leaq	.LC8(%rip), %rsi
	movq	%rax, %rdi
	call	_ZN6Object8set_nameEPKc
	jmp	.L83
.L78:
	movl	$24, %edi
	call	_Znwm@PLT
	movq	%rax, %rbx
	movl	$10, %edx
	movl	$6, %esi
	movq	%rbx, %rdi
	call	_ZN9RectangleC1Eii
	movq	%rbx, -24(%rbp)
	movq	-24(%rbp), %rax
	leaq	.LC9(%rip), %rsi
	movq	%rax, %rdi
	call	_ZN6Object8set_nameEPKc
	jmp	.L83
.L79:
	movl	$24, %edi
	call	_Znwm@PLT
	movq	%rax, %rbx
	movl	$9, %edx
	movl	$5, %esi
	movq	%rbx, %rdi
	call	_ZN13ParallelogramC1Eii
	movq	%rbx, -24(%rbp)
	movq	-24(%rbp), %rax
	leaq	.LC10(%rip), %rsi
	movq	%rax, %rdi
	call	_ZN6Object8set_nameEPKc
	jmp	.L83
.L77:
	movl	$40, %edi
	call	_Znwm@PLT
	movq	%rax, %rbx
	movl	$10, %esi
	movq	%rbx, %rdi
	call	_ZN6SquareC1Ei
	movq	%rbx, -24(%rbp)
	movq	-24(%rbp), %rax
	leaq	.LC11(%rip), %rsi
	movq	%rax, %rdi
	call	_ZN6Object8set_nameEPKc
	jmp	.L83
.L75:
	movl	$40, %edi
	call	_Znwm@PLT
	movq	%rax, %rbx
	movl	$9, %edx
	movl	$5, %esi
	movq	%rbx, %rdi
	call	_ZN8TriangleC1Eii
	movq	%rbx, -24(%rbp)
	movq	-24(%rbp), %rax
	leaq	.LC12(%rip), %rsi
	movq	%rax, %rdi
	call	_ZN6Object8set_nameEPKc
	jmp	.L83
.L80:
	movl	$32, %edi
	call	_Znwm@PLT
	movq	%rax, %rbx
	movl	$200, %esi
	movq	%rbx, %rdi
	call	_ZN7HexagonC1Ei
	movq	%rbx, -24(%rbp)
	movq	-24(%rbp), %rax
	leaq	.LC13(%rip), %rsi
	movq	%rax, %rdi
	call	_ZN6Object8set_nameEPKc
	jmp	.L83
.L81:
	movl	$32, %edi
	call	_Znwm@PLT
	movq	%rax, %rbx
	movl	$2, %esi
	movq	%rbx, %rdi
	call	_ZN8PentagonC1Ei
	movq	%rbx, -24(%rbp)
	movq	-24(%rbp), %rax
	leaq	.LC14(%rip), %rsi
	movq	%rax, %rdi
	call	_ZN6Object8set_nameEPKc
.LEHE6:
	jmp	.L83
.L74:
	movl	$1048, %edi
	call	__cxa_allocate_exception@PLT
	movq	%rax, %rbx
	leaq	.LC15(%rip), %rdx
	movl	$102, %esi
	movq	%rbx, %rdi
.LEHB7:
	call	_ZN17ShapeProgramErrorC1EiPKc
.LEHE7:
	leaq	_ZN17ShapeProgramErrorD1Ev(%rip), %rdx
	leaq	_ZTI17ShapeProgramError(%rip), %rsi
	movq	%rbx, %rdi
.LEHB8:
	call	__cxa_throw@PLT
.L83:
	movq	-24(%rbp), %rax
	jmp	.L87
.L86:
	endbr64
	movq	%rax, %r12
	movq	%rbx, %rdi
	call	__cxa_free_exception@PLT
	movq	%r12, %rax
	movq	%rax, %rdi
	call	_Unwind_Resume@PLT
.LEHE8:
.L87:
	addq	$32, %rsp
	popq	%rbx
	popq	%r12
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1849:
	.section	.gcc_except_table,"a",@progbits
.LLSDA1849:
	.byte	0xff
	.byte	0xff
	.byte	0x1
	.uleb128 .LLSDACSE1849-.LLSDACSB1849
.LLSDACSB1849:
	.uleb128 .LEHB6-.LFB1849
	.uleb128 .LEHE6-.LEHB6
	.uleb128 0
	.uleb128 0
	.uleb128 .LEHB7-.LFB1849
	.uleb128 .LEHE7-.LEHB7
	.uleb128 .L86-.LFB1849
	.uleb128 0
	.uleb128 .LEHB8-.LFB1849
	.uleb128 .LEHE8-.LEHB8
	.uleb128 0
	.uleb128 0
.LLSDACSE1849:
	.text
	.size	_Z11createshapec, .-_Z11createshapec
	.section	.rodata
	.align 8
.LC16:
	.string	"Area of %s is %f, Circumference of shape is %f\n"
.LC17:
	.string	"%s"
	.align 8
.LC18:
	.string	"THIS IS A BUG IN OUR CODING. PLEASE REPORT THIS ON CI IF YOU SPOT IT."
	.text
	.globl	_Z14printshapedataP5Shape
	.type	_Z14printshapedataP5Shape, @function
_Z14printshapedataP5Shape:
.LFB1850:
	.cfi_startproc
	.cfi_personality 0x9b,DW.ref.__gxx_personality_v0
	.cfi_lsda 0x1b,.LLSDA1850
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%rbx
	subq	$72, %rsp
	.cfi_offset 3, -24
	movq	%rdi, -72(%rbp)
	movq	-72(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN6Object4nameEv
	movq	%rax, -64(%rbp)
	movq	-72(%rbp), %rax
	movq	(%rax), %rax
	addq	$16, %rax
	movq	(%rax), %rdx
	movq	-72(%rbp), %rax
	movq	%rax, %rdi
.LEHB9:
	call	*%rdx
	movq	%xmm0, %rax
	movq	%rax, -56(%rbp)
	movq	-72(%rbp), %rax
	movq	(%rax), %rax
	addq	$24, %rax
	movq	(%rax), %rdx
	movq	-72(%rbp), %rax
	movq	%rax, %rdi
	call	*%rdx
	movq	%xmm0, %rax
	movq	%rax, -48(%rbp)
	movsd	-48(%rbp), %xmm0
	movq	-56(%rbp), %rdx
	movq	-64(%rbp), %rax
	movapd	%xmm0, %xmm1
	movq	%rdx, %xmm0
	movq	%rax, %rsi
	leaq	.LC16(%rip), %rdi
	movl	$2, %eax
	call	printf@PLT
.LEHE9:
	jmp	.L88
.L98:
	endbr64
	cmpq	$3, %rdx
	je	.L90
	cmpq	$3, %rdx
	jg	.L91
	cmpq	$1, %rdx
	je	.L92
	cmpq	$2, %rdx
	je	.L93
.L91:
	movq	%rax, %rdi
.LEHB10:
	call	_Unwind_Resume@PLT
.LEHE10:
.L92:
	movq	%rax, %rdi
	call	__cxa_begin_catch@PLT
	movq	%rax, -24(%rbp)
	movq	-24(%rbp), %rax
	movq	(%rax), %rax
	addq	$16, %rax
	movq	(%rax), %rdx
	movq	-24(%rbp), %rax
	movq	%rax, %rdi
	call	*%rdx
	movq	%rax, %rsi
	leaq	.LC17(%rip), %rdi
	movl	$0, %eax
.LEHB11:
	call	printf@PLT
.LEHE11:
.LEHB12:
	call	__cxa_end_catch@PLT
.LEHE12:
	jmp	.L88
.L93:
	movq	%rax, %rdi
	call	__cxa_begin_catch@PLT
	movq	%rax, -32(%rbp)
	leaq	.LC18(%rip), %rdi
.LEHB13:
	call	puts@PLT
	movq	-32(%rbp), %rax
	movq	(%rax), %rax
	addq	$16, %rax
	movq	(%rax), %rdx
	movq	-32(%rbp), %rax
	movq	%rax, %rdi
	call	*%rdx
	movq	%rax, %rsi
	leaq	.LC17(%rip), %rdi
	movl	$0, %eax
	call	printf@PLT
.LEHE13:
	call	__cxa_end_catch@PLT
	jmp	.L88
.L90:
	movq	%rax, %rdi
	call	__cxa_begin_catch@PLT
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rax
	movq	(%rax), %rax
	addq	$16, %rax
	movq	(%rax), %rdx
	movq	-40(%rbp), %rax
	movq	%rax, %rdi
	call	*%rdx
	movq	%rax, %rsi
	leaq	.LC17(%rip), %rdi
	movl	$0, %eax
.LEHB14:
	call	printf@PLT
.LEHE14:
	call	__cxa_end_catch@PLT
	jmp	.L88
.L99:
	endbr64
	movq	%rax, %rbx
	call	__cxa_end_catch@PLT
	movq	%rbx, %rax
	movq	%rax, %rdi
.LEHB15:
	call	_Unwind_Resume@PLT
.L100:
	endbr64
	movq	%rax, %rbx
	call	__cxa_end_catch@PLT
	movq	%rbx, %rax
	movq	%rax, %rdi
	call	_Unwind_Resume@PLT
.L101:
	endbr64
	movq	%rax, %rbx
	call	__cxa_end_catch@PLT
	movq	%rbx, %rax
	movq	%rax, %rdi
	call	_Unwind_Resume@PLT
.LEHE15:
.L88:
	addq	$72, %rsp
	popq	%rbx
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1850:
	.section	.gcc_except_table
	.align 4
.LLSDA1850:
	.byte	0xff
	.byte	0x9b
	.uleb128 .LLSDATT1850-.LLSDATTD1850
.LLSDATTD1850:
	.byte	0x1
	.uleb128 .LLSDACSE1850-.LLSDACSB1850
.LLSDACSB1850:
	.uleb128 .LEHB9-.LFB1850
	.uleb128 .LEHE9-.LEHB9
	.uleb128 .L98-.LFB1850
	.uleb128 0x5
	.uleb128 .LEHB10-.LFB1850
	.uleb128 .LEHE10-.LEHB10
	.uleb128 0
	.uleb128 0
	.uleb128 .LEHB11-.LFB1850
	.uleb128 .LEHE11-.LEHB11
	.uleb128 .L99-.LFB1850
	.uleb128 0
	.uleb128 .LEHB12-.LFB1850
	.uleb128 .LEHE12-.LEHB12
	.uleb128 0
	.uleb128 0
	.uleb128 .LEHB13-.LFB1850
	.uleb128 .LEHE13-.LEHB13
	.uleb128 .L100-.LFB1850
	.uleb128 0
	.uleb128 .LEHB14-.LFB1850
	.uleb128 .LEHE14-.LEHB14
	.uleb128 .L101-.LFB1850
	.uleb128 0
	.uleb128 .LEHB15-.LFB1850
	.uleb128 .LEHE15-.LEHB15
	.uleb128 0
	.uleb128 0
.LLSDACSE1850:
	.byte	0x3
	.byte	0
	.byte	0x2
	.byte	0x7d
	.byte	0x1
	.byte	0x7d
	.align 4
	.long	DW.ref._ZTISt9exception-.
	.long	DW.ref._ZTISt11logic_error-.
	.long	DW.ref._ZTI17ShapeProgramError-.
.LLSDATT1850:
	.text
	.size	_Z14printshapedataP5Shape, .-_Z14printshapedataP5Shape
	.section	.rodata
	.align 8
.LC19:
	.string	"Not enough arguments. Specify one letter."
	.align 8
.LC20:
	.string	"Please pick a single letter argument."
	.text
	.globl	main
	.type	main, @function
main:
.LFB1851:
	.cfi_startproc
	.cfi_personality 0x9b,DW.ref.__gxx_personality_v0
	.cfi_lsda 0x1b,.LLSDA1851
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%rbx
	subq	$56, %rsp
	.cfi_offset 3, -24
	movl	%edi, -52(%rbp)
	movq	%rsi, -64(%rbp)
	movq	$0, -40(%rbp)
	cmpl	$2, -52(%rbp)
	je	.L103
	leaq	.LC19(%rip), %rdi
.LEHB16:
	call	puts@PLT
	movl	$-1, %eax
	jmp	.L118
.L103:
	movq	-64(%rbp), %rax
	addq	$8, %rax
	movq	(%rax), %rax
	movq	%rax, %rdi
	call	strlen@PLT
	cmpq	$1, %rax
	je	.L105
	leaq	.LC20(%rip), %rdi
	call	puts@PLT
.LEHE16:
	movl	$-1, %eax
	jmp	.L118
.L105:
	movq	-64(%rbp), %rax
	addq	$8, %rax
	movq	(%rax), %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
	movl	%eax, %edi
.LEHB17:
	call	_Z11createshapec
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rax
	movq	%rax, %rdi
	call	_Z14printshapedataP5Shape
.LEHE17:
.L114:
	cmpq	$0, -40(%rbp)
	je	.L106
	movq	-40(%rbp), %rax
	testq	%rax, %rax
	je	.L107
	movq	(%rax), %rdx
	addq	$8, %rdx
	movq	(%rdx), %rdx
	movq	%rax, %rdi
	call	*%rdx
.L107:
	movq	$0, -40(%rbp)
.L106:
	movl	$0, %eax
	jmp	.L118
.L116:
	endbr64
	cmpq	$1, %rdx
	je	.L109
	movq	%rax, %rdi
.LEHB18:
	call	_Unwind_Resume@PLT
.LEHE18:
.L109:
	movq	%rax, %rdi
	call	__cxa_begin_catch@PLT
	movq	%rax, -32(%rbp)
	cmpq	$0, -32(%rbp)
	je	.L110
	movq	-32(%rbp), %rax
	movl	$0, %ecx
	leaq	_ZTI17ShapeProgramError(%rip), %rdx
	leaq	_ZTISt13runtime_error(%rip), %rsi
	movq	%rax, %rdi
	call	__dynamic_cast@PLT
	jmp	.L111
.L110:
	movl	$0, %eax
.L111:
	movq	%rax, -24(%rbp)
	cmpq	$0, -24(%rbp)
	je	.L112
	movq	-24(%rbp), %rax
	movq	(%rax), %rax
	addq	$16, %rax
	movq	(%rax), %rdx
	movq	-24(%rbp), %rax
	movq	%rax, %rdi
	call	*%rdx
	movq	%rax, %rdi
.LEHB19:
	call	puts@PLT
	jmp	.L113
.L112:
	movq	-32(%rbp), %rax
	movq	(%rax), %rax
	addq	$16, %rax
	movq	(%rax), %rdx
	movq	-32(%rbp), %rax
	movq	%rax, %rdi
	call	*%rdx
	movq	%rax, %rdi
	call	puts@PLT
.LEHE19:
.L113:
	call	__cxa_end_catch@PLT
	jmp	.L114
.L117:
	endbr64
	movq	%rax, %rbx
	call	__cxa_end_catch@PLT
	movq	%rbx, %rax
	movq	%rax, %rdi
.LEHB20:
	call	_Unwind_Resume@PLT
.LEHE20:
.L118:
	addq	$56, %rsp
	popq	%rbx
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1851:
	.section	.gcc_except_table
	.align 4
.LLSDA1851:
	.byte	0xff
	.byte	0x9b
	.uleb128 .LLSDATT1851-.LLSDATTD1851
.LLSDATTD1851:
	.byte	0x1
	.uleb128 .LLSDACSE1851-.LLSDACSB1851
.LLSDACSB1851:
	.uleb128 .LEHB16-.LFB1851
	.uleb128 .LEHE16-.LEHB16
	.uleb128 0
	.uleb128 0
	.uleb128 .LEHB17-.LFB1851
	.uleb128 .LEHE17-.LEHB17
	.uleb128 .L116-.LFB1851
	.uleb128 0x1
	.uleb128 .LEHB18-.LFB1851
	.uleb128 .LEHE18-.LEHB18
	.uleb128 0
	.uleb128 0
	.uleb128 .LEHB19-.LFB1851
	.uleb128 .LEHE19-.LEHB19
	.uleb128 .L117-.LFB1851
	.uleb128 0
	.uleb128 .LEHB20-.LFB1851
	.uleb128 .LEHE20-.LEHB20
	.uleb128 0
	.uleb128 0
.LLSDACSE1851:
	.byte	0x1
	.byte	0
	.align 4
	.long	DW.ref._ZTISt13runtime_error-.
.LLSDATT1851:
	.text
	.size	main, .-main
	.section	.text._ZSt3powIiiEN9__gnu_cxx11__promote_2IT_T0_NS0_9__promoteIS2_XsrSt12__is_integerIS2_E7__valueEE6__typeENS4_IS3_XsrS5_IS3_E7__valueEE6__typeEE6__typeES2_S3_,"axG",@progbits,_ZSt3powIiiEN9__gnu_cxx11__promote_2IT_T0_NS0_9__promoteIS2_XsrSt12__is_integerIS2_E7__valueEE6__typeENS4_IS3_XsrS5_IS3_E7__valueEE6__typeEE6__typeES2_S3_,comdat
	.weak	_ZSt3powIiiEN9__gnu_cxx11__promote_2IT_T0_NS0_9__promoteIS2_XsrSt12__is_integerIS2_E7__valueEE6__typeENS4_IS3_XsrS5_IS3_E7__valueEE6__typeEE6__typeES2_S3_
	.type	_ZSt3powIiiEN9__gnu_cxx11__promote_2IT_T0_NS0_9__promoteIS2_XsrSt12__is_integerIS2_E7__valueEE6__typeENS4_IS3_XsrS5_IS3_E7__valueEE6__typeEE6__typeES2_S3_, @function
_ZSt3powIiiEN9__gnu_cxx11__promote_2IT_T0_NS0_9__promoteIS2_XsrSt12__is_integerIS2_E7__valueEE6__typeENS4_IS3_XsrS5_IS3_E7__valueEE6__typeEE6__typeES2_S3_:
.LFB2088:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movl	%edi, -4(%rbp)
	movl	%esi, -8(%rbp)
	cvtsi2sdl	-8(%rbp), %xmm1
	cvtsi2sdl	-4(%rbp), %xmm0
	call	pow@PLT
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE2088:
	.size	_ZSt3powIiiEN9__gnu_cxx11__promote_2IT_T0_NS0_9__promoteIS2_XsrSt12__is_integerIS2_E7__valueEE6__typeENS4_IS3_XsrS5_IS3_E7__valueEE6__typeEE6__typeES2_S3_, .-_ZSt3powIiiEN9__gnu_cxx11__promote_2IT_T0_NS0_9__promoteIS2_XsrSt12__is_integerIS2_E7__valueEE6__typeENS4_IS3_XsrS5_IS3_E7__valueEE6__typeEE6__typeES2_S3_
	.weak	_ZTV7Hexagon
	.section	.data.rel.ro.local._ZTV7Hexagon,"awG",@progbits,_ZTV7Hexagon,comdat
	.align 8
	.type	_ZTV7Hexagon, @object
	.size	_ZTV7Hexagon, 80
_ZTV7Hexagon:
	.quad	0
	.quad	_ZTI7Hexagon
	.quad	_ZN7HexagonD1Ev
	.quad	_ZN7HexagonD0Ev
	.quad	_ZN7Hexagon4areaEv
	.quad	_ZN7Hexagon13circumferenceEv
	.quad	-16
	.quad	_ZTI7Hexagon
	.quad	_ZThn16_N7HexagonD1Ev
	.quad	_ZThn16_N7HexagonD0Ev
	.weak	_ZTV8Pentagon
	.section	.data.rel.ro.local._ZTV8Pentagon,"awG",@progbits,_ZTV8Pentagon,comdat
	.align 8
	.type	_ZTV8Pentagon, @object
	.size	_ZTV8Pentagon, 80
_ZTV8Pentagon:
	.quad	0
	.quad	_ZTI8Pentagon
	.quad	_ZN8PentagonD1Ev
	.quad	_ZN8PentagonD0Ev
	.quad	_ZN8Pentagon4areaEv
	.quad	_ZN8Pentagon13circumferenceEv
	.quad	-16
	.quad	_ZTI8Pentagon
	.quad	_ZThn16_N8PentagonD1Ev
	.quad	_ZThn16_N8PentagonD0Ev
	.weak	_ZTV6Circle
	.section	.data.rel.ro.local._ZTV6Circle,"awG",@progbits,_ZTV6Circle,comdat
	.align 8
	.type	_ZTV6Circle, @object
	.size	_ZTV6Circle, 48
_ZTV6Circle:
	.quad	0
	.quad	_ZTI6Circle
	.quad	_ZN6CircleD1Ev
	.quad	_ZN6CircleD0Ev
	.quad	_ZN6Circle4areaEv
	.quad	_ZN6Circle13circumferenceEv
	.weak	_ZTV8Triangle
	.section	.data.rel.ro.local._ZTV8Triangle,"awG",@progbits,_ZTV8Triangle,comdat
	.align 8
	.type	_ZTV8Triangle, @object
	.size	_ZTV8Triangle, 80
_ZTV8Triangle:
	.quad	0
	.quad	_ZTI8Triangle
	.quad	_ZN8TriangleD1Ev
	.quad	_ZN8TriangleD0Ev
	.quad	_ZN8Triangle4areaEv
	.quad	_ZN8Triangle13circumferenceEv
	.quad	-16
	.quad	_ZTI8Triangle
	.quad	_ZThn16_N8TriangleD1Ev
	.quad	_ZThn16_N8TriangleD0Ev
	.weak	_ZTV6Square
	.section	.data.rel.ro.local._ZTV6Square,"awG",@progbits,_ZTV6Square,comdat
	.align 8
	.type	_ZTV6Square, @object
	.size	_ZTV6Square, 80
_ZTV6Square:
	.quad	0
	.quad	_ZTI6Square
	.quad	_ZN6SquareD1Ev
	.quad	_ZN6SquareD0Ev
	.quad	_ZN13Parallelogram4areaEv
	.quad	_ZN6Square13circumferenceEv
	.quad	-24
	.quad	_ZTI6Square
	.quad	_ZThn24_N6SquareD1Ev
	.quad	_ZThn24_N6SquareD0Ev
	.weak	_ZTV9Rectangle
	.section	.data.rel.ro.local._ZTV9Rectangle,"awG",@progbits,_ZTV9Rectangle,comdat
	.align 8
	.type	_ZTV9Rectangle, @object
	.size	_ZTV9Rectangle, 48
_ZTV9Rectangle:
	.quad	0
	.quad	_ZTI9Rectangle
	.quad	_ZN9RectangleD1Ev
	.quad	_ZN9RectangleD0Ev
	.quad	_ZN13Parallelogram4areaEv
	.quad	_ZN13Parallelogram13circumferenceEv
	.weak	_ZTV13Parallelogram
	.section	.data.rel.ro.local._ZTV13Parallelogram,"awG",@progbits,_ZTV13Parallelogram,comdat
	.align 8
	.type	_ZTV13Parallelogram, @object
	.size	_ZTV13Parallelogram, 48
_ZTV13Parallelogram:
	.quad	0
	.quad	_ZTI13Parallelogram
	.quad	_ZN13ParallelogramD1Ev
	.quad	_ZN13ParallelogramD0Ev
	.quad	_ZN13Parallelogram4areaEv
	.quad	_ZN13Parallelogram13circumferenceEv
	.weak	_ZTV5Shape
	.section	.data.rel.ro._ZTV5Shape,"awG",@progbits,_ZTV5Shape,comdat
	.align 8
	.type	_ZTV5Shape, @object
	.size	_ZTV5Shape, 48
_ZTV5Shape:
	.quad	0
	.quad	_ZTI5Shape
	.quad	0
	.quad	0
	.quad	__cxa_pure_virtual
	.quad	__cxa_pure_virtual
	.weak	_ZTV11RegularNGon
	.section	.data.rel.ro.local._ZTV11RegularNGon,"awG",@progbits,_ZTV11RegularNGon,comdat
	.align 8
	.type	_ZTV11RegularNGon, @object
	.size	_ZTV11RegularNGon, 32
_ZTV11RegularNGon:
	.quad	0
	.quad	_ZTI11RegularNGon
	.quad	_ZN11RegularNGonD1Ev
	.quad	_ZN11RegularNGonD0Ev
	.weak	_ZTV6Object
	.section	.data.rel.ro.local._ZTV6Object,"awG",@progbits,_ZTV6Object,comdat
	.align 8
	.type	_ZTV6Object, @object
	.size	_ZTV6Object, 32
_ZTV6Object:
	.quad	0
	.quad	_ZTI6Object
	.quad	_ZN6ObjectD1Ev
	.quad	_ZN6ObjectD0Ev
	.weak	_ZTV17ShapeProgramError
	.section	.data.rel.ro.local._ZTV17ShapeProgramError,"awG",@progbits,_ZTV17ShapeProgramError,comdat
	.align 8
	.type	_ZTV17ShapeProgramError, @object
	.size	_ZTV17ShapeProgramError, 40
_ZTV17ShapeProgramError:
	.quad	0
	.quad	_ZTI17ShapeProgramError
	.quad	_ZN17ShapeProgramErrorD1Ev
	.quad	_ZN17ShapeProgramErrorD0Ev
	.quad	_ZNK17ShapeProgramError4whatEv
	.section	.text._ZN17ShapeProgramErrorD2Ev,"axG",@progbits,_ZN17ShapeProgramErrorD5Ev,comdat
	.align 2
	.weak	_ZN17ShapeProgramErrorD2Ev
	.type	_ZN17ShapeProgramErrorD2Ev, @function
_ZN17ShapeProgramErrorD2Ev:
.LFB2334:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	leaq	16+_ZTV17ShapeProgramError(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZNSt13runtime_errorD2Ev@PLT
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE2334:
	.size	_ZN17ShapeProgramErrorD2Ev, .-_ZN17ShapeProgramErrorD2Ev
	.weak	_ZN17ShapeProgramErrorD1Ev
	.set	_ZN17ShapeProgramErrorD1Ev,_ZN17ShapeProgramErrorD2Ev
	.section	.text._ZN17ShapeProgramErrorD0Ev,"axG",@progbits,_ZN17ShapeProgramErrorD5Ev,comdat
	.align 2
	.weak	_ZN17ShapeProgramErrorD0Ev
	.type	_ZN17ShapeProgramErrorD0Ev, @function
_ZN17ShapeProgramErrorD0Ev:
.LFB2336:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN17ShapeProgramErrorD1Ev
	movq	-8(%rbp), %rax
	movl	$1048, %esi
	movq	%rax, %rdi
	call	_ZdlPvm@PLT
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE2336:
	.size	_ZN17ShapeProgramErrorD0Ev, .-_ZN17ShapeProgramErrorD0Ev
	.weak	_ZTI7Hexagon
	.section	.data.rel.ro._ZTI7Hexagon,"awG",@progbits,_ZTI7Hexagon,comdat
	.align 8
	.type	_ZTI7Hexagon, @object
	.size	_ZTI7Hexagon, 56
_ZTI7Hexagon:
	.quad	_ZTVN10__cxxabiv121__vmi_class_type_infoE+16
	.quad	_ZTS7Hexagon
	.long	0
	.long	2
	.quad	_ZTI5Shape
	.quad	2
	.quad	_ZTI11RegularNGon
	.quad	4098
	.weak	_ZTS7Hexagon
	.section	.rodata._ZTS7Hexagon,"aG",@progbits,_ZTS7Hexagon,comdat
	.align 8
	.type	_ZTS7Hexagon, @object
	.size	_ZTS7Hexagon, 9
_ZTS7Hexagon:
	.string	"7Hexagon"
	.weak	_ZTI8Pentagon
	.section	.data.rel.ro._ZTI8Pentagon,"awG",@progbits,_ZTI8Pentagon,comdat
	.align 8
	.type	_ZTI8Pentagon, @object
	.size	_ZTI8Pentagon, 56
_ZTI8Pentagon:
	.quad	_ZTVN10__cxxabiv121__vmi_class_type_infoE+16
	.quad	_ZTS8Pentagon
	.long	0
	.long	2
	.quad	_ZTI5Shape
	.quad	2
	.quad	_ZTI11RegularNGon
	.quad	4098
	.weak	_ZTS8Pentagon
	.section	.rodata._ZTS8Pentagon,"aG",@progbits,_ZTS8Pentagon,comdat
	.align 8
	.type	_ZTS8Pentagon, @object
	.size	_ZTS8Pentagon, 10
_ZTS8Pentagon:
	.string	"8Pentagon"
	.weak	_ZTI6Circle
	.section	.data.rel.ro._ZTI6Circle,"awG",@progbits,_ZTI6Circle,comdat
	.align 8
	.type	_ZTI6Circle, @object
	.size	_ZTI6Circle, 24
_ZTI6Circle:
	.quad	_ZTVN10__cxxabiv120__si_class_type_infoE+16
	.quad	_ZTS6Circle
	.quad	_ZTI5Shape
	.weak	_ZTS6Circle
	.section	.rodata._ZTS6Circle,"aG",@progbits,_ZTS6Circle,comdat
	.align 8
	.type	_ZTS6Circle, @object
	.size	_ZTS6Circle, 8
_ZTS6Circle:
	.string	"6Circle"
	.weak	_ZTI8Triangle
	.section	.data.rel.ro._ZTI8Triangle,"awG",@progbits,_ZTI8Triangle,comdat
	.align 8
	.type	_ZTI8Triangle, @object
	.size	_ZTI8Triangle, 56
_ZTI8Triangle:
	.quad	_ZTVN10__cxxabiv121__vmi_class_type_infoE+16
	.quad	_ZTS8Triangle
	.long	0
	.long	2
	.quad	_ZTI5Shape
	.quad	2
	.quad	_ZTI11RegularNGon
	.quad	4098
	.weak	_ZTS8Triangle
	.section	.rodata._ZTS8Triangle,"aG",@progbits,_ZTS8Triangle,comdat
	.align 8
	.type	_ZTS8Triangle, @object
	.size	_ZTS8Triangle, 10
_ZTS8Triangle:
	.string	"8Triangle"
	.weak	_ZTI6Square
	.section	.data.rel.ro._ZTI6Square,"awG",@progbits,_ZTI6Square,comdat
	.align 8
	.type	_ZTI6Square, @object
	.size	_ZTI6Square, 56
_ZTI6Square:
	.quad	_ZTVN10__cxxabiv121__vmi_class_type_infoE+16
	.quad	_ZTS6Square
	.long	0
	.long	2
	.quad	_ZTI9Rectangle
	.quad	2
	.quad	_ZTI11RegularNGon
	.quad	6146
	.weak	_ZTS6Square
	.section	.rodata._ZTS6Square,"aG",@progbits,_ZTS6Square,comdat
	.align 8
	.type	_ZTS6Square, @object
	.size	_ZTS6Square, 8
_ZTS6Square:
	.string	"6Square"
	.weak	_ZTI9Rectangle
	.section	.data.rel.ro._ZTI9Rectangle,"awG",@progbits,_ZTI9Rectangle,comdat
	.align 8
	.type	_ZTI9Rectangle, @object
	.size	_ZTI9Rectangle, 24
_ZTI9Rectangle:
	.quad	_ZTVN10__cxxabiv120__si_class_type_infoE+16
	.quad	_ZTS9Rectangle
	.quad	_ZTI13Parallelogram
	.weak	_ZTS9Rectangle
	.section	.rodata._ZTS9Rectangle,"aG",@progbits,_ZTS9Rectangle,comdat
	.align 8
	.type	_ZTS9Rectangle, @object
	.size	_ZTS9Rectangle, 11
_ZTS9Rectangle:
	.string	"9Rectangle"
	.weak	_ZTI13Parallelogram
	.section	.data.rel.ro._ZTI13Parallelogram,"awG",@progbits,_ZTI13Parallelogram,comdat
	.align 8
	.type	_ZTI13Parallelogram, @object
	.size	_ZTI13Parallelogram, 24
_ZTI13Parallelogram:
	.quad	_ZTVN10__cxxabiv120__si_class_type_infoE+16
	.quad	_ZTS13Parallelogram
	.quad	_ZTI5Shape
	.weak	_ZTS13Parallelogram
	.section	.rodata._ZTS13Parallelogram,"aG",@progbits,_ZTS13Parallelogram,comdat
	.align 16
	.type	_ZTS13Parallelogram, @object
	.size	_ZTS13Parallelogram, 16
_ZTS13Parallelogram:
	.string	"13Parallelogram"
	.weak	_ZTI5Shape
	.section	.data.rel.ro._ZTI5Shape,"awG",@progbits,_ZTI5Shape,comdat
	.align 8
	.type	_ZTI5Shape, @object
	.size	_ZTI5Shape, 24
_ZTI5Shape:
	.quad	_ZTVN10__cxxabiv120__si_class_type_infoE+16
	.quad	_ZTS5Shape
	.quad	_ZTI6Object
	.weak	_ZTS5Shape
	.section	.rodata._ZTS5Shape,"aG",@progbits,_ZTS5Shape,comdat
	.type	_ZTS5Shape, @object
	.size	_ZTS5Shape, 7
_ZTS5Shape:
	.string	"5Shape"
	.weak	_ZTI11RegularNGon
	.section	.data.rel.ro._ZTI11RegularNGon,"awG",@progbits,_ZTI11RegularNGon,comdat
	.align 8
	.type	_ZTI11RegularNGon, @object
	.size	_ZTI11RegularNGon, 16
_ZTI11RegularNGon:
	.quad	_ZTVN10__cxxabiv117__class_type_infoE+16
	.quad	_ZTS11RegularNGon
	.weak	_ZTS11RegularNGon
	.section	.rodata._ZTS11RegularNGon,"aG",@progbits,_ZTS11RegularNGon,comdat
	.align 8
	.type	_ZTS11RegularNGon, @object
	.size	_ZTS11RegularNGon, 14
_ZTS11RegularNGon:
	.string	"11RegularNGon"
	.weak	_ZTI6Object
	.section	.data.rel.ro._ZTI6Object,"awG",@progbits,_ZTI6Object,comdat
	.align 8
	.type	_ZTI6Object, @object
	.size	_ZTI6Object, 16
_ZTI6Object:
	.quad	_ZTVN10__cxxabiv117__class_type_infoE+16
	.quad	_ZTS6Object
	.weak	_ZTS6Object
	.section	.rodata._ZTS6Object,"aG",@progbits,_ZTS6Object,comdat
	.align 8
	.type	_ZTS6Object, @object
	.size	_ZTS6Object, 8
_ZTS6Object:
	.string	"6Object"
	.weak	_ZTI17ShapeProgramError
	.section	.data.rel.ro._ZTI17ShapeProgramError,"awG",@progbits,_ZTI17ShapeProgramError,comdat
	.align 8
	.type	_ZTI17ShapeProgramError, @object
	.size	_ZTI17ShapeProgramError, 56
_ZTI17ShapeProgramError:
	.quad	_ZTVN10__cxxabiv121__vmi_class_type_infoE+16
	.quad	_ZTS17ShapeProgramError
	.long	0
	.long	2
	.quad	_ZTISt13runtime_error
	.quad	2
	.quad	_ZTI13ExceptionCode
	.quad	4098
	.weak	_ZTS17ShapeProgramError
	.section	.rodata._ZTS17ShapeProgramError,"aG",@progbits,_ZTS17ShapeProgramError,comdat
	.align 16
	.type	_ZTS17ShapeProgramError, @object
	.size	_ZTS17ShapeProgramError, 20
_ZTS17ShapeProgramError:
	.string	"17ShapeProgramError"
	.text
	.type	_Z41__static_initialization_and_destruction_0ii, @function
_Z41__static_initialization_and_destruction_0ii:
.LFB2337:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movl	%edi, -4(%rbp)
	movl	%esi, -8(%rbp)
	cmpl	$1, -4(%rbp)
	jne	.L125
	cmpl	$65535, -8(%rbp)
	jne	.L125
	leaq	_ZStL8__ioinit(%rip), %rdi
	call	_ZNSt8ios_base4InitC1Ev@PLT
	leaq	__dso_handle(%rip), %rdx
	leaq	_ZStL8__ioinit(%rip), %rsi
	movq	_ZNSt8ios_base4InitD1Ev@GOTPCREL(%rip), %rax
	movq	%rax, %rdi
	call	__cxa_atexit@PLT
.L125:
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE2337:
	.size	_Z41__static_initialization_and_destruction_0ii, .-_Z41__static_initialization_and_destruction_0ii
	.weak	_ZTI13ExceptionCode
	.section	.data.rel.ro._ZTI13ExceptionCode,"awG",@progbits,_ZTI13ExceptionCode,comdat
	.align 8
	.type	_ZTI13ExceptionCode, @object
	.size	_ZTI13ExceptionCode, 16
_ZTI13ExceptionCode:
	.quad	_ZTVN10__cxxabiv117__class_type_infoE+16
	.quad	_ZTS13ExceptionCode
	.weak	_ZTS13ExceptionCode
	.section	.rodata._ZTS13ExceptionCode,"aG",@progbits,_ZTS13ExceptionCode,comdat
	.align 16
	.type	_ZTS13ExceptionCode, @object
	.size	_ZTS13ExceptionCode, 16
_ZTS13ExceptionCode:
	.string	"13ExceptionCode"
	.text
	.type	_GLOBAL__sub_I__Z11createshapec, @function
_GLOBAL__sub_I__Z11createshapec:
.LFB2338:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	$65535, %esi
	movl	$1, %edi
	call	_Z41__static_initialization_and_destruction_0ii
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE2338:
	.size	_GLOBAL__sub_I__Z11createshapec, .-_GLOBAL__sub_I__Z11createshapec
	.section	.init_array,"aw"
	.align 8
	.quad	_GLOBAL__sub_I__Z11createshapec
	.section	.rodata
	.align 8
.LC2:
	.long	0
	.long	1071644672
	.align 8
.LC5:
	.long	1405670641
	.long	1074340347
	.align 8
.LC7:
	.long	776092032
	.long	1074055388
	.hidden	DW.ref._ZTI17ShapeProgramError
	.weak	DW.ref._ZTI17ShapeProgramError
	.section	.data.rel.local.DW.ref._ZTI17ShapeProgramError,"awG",@progbits,DW.ref._ZTI17ShapeProgramError,comdat
	.align 8
	.type	DW.ref._ZTI17ShapeProgramError, @object
	.size	DW.ref._ZTI17ShapeProgramError, 8
DW.ref._ZTI17ShapeProgramError:
	.quad	_ZTI17ShapeProgramError
	.hidden	DW.ref._ZTISt11logic_error
	.weak	DW.ref._ZTISt11logic_error
	.section	.data.rel.local.DW.ref._ZTISt11logic_error,"awG",@progbits,DW.ref._ZTISt11logic_error,comdat
	.align 8
	.type	DW.ref._ZTISt11logic_error, @object
	.size	DW.ref._ZTISt11logic_error, 8
DW.ref._ZTISt11logic_error:
	.quad	_ZTISt11logic_error
	.hidden	DW.ref._ZTISt13runtime_error
	.weak	DW.ref._ZTISt13runtime_error
	.section	.data.rel.local.DW.ref._ZTISt13runtime_error,"awG",@progbits,DW.ref._ZTISt13runtime_error,comdat
	.align 8
	.type	DW.ref._ZTISt13runtime_error, @object
	.size	DW.ref._ZTISt13runtime_error, 8
DW.ref._ZTISt13runtime_error:
	.quad	_ZTISt13runtime_error
	.hidden	DW.ref._ZTISt9exception
	.weak	DW.ref._ZTISt9exception
	.section	.data.rel.local.DW.ref._ZTISt9exception,"awG",@progbits,DW.ref._ZTISt9exception,comdat
	.align 8
	.type	DW.ref._ZTISt9exception, @object
	.size	DW.ref._ZTISt9exception, 8
DW.ref._ZTISt9exception:
	.quad	_ZTISt9exception
	.hidden	DW.ref.__gxx_personality_v0
	.weak	DW.ref.__gxx_personality_v0
	.section	.data.rel.local.DW.ref.__gxx_personality_v0,"awG",@progbits,DW.ref.__gxx_personality_v0,comdat
	.align 8
	.type	DW.ref.__gxx_personality_v0, @object
	.size	DW.ref.__gxx_personality_v0, 8
DW.ref.__gxx_personality_v0:
	.quad	__gxx_personality_v0
	.hidden	__dso_handle
	.ident	"GCC: (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0"
	.section	.note.GNU-stack,"",@progbits
	.section	.note.gnu.property,"a"
	.align 8
	.long	 1f - 0f
	.long	 4f - 1f
	.long	 5
0:
	.string	 "GNU"
1:
	.align 8
	.long	 0xc0000002
	.long	 3f - 2f
2:
	.long	 0x3
3:
	.align 8
4:
