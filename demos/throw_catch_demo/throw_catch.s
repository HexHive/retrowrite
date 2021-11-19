	.file	"throw_catch.cpp"
	.text
	.section	.rodata
	.type	_ZStL19piecewise_construct, @object
	.size	_ZStL19piecewise_construct, 1
_ZStL19piecewise_construct:
	.zero	1
	.section	.text._ZN5Shape4drawEv,"axG",@progbits,_ZN5Shape4drawEv,comdat
	.align 2
	.weak	_ZN5Shape4drawEv
	.type	_ZN5Shape4drawEv, @function
_ZN5Shape4drawEv:
.LFB1011:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1011:
	.size	_ZN5Shape4drawEv, .-_ZN5Shape4drawEv
	.section	.rodata
.LC0:
	.string	"This cannot be done !\n"
	.section	.text._ZN9Rectangle4drawEv,"axG",@progbits,_ZN9Rectangle4drawEv,comdat
	.align 2
	.weak	_ZN9Rectangle4drawEv
	.type	_ZN9Rectangle4drawEv, @function
_ZN9Rectangle4drawEv:
.LFB1012:
	.cfi_startproc
	.cfi_personality 0x9b,DW.ref.__gxx_personality_v0
	.cfi_lsda 0x1b,.LLSDA1012
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
	movl	$16, %edi
	call	__cxa_allocate_exception@PLT
	movq	%rax, %rbx
	leaq	.LC0(%rip), %rsi
	movq	%rbx, %rdi
.LEHB0:
	call	_ZNSt11logic_errorC1EPKc@PLT
.LEHE0:
	movq	_ZNSt11logic_errorD1Ev@GOTPCREL(%rip), %rax
	movq	%rax, %rdx
	leaq	_ZTISt11logic_error(%rip), %rsi
	movq	%rbx, %rdi
.LEHB1:
	call	__cxa_throw@PLT
.L4:
	endbr64
	movq	%rax, %r12
	movq	%rbx, %rdi
	call	__cxa_free_exception@PLT
	movq	%r12, %rax
	movq	%rax, %rdi
	call	_Unwind_Resume@PLT
.LEHE1:
	.cfi_endproc
.LFE1012:
	.globl	__gxx_personality_v0
	.section	.gcc_except_table._ZN9Rectangle4drawEv,"aG",@progbits,_ZN9Rectangle4drawEv,comdat
.LLSDA1012:
	.byte	0xff
	.byte	0xff
	.byte	0x1
	.uleb128 .LLSDACSE1012-.LLSDACSB1012
.LLSDACSB1012:
	.uleb128 .LEHB0-.LFB1012
	.uleb128 .LEHE0-.LEHB0
	.uleb128 .L4-.LFB1012
	.uleb128 0
	.uleb128 .LEHB1-.LFB1012
	.uleb128 .LEHE1-.LEHB1
	.uleb128 0
	.uleb128 0
.LLSDACSE1012:
	.section	.text._ZN9Rectangle4drawEv,"axG",@progbits,_ZN9Rectangle4drawEv,comdat
	.size	_ZN9Rectangle4drawEv, .-_ZN9Rectangle4drawEv
	.section	.rodata
.LC1:
	.string	"I'm here :)"
	.section	.text._ZN9Rectangle5helloEv,"axG",@progbits,_ZN9Rectangle5helloEv,comdat
	.align 2
	.weak	_ZN9Rectangle5helloEv
	.type	_ZN9Rectangle5helloEv, @function
_ZN9Rectangle5helloEv:
.LFB1013:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	leaq	.LC1(%rip), %rdi
	call	puts@PLT
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1013:
	.size	_ZN9Rectangle5helloEv, .-_ZN9Rectangle5helloEv
	.section	.text._ZN5ShapeC2Ev,"axG",@progbits,_ZN5ShapeC5Ev,comdat
	.align 2
	.weak	_ZN5ShapeC2Ev
	.type	_ZN5ShapeC2Ev, @function
_ZN5ShapeC2Ev:
.LFB1016:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	leaq	16+_ZTV5Shape(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1016:
	.size	_ZN5ShapeC2Ev, .-_ZN5ShapeC2Ev
	.weak	_ZN5ShapeC1Ev
	.set	_ZN5ShapeC1Ev,_ZN5ShapeC2Ev
	.section	.rodata
.LC2:
	.string	"I'm being constructed, yay !"
	.section	.text._ZN9RectangleC2Ev,"axG",@progbits,_ZN9RectangleC5Ev,comdat
	.align 2
	.weak	_ZN9RectangleC2Ev
	.type	_ZN9RectangleC2Ev, @function
_ZN9RectangleC2Ev:
.LFB1018:
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
	call	_ZN5ShapeC2Ev
	leaq	16+_ZTV9Rectangle(%rip), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	leaq	.LC2(%rip), %rdi
	call	puts@PLT
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1018:
	.size	_ZN9RectangleC2Ev, .-_ZN9RectangleC2Ev
	.weak	_ZN9RectangleC1Ev
	.set	_ZN9RectangleC1Ev,_ZN9RectangleC2Ev
	.globl	azerty
	.bss
	.align 8
	.type	azerty, @object
	.size	azerty, 8
azerty:
	.zero	8
	.section	.rodata
.LC3:
	.string	"We're in main."
.LC4:
	.string	"Error caught !"
	.text
	.globl	main
	.type	main, @function
main:
.LFB1020:
	.cfi_startproc
	.cfi_personality 0x9b,DW.ref.__gxx_personality_v0
	.cfi_lsda 0x1b,.LLSDA1020
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
	movl	%edi, -36(%rbp)
	movq	%rsi, -48(%rbp)
	leaq	.LC3(%rip), %rdi
.LEHB2:
	call	puts@PLT
	cmpl	$2, -36(%rbp)
	jne	.L9
	movl	$8, %edi
	call	_Znwm@PLT
	movq	%rax, %rbx
	movq	$0, (%rbx)
	movq	%rbx, %rdi
	call	_ZN5ShapeC1Ev
	movq	%rbx, -24(%rbp)
	leaq	azerty(%rip), %rdi
	call	_ZN9Rectangle5helloEv
	jmp	.L10
.L9:
	movl	$8, %edi
	call	_Znwm@PLT
.LEHE2:
	movq	%rax, %rbx
	movq	%rbx, %rdi
.LEHB3:
	call	_ZN9RectangleC1Ev
.LEHE3:
	movq	%rbx, -24(%rbp)
.L10:
	movq	-24(%rbp), %rax
	movq	(%rax), %rax
	movq	(%rax), %rdx
	movq	-24(%rbp), %rax
	movq	%rax, %rdi
.LEHB4:
	call	*%rdx
.LEHE4:
.L15:
	movq	-24(%rbp), %rax
	testq	%rax, %rax
	je	.L11
	movl	$8, %esi
	movq	%rax, %rdi
	call	_ZdlPvm@PLT
.L11:
	movl	$0, %eax
	jmp	.L20
.L17:
	endbr64
	movq	%rax, %r12
	movl	$8, %esi
	movq	%rbx, %rdi
	call	_ZdlPvm@PLT
	movq	%r12, %rax
	movq	%rax, %rdi
.LEHB5:
	call	_Unwind_Resume@PLT
.LEHE5:
.L18:
	endbr64
	movq	%rax, %rdi
	call	__cxa_begin_catch@PLT
	leaq	.LC4(%rip), %rdi
.LEHB6:
	call	puts@PLT
.LEHE6:
.LEHB7:
	call	__cxa_end_catch@PLT
.LEHE7:
	jmp	.L15
.L19:
	endbr64
	movq	%rax, %rbx
	call	__cxa_end_catch@PLT
	movq	%rbx, %rax
	movq	%rax, %rdi
.LEHB8:
	call	_Unwind_Resume@PLT
.LEHE8:
.L20:
	addq	$32, %rsp
	popq	%rbx
	popq	%r12
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1020:
	.section	.gcc_except_table,"a",@progbits
	.align 4
.LLSDA1020:
	.byte	0xff
	.byte	0x9b
	.uleb128 .LLSDATT1020-.LLSDATTD1020
.LLSDATTD1020:
	.byte	0x1
	.uleb128 .LLSDACSE1020-.LLSDACSB1020
.LLSDACSB1020:
	.uleb128 .LEHB2-.LFB1020
	.uleb128 .LEHE2-.LEHB2
	.uleb128 0
	.uleb128 0
	.uleb128 .LEHB3-.LFB1020
	.uleb128 .LEHE3-.LEHB3
	.uleb128 .L17-.LFB1020
	.uleb128 0
	.uleb128 .LEHB4-.LFB1020
	.uleb128 .LEHE4-.LEHB4
	.uleb128 .L18-.LFB1020
	.uleb128 0x1
	.uleb128 .LEHB5-.LFB1020
	.uleb128 .LEHE5-.LEHB5
	.uleb128 0
	.uleb128 0
	.uleb128 .LEHB6-.LFB1020
	.uleb128 .LEHE6-.LEHB6
	.uleb128 .L19-.LFB1020
	.uleb128 0
	.uleb128 .LEHB7-.LFB1020
	.uleb128 .LEHE7-.LEHB7
	.uleb128 0
	.uleb128 0
	.uleb128 .LEHB8-.LFB1020
	.uleb128 .LEHE8-.LEHB8
	.uleb128 0
	.uleb128 0
.LLSDACSE1020:
	.byte	0x1
	.byte	0
	.align 4
	.long	0

.LLSDATT1020:
	.text
	.size	main, .-main
	.weak	_ZTV9Rectangle
	.section	.data.rel.ro.local._ZTV9Rectangle,"awG",@progbits,_ZTV9Rectangle,comdat
	.align 8
	.type	_ZTV9Rectangle, @object
	.size	_ZTV9Rectangle, 24
_ZTV9Rectangle:
	.quad	0
	.quad	_ZTI9Rectangle
	.quad	_ZN9Rectangle4drawEv
	.weak	_ZTV5Shape
	.section	.data.rel.ro.local._ZTV5Shape,"awG",@progbits,_ZTV5Shape,comdat
	.align 8
	.type	_ZTV5Shape, @object
	.size	_ZTV5Shape, 24
_ZTV5Shape:
	.quad	0
	.quad	_ZTI5Shape
	.quad	_ZN5Shape4drawEv
	.weak	_ZTI9Rectangle
	.section	.data.rel.ro._ZTI9Rectangle,"awG",@progbits,_ZTI9Rectangle,comdat
	.align 8
	.type	_ZTI9Rectangle, @object
	.size	_ZTI9Rectangle, 24
_ZTI9Rectangle:
	.quad	_ZTVN10__cxxabiv120__si_class_type_infoE+16
	.quad	_ZTS9Rectangle
	.quad	_ZTI5Shape
	.weak	_ZTS9Rectangle
	.section	.rodata._ZTS9Rectangle,"aG",@progbits,_ZTS9Rectangle,comdat
	.align 8
	.type	_ZTS9Rectangle, @object
	.size	_ZTS9Rectangle, 11
_ZTS9Rectangle:
	.string	"9Rectangle"
	.weak	_ZTI5Shape
	.section	.data.rel.ro._ZTI5Shape,"awG",@progbits,_ZTI5Shape,comdat
	.align 8
	.type	_ZTI5Shape, @object
	.size	_ZTI5Shape, 16
_ZTI5Shape:
	.quad	_ZTVN10__cxxabiv117__class_type_infoE+16
	.quad	_ZTS5Shape
	.weak	_ZTS5Shape
	.section	.rodata._ZTS5Shape,"aG",@progbits,_ZTS5Shape,comdat
	.type	_ZTS5Shape, @object
	.size	_ZTS5Shape, 7
_ZTS5Shape:
	.string	"5Shape"
	.text
	.type	_Z41__static_initialization_and_destruction_0ii, @function
_Z41__static_initialization_and_destruction_0ii:
.LFB1475:
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
	jne	.L23
	cmpl	$65535, -8(%rbp)
	jne	.L23
	leaq	azerty(%rip), %rdi
	call	_ZN9RectangleC1Ev
.L23:
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1475:
	.size	_Z41__static_initialization_and_destruction_0ii, .-_Z41__static_initialization_and_destruction_0ii
	.type	_GLOBAL__sub_I_azerty, @function
_GLOBAL__sub_I_azerty:
.LFB1476:
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
.LFE1476:
	.size	_GLOBAL__sub_I_azerty, .-_GLOBAL__sub_I_azerty
	.section	.init_array,"aw"
	.align 8
	.quad	_GLOBAL__sub_I_azerty
	.hidden	DW.ref.__gxx_personality_v0
	.weak	DW.ref.__gxx_personality_v0
	.section	.data.rel.local.DW.ref.__gxx_personality_v0,"awG",@progbits,DW.ref.__gxx_personality_v0,comdat
	.align 8
	.type	DW.ref.__gxx_personality_v0, @object
	.size	DW.ref.__gxx_personality_v0, 8
DW.ref.__gxx_personality_v0:
	.quad	__gxx_personality_v0
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
