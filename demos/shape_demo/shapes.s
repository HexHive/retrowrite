	.text
	.intel_syntax noprefix
	.file	"shapes.cpp"
	.section	.text.startup,"ax",@progbits
	.p2align	4, 0x90         # -- Begin function __cxx_global_var_init
	.type	__cxx_global_var_init,@function
__cxx_global_var_init:                  # @__cxx_global_var_init
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	lea	rdi, [rip + _ZStL8__ioinit]
	call	_ZNSt8ios_base4InitC1Ev@PLT
	mov	rax, qword ptr [rip + _ZNSt8ios_base4InitD1Ev@GOTPCREL]
	mov	rdi, rax
	lea	rsi, [rip + _ZStL8__ioinit]
	lea	rdx, [rip + __dso_handle]
	call	__cxa_atexit@PLT
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end0:
	.size	__cxx_global_var_init, .Lfunc_end0-__cxx_global_var_init
	.cfi_endproc
                                        # -- End function
	.text
	.globl	main                    # -- Begin function main
	.p2align	4, 0x90
	.type	main,@function
main:                                   # @main
.Lfunc_begin0:
	.cfi_startproc
	.cfi_personality 155, DW.ref.__gxx_personality_v0
	.cfi_lsda 27, .Lexception0
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 160
	mov	dword ptr [rbp - 4], 0
	mov	dword ptr [rbp - 8], edi
	mov	qword ptr [rbp - 16], rsi
	mov	qword ptr [rbp - 24], 0
	cmp	dword ptr [rbp - 8], 2
	je	.LBB1_2
# %bb.1:
	lea	rdi, [rip + .L.str]
	mov	al, 0
	call	printf@PLT
	mov	dword ptr [rbp - 4], -1
	jmp	.LBB1_26
.LBB1_2:
	mov	rax, qword ptr [rbp - 16]
	mov	rdi, qword ptr [rax + 8]
	call	strlen@PLT
	cmp	rax, 1
	je	.LBB1_4
# %bb.3:
	lea	rdi, [rip + .L.str.1]
	mov	al, 0
	call	printf@PLT
	mov	dword ptr [rbp - 4], -1
	jmp	.LBB1_26
.LBB1_4:
	mov	rax, qword ptr [rbp - 16]
	mov	rax, qword ptr [rax + 8]
	movsx	ecx, byte ptr [rax]
	add	ecx, -67
	mov	eax, ecx
	sub	ecx, 17
	mov	qword ptr [rbp - 72], rax # 8-byte Spill
	ja	.LBB1_20
# %bb.28:
	lea	rax, [rip + .LJTI1_0]
	mov	rcx, qword ptr [rbp - 72] # 8-byte Reload
	movsxd	rdx, dword ptr [rax + 4*rcx]
	add	rdx, rax
	jmp	rdx
.LBB1_5:
	mov	edi, 24
	call	_Znwm@PLT
	mov	rcx, rax
	mov	rdx, rax
.Ltmp12:
	mov	esi, 4
	mov	rdi, rax
	mov	qword ptr [rbp - 80], rcx # 8-byte Spill
	mov	qword ptr [rbp - 88], rdx # 8-byte Spill
	call	_ZN6CircleC2Ei
.Ltmp13:
	jmp	.LBB1_6
.LBB1_6:
	mov	rax, qword ptr [rbp - 88] # 8-byte Reload
	mov	qword ptr [rbp - 24], rax
	mov	rax, qword ptr [rbp - 24]
	mov	rdi, rax
	lea	rsi, [rip + .L.str.2]
	call	_ZN6Object8set_nameEPKc
	jmp	.LBB1_21
.LBB1_7:
.Ltmp14:
                                        # kill: def $edx killed $edx killed $rdx
	mov	qword ptr [rbp - 32], rax
	mov	dword ptr [rbp - 36], edx
	mov	rdi, qword ptr [rbp - 80] # 8-byte Reload
	call	_ZdlPv@PLT
	jmp	.LBB1_27
.LBB1_8:
	mov	edi, 24
	call	_Znwm@PLT
	mov	rcx, rax
	mov	rdx, rax
.Ltmp9:
	mov	esi, 6
	mov	r8d, 10
	mov	rdi, rax
	mov	qword ptr [rbp - 96], rdx # 8-byte Spill
	mov	edx, r8d
	mov	qword ptr [rbp - 104], rcx # 8-byte Spill
	call	_ZN9RectangleC2Eii
.Ltmp10:
	jmp	.LBB1_9
.LBB1_9:
	mov	rax, qword ptr [rbp - 96] # 8-byte Reload
	mov	qword ptr [rbp - 24], rax
	mov	rax, qword ptr [rbp - 24]
	mov	rdi, rax
	lea	rsi, [rip + .L.str.3]
	call	_ZN6Object8set_nameEPKc
	jmp	.LBB1_21
.LBB1_10:
.Ltmp11:
                                        # kill: def $edx killed $edx killed $rdx
	mov	qword ptr [rbp - 32], rax
	mov	dword ptr [rbp - 36], edx
	mov	rdi, qword ptr [rbp - 104] # 8-byte Reload
	call	_ZdlPv@PLT
	jmp	.LBB1_27
.LBB1_11:
	mov	edi, 24
	call	_Znwm@PLT
	mov	rcx, rax
	mov	rdx, rax
.Ltmp6:
	mov	esi, 5
	mov	r8d, 9
	mov	rdi, rax
	mov	qword ptr [rbp - 112], rdx # 8-byte Spill
	mov	edx, r8d
	mov	qword ptr [rbp - 120], rcx # 8-byte Spill
	call	_ZN13ParallelogramC2Eii
.Ltmp7:
	jmp	.LBB1_12
.LBB1_12:
	mov	rax, qword ptr [rbp - 112] # 8-byte Reload
	mov	qword ptr [rbp - 24], rax
	mov	rax, qword ptr [rbp - 24]
	mov	rdi, rax
	lea	rsi, [rip + .L.str.4]
	call	_ZN6Object8set_nameEPKc
	jmp	.LBB1_21
.LBB1_13:
.Ltmp8:
                                        # kill: def $edx killed $edx killed $rdx
	mov	qword ptr [rbp - 32], rax
	mov	dword ptr [rbp - 36], edx
	mov	rdi, qword ptr [rbp - 120] # 8-byte Reload
	call	_ZdlPv@PLT
	jmp	.LBB1_27
.LBB1_14:
	mov	edi, 40
	call	_Znwm@PLT
	mov	rcx, rax
	mov	rdx, rax
.Ltmp3:
	mov	esi, 10
	mov	rdi, rax
	mov	qword ptr [rbp - 128], rcx # 8-byte Spill
	mov	qword ptr [rbp - 136], rdx # 8-byte Spill
	call	_ZN6SquareC2Ei
.Ltmp4:
	jmp	.LBB1_15
.LBB1_15:
	mov	rax, qword ptr [rbp - 136] # 8-byte Reload
	mov	qword ptr [rbp - 24], rax
	mov	rax, qword ptr [rbp - 24]
	mov	rdi, rax
	lea	rsi, [rip + .L.str.5]
	call	_ZN6Object8set_nameEPKc
	jmp	.LBB1_21
.LBB1_16:
.Ltmp5:
                                        # kill: def $edx killed $edx killed $rdx
	mov	qword ptr [rbp - 32], rax
	mov	dword ptr [rbp - 36], edx
	mov	rdi, qword ptr [rbp - 128] # 8-byte Reload
	call	_ZdlPv@PLT
	jmp	.LBB1_27
.LBB1_17:
	mov	edi, 24
	call	_Znwm@PLT
	mov	rcx, rax
	mov	rdx, rax
.Ltmp0:
	mov	esi, 5
	mov	r8d, 9
	mov	rdi, rax
	mov	qword ptr [rbp - 144], rdx # 8-byte Spill
	mov	edx, r8d
	mov	qword ptr [rbp - 152], rcx # 8-byte Spill
	call	_ZN8TriangleC2Eii
.Ltmp1:
	jmp	.LBB1_18
.LBB1_18:
	mov	rax, qword ptr [rbp - 144] # 8-byte Reload
	mov	qword ptr [rbp - 24], rax
	mov	rax, qword ptr [rbp - 24]
	mov	rdi, rax
	lea	rsi, [rip + .L.str.6]
	call	_ZN6Object8set_nameEPKc
	jmp	.LBB1_21
.LBB1_19:
.Ltmp2:
                                        # kill: def $edx killed $edx killed $rdx
	mov	qword ptr [rbp - 32], rax
	mov	dword ptr [rbp - 36], edx
	mov	rdi, qword ptr [rbp - 152] # 8-byte Reload
	call	_ZdlPv@PLT
	jmp	.LBB1_27
.LBB1_20:
	lea	rdi, [rip + .L.str.7]
	mov	al, 0
	call	printf@PLT
	mov	dword ptr [rbp - 4], -1
	jmp	.LBB1_26
.LBB1_21:
	mov	rax, qword ptr [rbp - 24]
	mov	rdi, rax
	call	_ZN6Object4nameEv
	mov	qword ptr [rbp - 48], rax
	mov	rax, qword ptr [rbp - 24]
	mov	rcx, qword ptr [rax]
	mov	rdi, rax
	call	qword ptr [rcx + 16]
	movsd	qword ptr [rbp - 56], xmm0
	mov	rax, qword ptr [rbp - 24]
	mov	rcx, qword ptr [rax]
	mov	rdi, rax
	call	qword ptr [rcx + 24]
	movsd	qword ptr [rbp - 64], xmm0
	mov	rsi, qword ptr [rbp - 48]
	movsd	xmm0, qword ptr [rbp - 56] # xmm0 = mem[0],zero
	movsd	xmm1, qword ptr [rbp - 64] # xmm1 = mem[0],zero
	lea	rdi, [rip + .L.str.8]
	mov	al, 2
	call	printf@PLT
	cmp	qword ptr [rbp - 24], 0
	je	.LBB1_25
# %bb.22:
	mov	rax, qword ptr [rbp - 24]
	cmp	rax, 0
	mov	qword ptr [rbp - 160], rax # 8-byte Spill
	je	.LBB1_24
# %bb.23:
	mov	rax, qword ptr [rbp - 160] # 8-byte Reload
	mov	rcx, qword ptr [rax]
	mov	rdi, rax
	call	qword ptr [rcx + 8]
.LBB1_24:
	mov	qword ptr [rbp - 24], 0
.LBB1_25:
	mov	dword ptr [rbp - 4], 0
.LBB1_26:
	mov	eax, dword ptr [rbp - 4]
	add	rsp, 160
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.LBB1_27:
	.cfi_def_cfa rbp, 16
	mov	rdi, qword ptr [rbp - 32]
	call	_Unwind_Resume@PLT
.Lfunc_end1:
	.size	main, .Lfunc_end1-main
	.cfi_endproc
	.section	.rodata,"a",@progbits
	.p2align	2
.LJTI1_0:
	.long	.LBB1_5-.LJTI1_0
	.long	.LBB1_20-.LJTI1_0
	.long	.LBB1_20-.LJTI1_0
	.long	.LBB1_20-.LJTI1_0
	.long	.LBB1_20-.LJTI1_0
	.long	.LBB1_20-.LJTI1_0
	.long	.LBB1_20-.LJTI1_0
	.long	.LBB1_20-.LJTI1_0
	.long	.LBB1_20-.LJTI1_0
	.long	.LBB1_20-.LJTI1_0
	.long	.LBB1_20-.LJTI1_0
	.long	.LBB1_20-.LJTI1_0
	.long	.LBB1_20-.LJTI1_0
	.long	.LBB1_11-.LJTI1_0
	.long	.LBB1_20-.LJTI1_0
	.long	.LBB1_8-.LJTI1_0
	.long	.LBB1_14-.LJTI1_0
	.long	.LBB1_17-.LJTI1_0
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table1:
.Lexception0:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end0-.Lcst_begin0
.Lcst_begin0:
	.uleb128 .Lfunc_begin0-.Lfunc_begin0 # >> Call Site 1 <<
	.uleb128 .Ltmp12-.Lfunc_begin0  #   Call between .Lfunc_begin0 and .Ltmp12
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp12-.Lfunc_begin0  # >> Call Site 2 <<
	.uleb128 .Ltmp13-.Ltmp12        #   Call between .Ltmp12 and .Ltmp13
	.uleb128 .Ltmp14-.Lfunc_begin0  #     jumps to .Ltmp14
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp13-.Lfunc_begin0  # >> Call Site 3 <<
	.uleb128 .Ltmp9-.Ltmp13         #   Call between .Ltmp13 and .Ltmp9
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp9-.Lfunc_begin0   # >> Call Site 4 <<
	.uleb128 .Ltmp10-.Ltmp9         #   Call between .Ltmp9 and .Ltmp10
	.uleb128 .Ltmp11-.Lfunc_begin0  #     jumps to .Ltmp11
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp10-.Lfunc_begin0  # >> Call Site 5 <<
	.uleb128 .Ltmp6-.Ltmp10         #   Call between .Ltmp10 and .Ltmp6
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp6-.Lfunc_begin0   # >> Call Site 6 <<
	.uleb128 .Ltmp7-.Ltmp6          #   Call between .Ltmp6 and .Ltmp7
	.uleb128 .Ltmp8-.Lfunc_begin0   #     jumps to .Ltmp8
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp7-.Lfunc_begin0   # >> Call Site 7 <<
	.uleb128 .Ltmp3-.Ltmp7          #   Call between .Ltmp7 and .Ltmp3
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp3-.Lfunc_begin0   # >> Call Site 8 <<
	.uleb128 .Ltmp4-.Ltmp3          #   Call between .Ltmp3 and .Ltmp4
	.uleb128 .Ltmp5-.Lfunc_begin0   #     jumps to .Ltmp5
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp4-.Lfunc_begin0   # >> Call Site 9 <<
	.uleb128 .Ltmp0-.Ltmp4          #   Call between .Ltmp4 and .Ltmp0
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp0-.Lfunc_begin0   # >> Call Site 10 <<
	.uleb128 .Ltmp1-.Ltmp0          #   Call between .Ltmp0 and .Ltmp1
	.uleb128 .Ltmp2-.Lfunc_begin0   #     jumps to .Ltmp2
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp1-.Lfunc_begin0   # >> Call Site 11 <<
	.uleb128 .Lfunc_end1-.Ltmp1     #   Call between .Ltmp1 and .Lfunc_end1
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end0:
	.p2align	2
                                        # -- End function
	.section	.text._ZN6CircleC2Ei,"axG",@progbits,_ZN6CircleC2Ei,comdat
	.weak	_ZN6CircleC2Ei          # -- Begin function _ZN6CircleC2Ei
	.p2align	4, 0x90
	.type	_ZN6CircleC2Ei,@function
_ZN6CircleC2Ei:                         # @_ZN6CircleC2Ei
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 32
	mov	qword ptr [rbp - 8], rdi
	mov	dword ptr [rbp - 12], esi
	mov	rax, qword ptr [rbp - 8]
	mov	rcx, rax
	mov	rdi, rcx
	mov	qword ptr [rbp - 24], rax # 8-byte Spill
	call	_ZN5ShapeC2Ev
	lea	rax, [rip + _ZTV6Circle]
	add	rax, 16
	mov	rcx, qword ptr [rbp - 24] # 8-byte Reload
	mov	qword ptr [rcx], rax
	mov	edx, dword ptr [rbp - 12]
	mov	dword ptr [rcx + 16], edx
	add	rsp, 32
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end2:
	.size	_ZN6CircleC2Ei, .Lfunc_end2-_ZN6CircleC2Ei
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN6Object8set_nameEPKc,"axG",@progbits,_ZN6Object8set_nameEPKc,comdat
	.weak	_ZN6Object8set_nameEPKc # -- Begin function _ZN6Object8set_nameEPKc
	.p2align	4, 0x90
	.type	_ZN6Object8set_nameEPKc,@function
_ZN6Object8set_nameEPKc:                # @_ZN6Object8set_nameEPKc
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 32
	mov	qword ptr [rbp - 8], rdi
	mov	qword ptr [rbp - 16], rsi
	mov	rax, qword ptr [rbp - 8]
	mov	rdi, qword ptr [rbp - 16]
	mov	qword ptr [rbp - 32], rax # 8-byte Spill
	call	strlen@PLT
	mov	qword ptr [rbp - 24], rax
	mov	rax, qword ptr [rbp - 24]
	add	rax, 1
	mov	rdi, rax
	mov	esi, 1
	call	calloc@PLT
	mov	rcx, qword ptr [rbp - 32] # 8-byte Reload
	mov	qword ptr [rcx + 8], rax
	mov	rdi, qword ptr [rcx + 8]
	mov	rsi, qword ptr [rbp - 16]
	call	strcpy@PLT
	add	rsp, 32
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end3:
	.size	_ZN6Object8set_nameEPKc, .Lfunc_end3-_ZN6Object8set_nameEPKc
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN9RectangleC2Eii,"axG",@progbits,_ZN9RectangleC2Eii,comdat
	.weak	_ZN9RectangleC2Eii      # -- Begin function _ZN9RectangleC2Eii
	.p2align	4, 0x90
	.type	_ZN9RectangleC2Eii,@function
_ZN9RectangleC2Eii:                     # @_ZN9RectangleC2Eii
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 32
	mov	qword ptr [rbp - 8], rdi
	mov	dword ptr [rbp - 12], esi
	mov	dword ptr [rbp - 16], edx
	mov	rax, qword ptr [rbp - 8]
	mov	rcx, rax
	mov	esi, dword ptr [rbp - 12]
	mov	edx, dword ptr [rbp - 16]
	mov	rdi, rcx
	mov	qword ptr [rbp - 24], rax # 8-byte Spill
	call	_ZN13ParallelogramC2Eii
	lea	rax, [rip + _ZTV9Rectangle]
	add	rax, 16
	mov	rcx, qword ptr [rbp - 24] # 8-byte Reload
	mov	qword ptr [rcx], rax
	add	rsp, 32
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end4:
	.size	_ZN9RectangleC2Eii, .Lfunc_end4-_ZN9RectangleC2Eii
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN13ParallelogramC2Eii,"axG",@progbits,_ZN13ParallelogramC2Eii,comdat
	.weak	_ZN13ParallelogramC2Eii # -- Begin function _ZN13ParallelogramC2Eii
	.p2align	4, 0x90
	.type	_ZN13ParallelogramC2Eii,@function
_ZN13ParallelogramC2Eii:                # @_ZN13ParallelogramC2Eii
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 32
	mov	qword ptr [rbp - 8], rdi
	mov	dword ptr [rbp - 12], esi
	mov	dword ptr [rbp - 16], edx
	mov	rax, qword ptr [rbp - 8]
	mov	rcx, rax
	mov	rdi, rcx
	mov	qword ptr [rbp - 24], rax # 8-byte Spill
	call	_ZN5ShapeC2Ev
	lea	rax, [rip + _ZTV13Parallelogram]
	add	rax, 16
	mov	rcx, qword ptr [rbp - 24] # 8-byte Reload
	mov	qword ptr [rcx], rax
	mov	edx, dword ptr [rbp - 12]
	mov	dword ptr [rcx + 16], edx
	mov	edx, dword ptr [rbp - 16]
	mov	dword ptr [rcx + 20], edx
	add	rsp, 32
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end5:
	.size	_ZN13ParallelogramC2Eii, .Lfunc_end5-_ZN13ParallelogramC2Eii
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN6SquareC2Ei,"axG",@progbits,_ZN6SquareC2Ei,comdat
	.weak	_ZN6SquareC2Ei          # -- Begin function _ZN6SquareC2Ei
	.p2align	4, 0x90
	.type	_ZN6SquareC2Ei,@function
_ZN6SquareC2Ei:                         # @_ZN6SquareC2Ei
.Lfunc_begin1:
	.cfi_startproc
	.cfi_personality 155, DW.ref.__gxx_personality_v0
	.cfi_lsda 27, .Lexception1
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 48
	mov	qword ptr [rbp - 8], rdi
	mov	dword ptr [rbp - 12], esi
	mov	rax, qword ptr [rbp - 8]
	mov	ecx, dword ptr [rbp - 12]
	mov	rdi, rax
	mov	esi, ecx
	mov	edx, ecx
	mov	qword ptr [rbp - 40], rax # 8-byte Spill
	call	_ZN9RectangleC2Eii
	mov	rax, qword ptr [rbp - 40] # 8-byte Reload
	add	rax, 24
.Ltmp15:
	mov	esi, 4
	mov	rdi, rax
	call	_ZN11RegularNGonC2Ei
.Ltmp16:
	jmp	.LBB6_1
.LBB6_1:
	lea	rax, [rip + _ZTV6Square]
	mov	rcx, rax
	add	rcx, 64
	add	rax, 16
	mov	rdx, qword ptr [rbp - 40] # 8-byte Reload
	mov	qword ptr [rdx], rax
	mov	qword ptr [rdx + 24], rcx
	add	rsp, 48
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.LBB6_2:
	.cfi_def_cfa rbp, 16
.Ltmp17:
                                        # kill: def $edx killed $edx killed $rdx
	mov	qword ptr [rbp - 24], rax
	mov	dword ptr [rbp - 28], edx
	mov	rax, qword ptr [rbp - 40] # 8-byte Reload
	mov	rdi, rax
	call	_ZN9RectangleD2Ev
# %bb.3:
	mov	rdi, qword ptr [rbp - 24]
	call	_Unwind_Resume@PLT
.Lfunc_end6:
	.size	_ZN6SquareC2Ei, .Lfunc_end6-_ZN6SquareC2Ei
	.cfi_endproc
	.section	.gcc_except_table,"a",@progbits
	.p2align	2
GCC_except_table6:
.Lexception1:
	.byte	255                     # @LPStart Encoding = omit
	.byte	255                     # @TType Encoding = omit
	.byte	1                       # Call site Encoding = uleb128
	.uleb128 .Lcst_end1-.Lcst_begin1
.Lcst_begin1:
	.uleb128 .Lfunc_begin1-.Lfunc_begin1 # >> Call Site 1 <<
	.uleb128 .Ltmp15-.Lfunc_begin1  #   Call between .Lfunc_begin1 and .Ltmp15
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp15-.Lfunc_begin1  # >> Call Site 2 <<
	.uleb128 .Ltmp16-.Ltmp15        #   Call between .Ltmp15 and .Ltmp16
	.uleb128 .Ltmp17-.Lfunc_begin1  #     jumps to .Ltmp17
	.byte	0                       #   On action: cleanup
	.uleb128 .Ltmp16-.Lfunc_begin1  # >> Call Site 3 <<
	.uleb128 .Lfunc_end6-.Ltmp16    #   Call between .Ltmp16 and .Lfunc_end6
	.byte	0                       #     has no landing pad
	.byte	0                       #   On action: cleanup
.Lcst_end1:
	.p2align	2
                                        # -- End function
	.section	.text._ZN8TriangleC2Eii,"axG",@progbits,_ZN8TriangleC2Eii,comdat
	.weak	_ZN8TriangleC2Eii       # -- Begin function _ZN8TriangleC2Eii
	.p2align	4, 0x90
	.type	_ZN8TriangleC2Eii,@function
_ZN8TriangleC2Eii:                      # @_ZN8TriangleC2Eii
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 32
	mov	qword ptr [rbp - 8], rdi
	mov	dword ptr [rbp - 12], esi
	mov	dword ptr [rbp - 16], edx
	mov	rax, qword ptr [rbp - 8]
	mov	rcx, rax
	mov	rdi, rcx
	mov	qword ptr [rbp - 24], rax # 8-byte Spill
	call	_ZN5ShapeC2Ev
	lea	rax, [rip + _ZTV8Triangle]
	add	rax, 16
	mov	rcx, qword ptr [rbp - 24] # 8-byte Reload
	mov	qword ptr [rcx], rax
	mov	edx, dword ptr [rbp - 12]
	mov	dword ptr [rcx + 16], edx
	mov	edx, dword ptr [rbp - 16]
	mov	dword ptr [rcx + 20], edx
	add	rsp, 32
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end7:
	.size	_ZN8TriangleC2Eii, .Lfunc_end7-_ZN8TriangleC2Eii
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN6Object4nameEv,"axG",@progbits,_ZN6Object4nameEv,comdat
	.weak	_ZN6Object4nameEv       # -- Begin function _ZN6Object4nameEv
	.p2align	4, 0x90
	.type	_ZN6Object4nameEv,@function
_ZN6Object4nameEv:                      # @_ZN6Object4nameEv
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	mov	qword ptr [rbp - 8], rdi
	mov	rax, qword ptr [rbp - 8]
	mov	rax, qword ptr [rax + 8]
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end8:
	.size	_ZN6Object4nameEv, .Lfunc_end8-_ZN6Object4nameEv
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN5ShapeC2Ev,"axG",@progbits,_ZN5ShapeC2Ev,comdat
	.weak	_ZN5ShapeC2Ev           # -- Begin function _ZN5ShapeC2Ev
	.p2align	4, 0x90
	.type	_ZN5ShapeC2Ev,@function
_ZN5ShapeC2Ev:                          # @_ZN5ShapeC2Ev
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 16
	mov	qword ptr [rbp - 8], rdi
	mov	rax, qword ptr [rbp - 8]
	mov	rcx, rax
	mov	rdi, rcx
	mov	qword ptr [rbp - 16], rax # 8-byte Spill
	call	_ZN6ObjectC2Ev
	lea	rax, [rip + _ZTV5Shape]
	add	rax, 16
	mov	rcx, qword ptr [rbp - 16] # 8-byte Reload
	mov	qword ptr [rcx], rax
	add	rsp, 16
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end9:
	.size	_ZN5ShapeC2Ev, .Lfunc_end9-_ZN5ShapeC2Ev
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN6CircleD2Ev,"axG",@progbits,_ZN6CircleD2Ev,comdat
	.weak	_ZN6CircleD2Ev          # -- Begin function _ZN6CircleD2Ev
	.p2align	4, 0x90
	.type	_ZN6CircleD2Ev,@function
_ZN6CircleD2Ev:                         # @_ZN6CircleD2Ev
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 16
	mov	qword ptr [rbp - 8], rdi
	mov	rax, qword ptr [rbp - 8]
	mov	rdi, rax
	call	_ZN5ShapeD2Ev
	add	rsp, 16
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end10:
	.size	_ZN6CircleD2Ev, .Lfunc_end10-_ZN6CircleD2Ev
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN6CircleD0Ev,"axG",@progbits,_ZN6CircleD0Ev,comdat
	.weak	_ZN6CircleD0Ev          # -- Begin function _ZN6CircleD0Ev
	.p2align	4, 0x90
	.type	_ZN6CircleD0Ev,@function
_ZN6CircleD0Ev:                         # @_ZN6CircleD0Ev
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 16
	mov	qword ptr [rbp - 8], rdi
	mov	rax, qword ptr [rbp - 8]
	mov	rdi, rax
	mov	qword ptr [rbp - 16], rax # 8-byte Spill
	call	_ZN6CircleD2Ev
	mov	rax, qword ptr [rbp - 16] # 8-byte Reload
	mov	rdi, rax
	call	_ZdlPv@PLT
	add	rsp, 16
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end11:
	.size	_ZN6CircleD0Ev, .Lfunc_end11-_ZN6CircleD0Ev
	.cfi_endproc
                                        # -- End function
	.section	.rodata.cst8,"aM",@progbits,8
	.p2align	3               # -- Begin function _ZN6Circle4areaEv
.LCPI12_0:
	.quad	4614256656543962353     # double 3.1415926500000002
	.section	.text._ZN6Circle4areaEv,"axG",@progbits,_ZN6Circle4areaEv,comdat
	.weak	_ZN6Circle4areaEv
	.p2align	4, 0x90
	.type	_ZN6Circle4areaEv,@function
_ZN6Circle4areaEv:                      # @_ZN6Circle4areaEv
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	movsd	xmm0, qword ptr [rip + .LCPI12_0] # xmm0 = mem[0],zero
	mov	qword ptr [rbp - 8], rdi
	mov	rax, qword ptr [rbp - 8]
	mov	ecx, dword ptr [rax + 16]
	xor	ecx, 2
	imul	ecx, ecx, 0
	cvtsi2sd	xmm1, ecx
	mulsd	xmm1, xmm0
	movaps	xmm0, xmm1
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end12:
	.size	_ZN6Circle4areaEv, .Lfunc_end12-_ZN6Circle4areaEv
	.cfi_endproc
                                        # -- End function
	.section	.rodata.cst8,"aM",@progbits,8
	.p2align	3               # -- Begin function _ZN6Circle13circumferenceEv
.LCPI13_0:
	.quad	4614256656543962353     # double 3.1415926500000002
	.section	.text._ZN6Circle13circumferenceEv,"axG",@progbits,_ZN6Circle13circumferenceEv,comdat
	.weak	_ZN6Circle13circumferenceEv
	.p2align	4, 0x90
	.type	_ZN6Circle13circumferenceEv,@function
_ZN6Circle13circumferenceEv:            # @_ZN6Circle13circumferenceEv
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	movsd	xmm0, qword ptr [rip + .LCPI13_0] # xmm0 = mem[0],zero
	mov	qword ptr [rbp - 8], rdi
	mov	rax, qword ptr [rbp - 8]
	mov	ecx, dword ptr [rax + 16]
	shl	ecx, 1
	cvtsi2sd	xmm1, ecx
	mulsd	xmm1, xmm0
	movaps	xmm0, xmm1
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end13:
	.size	_ZN6Circle13circumferenceEv, .Lfunc_end13-_ZN6Circle13circumferenceEv
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN6ObjectC2Ev,"axG",@progbits,_ZN6ObjectC2Ev,comdat
	.weak	_ZN6ObjectC2Ev          # -- Begin function _ZN6ObjectC2Ev
	.p2align	4, 0x90
	.type	_ZN6ObjectC2Ev,@function
_ZN6ObjectC2Ev:                         # @_ZN6ObjectC2Ev
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	lea	rax, [rip + _ZTV6Object]
	add	rax, 16
	mov	qword ptr [rbp - 8], rdi
	mov	rcx, qword ptr [rbp - 8]
	mov	qword ptr [rcx], rax
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end14:
	.size	_ZN6ObjectC2Ev, .Lfunc_end14-_ZN6ObjectC2Ev
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN5ShapeD2Ev,"axG",@progbits,_ZN5ShapeD2Ev,comdat
	.weak	_ZN5ShapeD2Ev           # -- Begin function _ZN5ShapeD2Ev
	.p2align	4, 0x90
	.type	_ZN5ShapeD2Ev,@function
_ZN5ShapeD2Ev:                          # @_ZN5ShapeD2Ev
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 16
	mov	qword ptr [rbp - 8], rdi
	mov	rax, qword ptr [rbp - 8]
	mov	rdi, rax
	call	_ZN6ObjectD2Ev
	add	rsp, 16
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end15:
	.size	_ZN5ShapeD2Ev, .Lfunc_end15-_ZN5ShapeD2Ev
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN5ShapeD0Ev,"axG",@progbits,_ZN5ShapeD0Ev,comdat
	.weak	_ZN5ShapeD0Ev           # -- Begin function _ZN5ShapeD0Ev
	.p2align	4, 0x90
	.type	_ZN5ShapeD0Ev,@function
_ZN5ShapeD0Ev:                          # @_ZN5ShapeD0Ev
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	mov	qword ptr [rbp - 8], rdi
	ud2
.Lfunc_end16:
	.size	_ZN5ShapeD0Ev, .Lfunc_end16-_ZN5ShapeD0Ev
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN6ObjectD2Ev,"axG",@progbits,_ZN6ObjectD2Ev,comdat
	.weak	_ZN6ObjectD2Ev          # -- Begin function _ZN6ObjectD2Ev
	.p2align	4, 0x90
	.type	_ZN6ObjectD2Ev,@function
_ZN6ObjectD2Ev:                         # @_ZN6ObjectD2Ev
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 16
	lea	rax, [rip + _ZTV6Object]
	add	rax, 16
	mov	qword ptr [rbp - 8], rdi
	mov	rcx, qword ptr [rbp - 8]
	mov	qword ptr [rcx], rax
	cmp	qword ptr [rcx + 8], 0
	mov	qword ptr [rbp - 16], rcx # 8-byte Spill
	je	.LBB17_2
# %bb.1:
	mov	rax, qword ptr [rbp - 16] # 8-byte Reload
	mov	rdi, qword ptr [rax + 8]
	call	free@PLT
	mov	rax, qword ptr [rbp - 16] # 8-byte Reload
	mov	qword ptr [rax + 8], 0
.LBB17_2:
	add	rsp, 16
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end17:
	.size	_ZN6ObjectD2Ev, .Lfunc_end17-_ZN6ObjectD2Ev
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN6ObjectD0Ev,"axG",@progbits,_ZN6ObjectD0Ev,comdat
	.weak	_ZN6ObjectD0Ev          # -- Begin function _ZN6ObjectD0Ev
	.p2align	4, 0x90
	.type	_ZN6ObjectD0Ev,@function
_ZN6ObjectD0Ev:                         # @_ZN6ObjectD0Ev
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 16
	mov	qword ptr [rbp - 8], rdi
	mov	rax, qword ptr [rbp - 8]
	mov	rdi, rax
	mov	qword ptr [rbp - 16], rax # 8-byte Spill
	call	_ZN6ObjectD2Ev
	mov	rax, qword ptr [rbp - 16] # 8-byte Reload
	mov	rdi, rax
	call	_ZdlPv@PLT
	add	rsp, 16
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end18:
	.size	_ZN6ObjectD0Ev, .Lfunc_end18-_ZN6ObjectD0Ev
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN9RectangleD2Ev,"axG",@progbits,_ZN9RectangleD2Ev,comdat
	.weak	_ZN9RectangleD2Ev       # -- Begin function _ZN9RectangleD2Ev
	.p2align	4, 0x90
	.type	_ZN9RectangleD2Ev,@function
_ZN9RectangleD2Ev:                      # @_ZN9RectangleD2Ev
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 16
	mov	qword ptr [rbp - 8], rdi
	mov	rax, qword ptr [rbp - 8]
	mov	rdi, rax
	call	_ZN13ParallelogramD2Ev
	add	rsp, 16
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end19:
	.size	_ZN9RectangleD2Ev, .Lfunc_end19-_ZN9RectangleD2Ev
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN9RectangleD0Ev,"axG",@progbits,_ZN9RectangleD0Ev,comdat
	.weak	_ZN9RectangleD0Ev       # -- Begin function _ZN9RectangleD0Ev
	.p2align	4, 0x90
	.type	_ZN9RectangleD0Ev,@function
_ZN9RectangleD0Ev:                      # @_ZN9RectangleD0Ev
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 16
	mov	qword ptr [rbp - 8], rdi
	mov	rax, qword ptr [rbp - 8]
	mov	rdi, rax
	mov	qword ptr [rbp - 16], rax # 8-byte Spill
	call	_ZN9RectangleD2Ev
	mov	rax, qword ptr [rbp - 16] # 8-byte Reload
	mov	rdi, rax
	call	_ZdlPv@PLT
	add	rsp, 16
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end20:
	.size	_ZN9RectangleD0Ev, .Lfunc_end20-_ZN9RectangleD0Ev
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN13Parallelogram4areaEv,"axG",@progbits,_ZN13Parallelogram4areaEv,comdat
	.weak	_ZN13Parallelogram4areaEv # -- Begin function _ZN13Parallelogram4areaEv
	.p2align	4, 0x90
	.type	_ZN13Parallelogram4areaEv,@function
_ZN13Parallelogram4areaEv:              # @_ZN13Parallelogram4areaEv
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	mov	qword ptr [rbp - 8], rdi
	mov	rax, qword ptr [rbp - 8]
	mov	ecx, dword ptr [rax + 16]
	imul	ecx, dword ptr [rax + 20]
	cvtsi2sd	xmm0, ecx
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end21:
	.size	_ZN13Parallelogram4areaEv, .Lfunc_end21-_ZN13Parallelogram4areaEv
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN13Parallelogram13circumferenceEv,"axG",@progbits,_ZN13Parallelogram13circumferenceEv,comdat
	.weak	_ZN13Parallelogram13circumferenceEv # -- Begin function _ZN13Parallelogram13circumferenceEv
	.p2align	4, 0x90
	.type	_ZN13Parallelogram13circumferenceEv,@function
_ZN13Parallelogram13circumferenceEv:    # @_ZN13Parallelogram13circumferenceEv
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	mov	qword ptr [rbp - 8], rdi
	mov	rax, qword ptr [rbp - 8]
	mov	ecx, dword ptr [rax + 16]
	add	ecx, dword ptr [rax + 20]
	shl	ecx, 1
	cvtsi2sd	xmm0, ecx
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end22:
	.size	_ZN13Parallelogram13circumferenceEv, .Lfunc_end22-_ZN13Parallelogram13circumferenceEv
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN13ParallelogramD2Ev,"axG",@progbits,_ZN13ParallelogramD2Ev,comdat
	.weak	_ZN13ParallelogramD2Ev  # -- Begin function _ZN13ParallelogramD2Ev
	.p2align	4, 0x90
	.type	_ZN13ParallelogramD2Ev,@function
_ZN13ParallelogramD2Ev:                 # @_ZN13ParallelogramD2Ev
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 16
	mov	qword ptr [rbp - 8], rdi
	mov	rax, qword ptr [rbp - 8]
	mov	rdi, rax
	call	_ZN5ShapeD2Ev
	add	rsp, 16
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end23:
	.size	_ZN13ParallelogramD2Ev, .Lfunc_end23-_ZN13ParallelogramD2Ev
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN13ParallelogramD0Ev,"axG",@progbits,_ZN13ParallelogramD0Ev,comdat
	.weak	_ZN13ParallelogramD0Ev  # -- Begin function _ZN13ParallelogramD0Ev
	.p2align	4, 0x90
	.type	_ZN13ParallelogramD0Ev,@function
_ZN13ParallelogramD0Ev:                 # @_ZN13ParallelogramD0Ev
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 16
	mov	qword ptr [rbp - 8], rdi
	mov	rax, qword ptr [rbp - 8]
	mov	rdi, rax
	mov	qword ptr [rbp - 16], rax # 8-byte Spill
	call	_ZN13ParallelogramD2Ev
	mov	rax, qword ptr [rbp - 16] # 8-byte Reload
	mov	rdi, rax
	call	_ZdlPv@PLT
	add	rsp, 16
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end24:
	.size	_ZN13ParallelogramD0Ev, .Lfunc_end24-_ZN13ParallelogramD0Ev
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN11RegularNGonC2Ei,"axG",@progbits,_ZN11RegularNGonC2Ei,comdat
	.weak	_ZN11RegularNGonC2Ei    # -- Begin function _ZN11RegularNGonC2Ei
	.p2align	4, 0x90
	.type	_ZN11RegularNGonC2Ei,@function
_ZN11RegularNGonC2Ei:                   # @_ZN11RegularNGonC2Ei
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	lea	rax, [rip + _ZTV11RegularNGon]
	add	rax, 16
	mov	qword ptr [rbp - 8], rdi
	mov	dword ptr [rbp - 12], esi
	mov	rcx, qword ptr [rbp - 8]
	mov	qword ptr [rcx], rax
	mov	edx, dword ptr [rbp - 12]
	mov	dword ptr [rcx + 8], edx
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end25:
	.size	_ZN11RegularNGonC2Ei, .Lfunc_end25-_ZN11RegularNGonC2Ei
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN6SquareD2Ev,"axG",@progbits,_ZN6SquareD2Ev,comdat
	.weak	_ZN6SquareD2Ev          # -- Begin function _ZN6SquareD2Ev
	.p2align	4, 0x90
	.type	_ZN6SquareD2Ev,@function
_ZN6SquareD2Ev:                         # @_ZN6SquareD2Ev
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 16
	mov	qword ptr [rbp - 8], rdi
	mov	rax, qword ptr [rbp - 8]
	mov	rcx, rax
	add	rcx, 24
	mov	rdi, rcx
	mov	qword ptr [rbp - 16], rax # 8-byte Spill
	call	_ZN11RegularNGonD2Ev
	mov	rax, qword ptr [rbp - 16] # 8-byte Reload
	mov	rdi, rax
	call	_ZN9RectangleD2Ev
	add	rsp, 16
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end26:
	.size	_ZN6SquareD2Ev, .Lfunc_end26-_ZN6SquareD2Ev
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN6SquareD0Ev,"axG",@progbits,_ZN6SquareD0Ev,comdat
	.weak	_ZN6SquareD0Ev          # -- Begin function _ZN6SquareD0Ev
	.p2align	4, 0x90
	.type	_ZN6SquareD0Ev,@function
_ZN6SquareD0Ev:                         # @_ZN6SquareD0Ev
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 16
	mov	qword ptr [rbp - 8], rdi
	mov	rax, qword ptr [rbp - 8]
	mov	rdi, rax
	mov	qword ptr [rbp - 16], rax # 8-byte Spill
	call	_ZN6SquareD2Ev
	mov	rax, qword ptr [rbp - 16] # 8-byte Reload
	mov	rdi, rax
	call	_ZdlPv@PLT
	add	rsp, 16
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end27:
	.size	_ZN6SquareD0Ev, .Lfunc_end27-_ZN6SquareD0Ev
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN6Square13circumferenceEv,"axG",@progbits,_ZN6Square13circumferenceEv,comdat
	.weak	_ZN6Square13circumferenceEv # -- Begin function _ZN6Square13circumferenceEv
	.p2align	4, 0x90
	.type	_ZN6Square13circumferenceEv,@function
_ZN6Square13circumferenceEv:            # @_ZN6Square13circumferenceEv
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	mov	qword ptr [rbp - 8], rdi
	mov	rax, qword ptr [rbp - 8]
	mov	ecx, dword ptr [rax + 32]
	imul	ecx, dword ptr [rax + 16]
	cvtsi2sd	xmm0, ecx
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end28:
	.size	_ZN6Square13circumferenceEv, .Lfunc_end28-_ZN6Square13circumferenceEv
	.cfi_endproc
                                        # -- End function
	.section	.text._ZThn24_N6SquareD1Ev,"axG",@progbits,_ZThn24_N6SquareD1Ev,comdat
	.weak	_ZThn24_N6SquareD1Ev    # -- Begin function _ZThn24_N6SquareD1Ev
	.p2align	4, 0x90
	.type	_ZThn24_N6SquareD1Ev,@function
_ZThn24_N6SquareD1Ev:                   # @_ZThn24_N6SquareD1Ev
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	mov	qword ptr [rbp - 8], rdi
	mov	rax, qword ptr [rbp - 8]
	add	rax, -24
	mov	rdi, rax
	pop	rbp
	.cfi_def_cfa rsp, 8
	jmp	_ZN6SquareD2Ev          # TAILCALL
.Lfunc_end29:
	.size	_ZThn24_N6SquareD1Ev, .Lfunc_end29-_ZThn24_N6SquareD1Ev
	.cfi_endproc
                                        # -- End function
	.section	.text._ZThn24_N6SquareD0Ev,"axG",@progbits,_ZThn24_N6SquareD0Ev,comdat
	.weak	_ZThn24_N6SquareD0Ev    # -- Begin function _ZThn24_N6SquareD0Ev
	.p2align	4, 0x90
	.type	_ZThn24_N6SquareD0Ev,@function
_ZThn24_N6SquareD0Ev:                   # @_ZThn24_N6SquareD0Ev
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	mov	qword ptr [rbp - 8], rdi
	mov	rax, qword ptr [rbp - 8]
	add	rax, -24
	mov	rdi, rax
	pop	rbp
	.cfi_def_cfa rsp, 8
	jmp	_ZN6SquareD0Ev          # TAILCALL
.Lfunc_end30:
	.size	_ZThn24_N6SquareD0Ev, .Lfunc_end30-_ZThn24_N6SquareD0Ev
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN11RegularNGonD2Ev,"axG",@progbits,_ZN11RegularNGonD2Ev,comdat
	.weak	_ZN11RegularNGonD2Ev    # -- Begin function _ZN11RegularNGonD2Ev
	.p2align	4, 0x90
	.type	_ZN11RegularNGonD2Ev,@function
_ZN11RegularNGonD2Ev:                   # @_ZN11RegularNGonD2Ev
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	mov	qword ptr [rbp - 8], rdi
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end31:
	.size	_ZN11RegularNGonD2Ev, .Lfunc_end31-_ZN11RegularNGonD2Ev
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN11RegularNGonD0Ev,"axG",@progbits,_ZN11RegularNGonD0Ev,comdat
	.weak	_ZN11RegularNGonD0Ev    # -- Begin function _ZN11RegularNGonD0Ev
	.p2align	4, 0x90
	.type	_ZN11RegularNGonD0Ev,@function
_ZN11RegularNGonD0Ev:                   # @_ZN11RegularNGonD0Ev
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 16
	mov	qword ptr [rbp - 8], rdi
	mov	rax, qword ptr [rbp - 8]
	mov	rdi, rax
	mov	qword ptr [rbp - 16], rax # 8-byte Spill
	call	_ZN11RegularNGonD2Ev
	mov	rax, qword ptr [rbp - 16] # 8-byte Reload
	mov	rdi, rax
	call	_ZdlPv@PLT
	add	rsp, 16
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end32:
	.size	_ZN11RegularNGonD0Ev, .Lfunc_end32-_ZN11RegularNGonD0Ev
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN8TriangleD2Ev,"axG",@progbits,_ZN8TriangleD2Ev,comdat
	.weak	_ZN8TriangleD2Ev        # -- Begin function _ZN8TriangleD2Ev
	.p2align	4, 0x90
	.type	_ZN8TriangleD2Ev,@function
_ZN8TriangleD2Ev:                       # @_ZN8TriangleD2Ev
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 16
	mov	qword ptr [rbp - 8], rdi
	mov	rax, qword ptr [rbp - 8]
	mov	rdi, rax
	call	_ZN5ShapeD2Ev
	add	rsp, 16
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end33:
	.size	_ZN8TriangleD2Ev, .Lfunc_end33-_ZN8TriangleD2Ev
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN8TriangleD0Ev,"axG",@progbits,_ZN8TriangleD0Ev,comdat
	.weak	_ZN8TriangleD0Ev        # -- Begin function _ZN8TriangleD0Ev
	.p2align	4, 0x90
	.type	_ZN8TriangleD0Ev,@function
_ZN8TriangleD0Ev:                       # @_ZN8TriangleD0Ev
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 16
	mov	qword ptr [rbp - 8], rdi
	mov	rax, qword ptr [rbp - 8]
	mov	rdi, rax
	mov	qword ptr [rbp - 16], rax # 8-byte Spill
	call	_ZN8TriangleD2Ev
	mov	rax, qword ptr [rbp - 16] # 8-byte Reload
	mov	rdi, rax
	call	_ZdlPv@PLT
	add	rsp, 16
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end34:
	.size	_ZN8TriangleD0Ev, .Lfunc_end34-_ZN8TriangleD0Ev
	.cfi_endproc
                                        # -- End function
	.section	.rodata.cst8,"aM",@progbits,8
	.p2align	3               # -- Begin function _ZN8Triangle4areaEv
.LCPI35_0:
	.quad	4602678819172646912     # double 0.5
	.section	.text._ZN8Triangle4areaEv,"axG",@progbits,_ZN8Triangle4areaEv,comdat
	.weak	_ZN8Triangle4areaEv
	.p2align	4, 0x90
	.type	_ZN8Triangle4areaEv,@function
_ZN8Triangle4areaEv:                    # @_ZN8Triangle4areaEv
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	movsd	xmm0, qword ptr [rip + .LCPI35_0] # xmm0 = mem[0],zero
	mov	qword ptr [rbp - 8], rdi
	mov	rax, qword ptr [rbp - 8]
	cvtsi2sd	xmm1, dword ptr [rax + 16]
	mulsd	xmm0, xmm1
	cvtsi2sd	xmm1, dword ptr [rax + 20]
	mulsd	xmm0, xmm1
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end35:
	.size	_ZN8Triangle4areaEv, .Lfunc_end35-_ZN8Triangle4areaEv
	.cfi_endproc
                                        # -- End function
	.section	.text._ZN8Triangle13circumferenceEv,"axG",@progbits,_ZN8Triangle13circumferenceEv,comdat
	.weak	_ZN8Triangle13circumferenceEv # -- Begin function _ZN8Triangle13circumferenceEv
	.p2align	4, 0x90
	.type	_ZN8Triangle13circumferenceEv,@function
_ZN8Triangle13circumferenceEv:          # @_ZN8Triangle13circumferenceEv
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 16
	mov	qword ptr [rbp - 8], rdi
	mov	rax, qword ptr [rbp - 8]
	mov	ecx, dword ptr [rax + 16]
	add	ecx, dword ptr [rax + 20]
	cvtsi2sd	xmm0, ecx
	mov	ecx, dword ptr [rax + 16]
	mov	edx, dword ptr [rax + 20]
	add	edx, 2
	xor	ecx, edx
	xor	ecx, 2
	mov	edi, ecx
	movsd	qword ptr [rbp - 16], xmm0 # 8-byte Spill
	call	_ZSt4sqrtIiEN9__gnu_cxx11__enable_ifIXsr12__is_integerIT_EE7__valueEdE6__typeES2_
	movsd	xmm1, qword ptr [rbp - 16] # 8-byte Reload
                                        # xmm1 = mem[0],zero
	addsd	xmm1, xmm0
	movaps	xmm0, xmm1
	add	rsp, 16
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end36:
	.size	_ZN8Triangle13circumferenceEv, .Lfunc_end36-_ZN8Triangle13circumferenceEv
	.cfi_endproc
                                        # -- End function
	.section	.text._ZSt4sqrtIiEN9__gnu_cxx11__enable_ifIXsr12__is_integerIT_EE7__valueEdE6__typeES2_,"axG",@progbits,_ZSt4sqrtIiEN9__gnu_cxx11__enable_ifIXsr12__is_integerIT_EE7__valueEdE6__typeES2_,comdat
	.weak	_ZSt4sqrtIiEN9__gnu_cxx11__enable_ifIXsr12__is_integerIT_EE7__valueEdE6__typeES2_ # -- Begin function _ZSt4sqrtIiEN9__gnu_cxx11__enable_ifIXsr12__is_integerIT_EE7__valueEdE6__typeES2_
	.p2align	4, 0x90
	.type	_ZSt4sqrtIiEN9__gnu_cxx11__enable_ifIXsr12__is_integerIT_EE7__valueEdE6__typeES2_,@function
_ZSt4sqrtIiEN9__gnu_cxx11__enable_ifIXsr12__is_integerIT_EE7__valueEdE6__typeES2_: # @_ZSt4sqrtIiEN9__gnu_cxx11__enable_ifIXsr12__is_integerIT_EE7__valueEdE6__typeES2_
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 16
	mov	dword ptr [rbp - 4], edi
	cvtsi2sd	xmm0, dword ptr [rbp - 4]
	call	sqrt@PLT
	add	rsp, 16
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end37:
	.size	_ZSt4sqrtIiEN9__gnu_cxx11__enable_ifIXsr12__is_integerIT_EE7__valueEdE6__typeES2_, .Lfunc_end37-_ZSt4sqrtIiEN9__gnu_cxx11__enable_ifIXsr12__is_integerIT_EE7__valueEdE6__typeES2_
	.cfi_endproc
                                        # -- End function
	.section	.text.startup,"ax",@progbits
	.p2align	4, 0x90         # -- Begin function _GLOBAL__sub_I_shapes.cpp
	.type	_GLOBAL__sub_I_shapes.cpp,@function
_GLOBAL__sub_I_shapes.cpp:              # @_GLOBAL__sub_I_shapes.cpp
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	call	__cxx_global_var_init
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end38:
	.size	_GLOBAL__sub_I_shapes.cpp, .Lfunc_end38-_GLOBAL__sub_I_shapes.cpp
	.cfi_endproc
                                        # -- End function
	.type	_ZStL8__ioinit,@object  # @_ZStL8__ioinit
	.local	_ZStL8__ioinit
	.comm	_ZStL8__ioinit,1,1
	.hidden	__dso_handle
	.type	.L.str,@object          # @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"Not enough arguments. Specify one letter.\n"
	.size	.L.str, 43

	.type	.L.str.1,@object        # @.str.1
.L.str.1:
	.asciz	"Please pick a single letter argument.\n"
	.size	.L.str.1, 39

	.type	.L.str.2,@object        # @.str.2
.L.str.2:
	.asciz	"Circle"
	.size	.L.str.2, 7

	.type	.L.str.3,@object        # @.str.3
.L.str.3:
	.asciz	"Rectangle"
	.size	.L.str.3, 10

	.type	.L.str.4,@object        # @.str.4
.L.str.4:
	.asciz	"Parallelogram"
	.size	.L.str.4, 14

	.type	.L.str.5,@object        # @.str.5
.L.str.5:
	.asciz	"Square"
	.size	.L.str.5, 7

	.type	.L.str.6,@object        # @.str.6
.L.str.6:
	.asciz	"Triangle"
	.size	.L.str.6, 9

	.type	.L.str.7,@object        # @.str.7
.L.str.7:
	.asciz	"Not a valid shape type. Exiting"
	.size	.L.str.7, 32

	.type	.L.str.8,@object        # @.str.8
.L.str.8:
	.asciz	"Area of %s is %f, Circumference of shape is %f\n"
	.size	.L.str.8, 48

	.type	_ZTV6Circle,@object     # @_ZTV6Circle
	.section	.data.rel.ro._ZTV6Circle,"aGw",@progbits,_ZTV6Circle,comdat
	.weak	_ZTV6Circle
	.p2align	3
_ZTV6Circle:
	.quad	0
	.quad	_ZTI6Circle
	.quad	_ZN6CircleD2Ev
	.quad	_ZN6CircleD0Ev
	.quad	_ZN6Circle4areaEv
	.quad	_ZN6Circle13circumferenceEv
	.size	_ZTV6Circle, 48

	.type	_ZTS6Circle,@object     # @_ZTS6Circle
	.section	.rodata._ZTS6Circle,"aG",@progbits,_ZTS6Circle,comdat
	.weak	_ZTS6Circle
_ZTS6Circle:
	.asciz	"6Circle"
	.size	_ZTS6Circle, 8

	.type	_ZTS5Shape,@object      # @_ZTS5Shape
	.section	.rodata._ZTS5Shape,"aG",@progbits,_ZTS5Shape,comdat
	.weak	_ZTS5Shape
_ZTS5Shape:
	.asciz	"5Shape"
	.size	_ZTS5Shape, 7

	.type	_ZTS6Object,@object     # @_ZTS6Object
	.section	.rodata._ZTS6Object,"aG",@progbits,_ZTS6Object,comdat
	.weak	_ZTS6Object
_ZTS6Object:
	.asciz	"6Object"
	.size	_ZTS6Object, 8

	.type	_ZTI6Object,@object     # @_ZTI6Object
	.section	.data.rel.ro._ZTI6Object,"aGw",@progbits,_ZTI6Object,comdat
	.weak	_ZTI6Object
	.p2align	3
_ZTI6Object:
	.quad	_ZTVN10__cxxabiv117__class_type_infoE+16
	.quad	_ZTS6Object
	.size	_ZTI6Object, 16

	.type	_ZTI5Shape,@object      # @_ZTI5Shape
	.section	.data.rel.ro._ZTI5Shape,"aGw",@progbits,_ZTI5Shape,comdat
	.weak	_ZTI5Shape
	.p2align	3
_ZTI5Shape:
	.quad	_ZTVN10__cxxabiv120__si_class_type_infoE+16
	.quad	_ZTS5Shape
	.quad	_ZTI6Object
	.size	_ZTI5Shape, 24

	.type	_ZTI6Circle,@object     # @_ZTI6Circle
	.section	.data.rel.ro._ZTI6Circle,"aGw",@progbits,_ZTI6Circle,comdat
	.weak	_ZTI6Circle
	.p2align	3
_ZTI6Circle:
	.quad	_ZTVN10__cxxabiv120__si_class_type_infoE+16
	.quad	_ZTS6Circle
	.quad	_ZTI5Shape
	.size	_ZTI6Circle, 24

	.type	_ZTV5Shape,@object      # @_ZTV5Shape
	.section	.data.rel.ro._ZTV5Shape,"aGw",@progbits,_ZTV5Shape,comdat
	.weak	_ZTV5Shape
	.p2align	3
_ZTV5Shape:
	.quad	0
	.quad	_ZTI5Shape
	.quad	_ZN5ShapeD2Ev
	.quad	_ZN5ShapeD0Ev
	.quad	__cxa_pure_virtual
	.quad	__cxa_pure_virtual
	.size	_ZTV5Shape, 48

	.type	_ZTV6Object,@object     # @_ZTV6Object
	.section	.data.rel.ro._ZTV6Object,"aGw",@progbits,_ZTV6Object,comdat
	.weak	_ZTV6Object
	.p2align	3
_ZTV6Object:
	.quad	0
	.quad	_ZTI6Object
	.quad	_ZN6ObjectD2Ev
	.quad	_ZN6ObjectD0Ev
	.size	_ZTV6Object, 32

	.type	_ZTV9Rectangle,@object  # @_ZTV9Rectangle
	.section	.data.rel.ro._ZTV9Rectangle,"aGw",@progbits,_ZTV9Rectangle,comdat
	.weak	_ZTV9Rectangle
	.p2align	3
_ZTV9Rectangle:
	.quad	0
	.quad	_ZTI9Rectangle
	.quad	_ZN9RectangleD2Ev
	.quad	_ZN9RectangleD0Ev
	.quad	_ZN13Parallelogram4areaEv
	.quad	_ZN13Parallelogram13circumferenceEv
	.size	_ZTV9Rectangle, 48

	.type	_ZTS9Rectangle,@object  # @_ZTS9Rectangle
	.section	.rodata._ZTS9Rectangle,"aG",@progbits,_ZTS9Rectangle,comdat
	.weak	_ZTS9Rectangle
_ZTS9Rectangle:
	.asciz	"9Rectangle"
	.size	_ZTS9Rectangle, 11

	.type	_ZTS13Parallelogram,@object # @_ZTS13Parallelogram
	.section	.rodata._ZTS13Parallelogram,"aG",@progbits,_ZTS13Parallelogram,comdat
	.weak	_ZTS13Parallelogram
_ZTS13Parallelogram:
	.asciz	"13Parallelogram"
	.size	_ZTS13Parallelogram, 16

	.type	_ZTI13Parallelogram,@object # @_ZTI13Parallelogram
	.section	.data.rel.ro._ZTI13Parallelogram,"aGw",@progbits,_ZTI13Parallelogram,comdat
	.weak	_ZTI13Parallelogram
	.p2align	3
_ZTI13Parallelogram:
	.quad	_ZTVN10__cxxabiv120__si_class_type_infoE+16
	.quad	_ZTS13Parallelogram
	.quad	_ZTI5Shape
	.size	_ZTI13Parallelogram, 24

	.type	_ZTI9Rectangle,@object  # @_ZTI9Rectangle
	.section	.data.rel.ro._ZTI9Rectangle,"aGw",@progbits,_ZTI9Rectangle,comdat
	.weak	_ZTI9Rectangle
	.p2align	3
_ZTI9Rectangle:
	.quad	_ZTVN10__cxxabiv120__si_class_type_infoE+16
	.quad	_ZTS9Rectangle
	.quad	_ZTI13Parallelogram
	.size	_ZTI9Rectangle, 24

	.type	_ZTV13Parallelogram,@object # @_ZTV13Parallelogram
	.section	.data.rel.ro._ZTV13Parallelogram,"aGw",@progbits,_ZTV13Parallelogram,comdat
	.weak	_ZTV13Parallelogram
	.p2align	3
_ZTV13Parallelogram:
	.quad	0
	.quad	_ZTI13Parallelogram
	.quad	_ZN13ParallelogramD2Ev
	.quad	_ZN13ParallelogramD0Ev
	.quad	_ZN13Parallelogram4areaEv
	.quad	_ZN13Parallelogram13circumferenceEv
	.size	_ZTV13Parallelogram, 48

	.type	_ZTV6Square,@object     # @_ZTV6Square
	.section	.data.rel.ro._ZTV6Square,"aGw",@progbits,_ZTV6Square,comdat
	.weak	_ZTV6Square
	.p2align	3
_ZTV6Square:
	.quad	0
	.quad	_ZTI6Square
	.quad	_ZN6SquareD2Ev
	.quad	_ZN6SquareD0Ev
	.quad	_ZN13Parallelogram4areaEv
	.quad	_ZN6Square13circumferenceEv
	.quad	-24
	.quad	_ZTI6Square
	.quad	_ZThn24_N6SquareD1Ev
	.quad	_ZThn24_N6SquareD0Ev
	.size	_ZTV6Square, 80

	.type	_ZTS6Square,@object     # @_ZTS6Square
	.section	.rodata._ZTS6Square,"aG",@progbits,_ZTS6Square,comdat
	.weak	_ZTS6Square
_ZTS6Square:
	.asciz	"6Square"
	.size	_ZTS6Square, 8

	.type	_ZTS11RegularNGon,@object # @_ZTS11RegularNGon
	.section	.rodata._ZTS11RegularNGon,"aG",@progbits,_ZTS11RegularNGon,comdat
	.weak	_ZTS11RegularNGon
_ZTS11RegularNGon:
	.asciz	"11RegularNGon"
	.size	_ZTS11RegularNGon, 14

	.type	_ZTI11RegularNGon,@object # @_ZTI11RegularNGon
	.section	.data.rel.ro._ZTI11RegularNGon,"aGw",@progbits,_ZTI11RegularNGon,comdat
	.weak	_ZTI11RegularNGon
	.p2align	3
_ZTI11RegularNGon:
	.quad	_ZTVN10__cxxabiv117__class_type_infoE+16
	.quad	_ZTS11RegularNGon
	.size	_ZTI11RegularNGon, 16

	.type	_ZTI6Square,@object     # @_ZTI6Square
	.section	.data.rel.ro._ZTI6Square,"aGw",@progbits,_ZTI6Square,comdat
	.weak	_ZTI6Square
	.p2align	3
_ZTI6Square:
	.quad	_ZTVN10__cxxabiv121__vmi_class_type_infoE+16
	.quad	_ZTS6Square
	.long	0                       # 0x0
	.long	2                       # 0x2
	.quad	_ZTI9Rectangle
	.quad	2                       # 0x2
	.quad	_ZTI11RegularNGon
	.quad	6146                    # 0x1802
	.size	_ZTI6Square, 56

	.type	_ZTV11RegularNGon,@object # @_ZTV11RegularNGon
	.section	.data.rel.ro._ZTV11RegularNGon,"aGw",@progbits,_ZTV11RegularNGon,comdat
	.weak	_ZTV11RegularNGon
	.p2align	3
_ZTV11RegularNGon:
	.quad	0
	.quad	_ZTI11RegularNGon
	.quad	_ZN11RegularNGonD2Ev
	.quad	_ZN11RegularNGonD0Ev
	.size	_ZTV11RegularNGon, 32

	.type	_ZTV8Triangle,@object   # @_ZTV8Triangle
	.section	.data.rel.ro._ZTV8Triangle,"aGw",@progbits,_ZTV8Triangle,comdat
	.weak	_ZTV8Triangle
	.p2align	3
_ZTV8Triangle:
	.quad	0
	.quad	_ZTI8Triangle
	.quad	_ZN8TriangleD2Ev
	.quad	_ZN8TriangleD0Ev
	.quad	_ZN8Triangle4areaEv
	.quad	_ZN8Triangle13circumferenceEv
	.size	_ZTV8Triangle, 48

	.type	_ZTS8Triangle,@object   # @_ZTS8Triangle
	.section	.rodata._ZTS8Triangle,"aG",@progbits,_ZTS8Triangle,comdat
	.weak	_ZTS8Triangle
_ZTS8Triangle:
	.asciz	"8Triangle"
	.size	_ZTS8Triangle, 10

	.type	_ZTI8Triangle,@object   # @_ZTI8Triangle
	.section	.data.rel.ro._ZTI8Triangle,"aGw",@progbits,_ZTI8Triangle,comdat
	.weak	_ZTI8Triangle
	.p2align	3
_ZTI8Triangle:
	.quad	_ZTVN10__cxxabiv120__si_class_type_infoE+16
	.quad	_ZTS8Triangle
	.quad	_ZTI5Shape
	.size	_ZTI8Triangle, 24

	.section	.init_array,"aw",@init_array
	.p2align	3
	.quad	_GLOBAL__sub_I_shapes.cpp
	.section	".linker-options","e",@llvm_linker_options
	.hidden	DW.ref.__gxx_personality_v0
	.weak	DW.ref.__gxx_personality_v0
	.section	.data.DW.ref.__gxx_personality_v0,"aGw",@progbits,DW.ref.__gxx_personality_v0,comdat
	.p2align	3
	.type	DW.ref.__gxx_personality_v0,@object
	.size	DW.ref.__gxx_personality_v0, 8
DW.ref.__gxx_personality_v0:
	.quad	__gxx_personality_v0
	.ident	"clang version 10.0.0-4ubuntu1 "
	.section	".note.GNU-stack","",@progbits
	.addrsig
	.addrsig_sym __cxx_global_var_init
	.addrsig_sym __cxa_atexit
	.addrsig_sym printf
	.addrsig_sym strlen
	.addrsig_sym _Znwm
	.addrsig_sym __gxx_personality_v0
	.addrsig_sym _ZdlPv
	.addrsig_sym _ZN6Object8set_nameEPKc
	.addrsig_sym _ZN6Object4nameEv
	.addrsig_sym free
	.addrsig_sym calloc
	.addrsig_sym strcpy
	.addrsig_sym _ZSt4sqrtIiEN9__gnu_cxx11__enable_ifIXsr12__is_integerIT_EE7__valueEdE6__typeES2_
	.addrsig_sym sqrt
	.addrsig_sym _GLOBAL__sub_I_shapes.cpp
	.addrsig_sym _Unwind_Resume
	.addrsig_sym _ZStL8__ioinit
	.addrsig_sym __dso_handle
	.addrsig_sym _ZTVN10__cxxabiv120__si_class_type_infoE
	.addrsig_sym _ZTS6Circle
	.addrsig_sym _ZTS5Shape
	.addrsig_sym _ZTVN10__cxxabiv117__class_type_infoE
	.addrsig_sym _ZTS6Object
	.addrsig_sym _ZTI6Object
	.addrsig_sym _ZTI5Shape
	.addrsig_sym _ZTI6Circle
	.addrsig_sym _ZTS9Rectangle
	.addrsig_sym _ZTS13Parallelogram
	.addrsig_sym _ZTI13Parallelogram
	.addrsig_sym _ZTI9Rectangle
	.addrsig_sym _ZTVN10__cxxabiv121__vmi_class_type_infoE
	.addrsig_sym _ZTS6Square
	.addrsig_sym _ZTS11RegularNGon
	.addrsig_sym _ZTI11RegularNGon
	.addrsig_sym _ZTI6Square
	.addrsig_sym _ZTS8Triangle
	.addrsig_sym _ZTI8Triangle
