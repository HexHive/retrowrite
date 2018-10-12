.intel_syntax noprefix
.section .text
    .global main

main:
    mov rbx, 0
.LC0:
    push rcx
    push rax
    push rdi
    lahf
    seto al
    xchg al, ah
    push rax
    pop rax
    xchg al, ah
    add al, 0x7f
    sahf
    pop rdi
    pop rax
    pop rcx
    inc rbx
    cmp ebx, 0xffffffff
    jb .LC0
    ret
