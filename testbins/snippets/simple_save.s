.intel_syntax noprefix
.section .text
    .global main

main:
    mov rbx, 0
.LC0:
    push rax
    push rdi
    pushf
    popf
    pop rdi
    pop rax
    inc rbx
    cmp ebx, 0xffffffff
    jb .LC0
    ret
