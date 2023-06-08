.globl _start
_start:
.intel_syntax noprefix
        // call exit syscall w/ exit code 42
        mov rax, 60
        mov rdi, 42
        syscall
