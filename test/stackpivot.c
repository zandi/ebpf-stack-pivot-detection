#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

// boilerplate for functions to make up our rop chain
#define printfuncname(num) func##num

#define printfunc(num) \
void func##num() { \
    printf("func##num\n"); \
}

static void *malicious_stack = NULL;

printfunc(1)
printfunc(2)
printfunc(3)

void do_exit(int status)
{
    exit(status);
}

void do_stack_pivot()
{
    // TODO: use inline asm to stack pivot and execute our ROP chain
    return;
}

// not a proper thunk since we do an actual function call to get here, so sp changes.
// but good enough to get a near-enough value of the stack pointer at calltime since 
// 1) we have essentially no variables on the stack (we're only off by rip+rbp)
// 2) we just need to know what VMA the legit stack is in, to compare
void *get_sp_thunk() {
    void *result;

    asm(".intel_syntax noprefix\n" \
        "mov %0, rsp\n"
        :"=a" (result)
        );

    return result;
}

int main(int argc, char **argv)
{
    void *legit_stack;

    malicious_stack = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
    if (malicious_stack == MAP_FAILED) {
        //error
        perror("mmap");
        exit(-1);
    }

    legit_stack = get_sp_thunk();
    if (legit_stack) {
        printf("legit stack at: %p\n", legit_stack);
    } else {
        perror("get_sp_thunk");
        exit(-1);
    }

    printf("malicious stack allocated in page beginning at %p\n", malicious_stack);

    return 0;
}
