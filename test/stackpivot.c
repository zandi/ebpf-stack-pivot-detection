#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

// boilerplate for functions to make up our rop chain
#define printfuncname(num) func##num

#define printfunc(num) \
void func##num() { \
    puts("func "#num); \
}

// nifty macros for inline assembly so we can examine our own stack
#define GET_SP(result) \
    asm(".intel_syntax noprefix\n" \
        "mov %0, rsp\n" \
        :"=a" (result) \
        );

#define GET_BP(result) \
    asm(".intel_syntax noprefix\n" \
        "mov %0, rbp\n" \
        :"=a" (result) \
        );

static void *malicious_stack = NULL;

printfunc(1)
printfunc(2)
printfunc(3)

void do_exit(int status)
{
    exit(status);
}

/* slightly nasty hack, but lets us access gadget locations through a symbol
 * assuming compilation is deterministic within a function.
 *
 * put all the gadgets in here
 *
 * If you fiddle with compiler flags (such as -O) or things break, you'll need
 * to manually verify gadget locations. Yes, you! (use objdump -M intel -d
 * $file.bin to check)
 */
void gadget_warehouse() {
    /*
     * +8   leave; ret;
     * +10  pop rdi; ret;
     */

    asm(".intel_syntax noprefix\n" \
        "leave\n" \
        "ret\n" \
        "pop rdi\n" \
        "ret\n" \
        );
}

void do_stack_pivot()
{
    void *legit_stack;
    unsigned long *bp, *saved_rbp, *saved_rip;

    GET_BP(bp);
    saved_rbp = bp;
    saved_rip = bp+1;
    printf("[I] bp: %p, *saved_rbp=%#lx, *saved_rip=%#lx\n", bp, *saved_rbp, *saved_rip);

    GET_SP(legit_stack);
    printf("[I] legit stack at: %p\n", legit_stack);

    printf("[I] leave;ret; gadget: %p\n", (gadget_warehouse+8));

    // set up big rop chain in new stack we'll pivot to
    unsigned long *ms = malicious_stack + 2048; // need enough space for functions we call to not segfault
    *ms++ = (unsigned long) malicious_stack + 2048 + 16; // rbp
    *ms++ = (unsigned long) &printfuncname(1);
    *ms++ = (unsigned long) &printfuncname(2);
    *ms++ = (unsigned long) &printfuncname(3);
    *ms++ = (unsigned long) (gadget_warehouse+10);
    *ms++ = (unsigned long) 42;
    *ms++ = (unsigned long) do_exit;

    // smaller rop chain to do stack pivot
    *saved_rbp = (unsigned long) malicious_stack + 2048;
    *saved_rip = (unsigned long) (gadget_warehouse+8); // leave;ret;
    *(saved_rip+1) = (unsigned long) 0x4141414141414141; // padding

    // kick off smaller rop chain
    puts("[I] doing stack pivot...");
    return;
}

int main(int argc, char **argv)
{
    malicious_stack = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
    if (malicious_stack == MAP_FAILED) {
        //error
        perror("mmap");
        exit(-1);
    }

    printf("[I] malicious stack allocated in page beginning at %p\n", malicious_stack);

    do_stack_pivot();

    return 0;
}
