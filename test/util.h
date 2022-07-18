
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
