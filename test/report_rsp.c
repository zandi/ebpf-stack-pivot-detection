#include <stdio.h>

#include "util.h"

int main(int argc, char **argv)
{
    void *rsp;
    GET_SP(rsp);
    printf("[I] rsp: %p\n", rsp);

    return 0;
}
