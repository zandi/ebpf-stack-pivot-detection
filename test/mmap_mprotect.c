/* Copyright (c) 2023 BlackBerry Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/* call mmap & mprotect to test observing/checking these syscalls.
 *
 * mmap & mprotect would be necessary/very useful for shellcode to
 * use to execute a new program/2nd stage shellcode without using execve.
*/

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "util.h"

/*
 default glibc.malloc.mmap_max value is 4096*32; any request above this
 is fulfilled with mmap (by default). This is currently a false negative
 blindspot of ours, so to simluate a detectable (currently) stack pivot into
 the heap, we need smaller stack sizes.
*/
#define MALICIOUS_STACK_SIZE (4096 * 16)

static void *misc_page = NULL;
static void *malicious_stack = NULL;

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

void do_exit(int status)
{
    exit(status);
}

void do_mmap_mprotect(void *arg)
{
    int res;
    pid_t mypid = getpid();
    pid_t mytid = gettid();
    void *myrsp;
    GET_SP(myrsp);

    //printf("[I] %d:%d non-leader thread rsp: %p\n", mypid, mytid, myrsp);

    misc_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
    if (misc_page == MAP_FAILED) {
        //error
        perror("mmap");
        exit(-1);
    }

    res = mprotect(misc_page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
    if (res == -1) {
        perror("mprotect");
        exit(-1);
    }

    //printf("[I] allocated page with mmap, and remapped it RWX\n");
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
    unsigned long *ms = malicious_stack + (MALICIOUS_STACK_SIZE / 2); // need enough space for functions we call to not segfault
    *ms++ = (unsigned long) malicious_stack + (MALICIOUS_STACK_SIZE / 2) + 16; // rbp
    // print 1, 2, 3
/*
    *ms++ = (unsigned long) &printfuncname(1);
    *ms++ = (unsigned long) &printfuncname(2);
    *ms++ = (unsigned long) &printfuncname(3);
*/
    *ms++ = (unsigned long) do_mmap_mprotect;
    //*
    // exit(42)
    *ms++ = (unsigned long) (gadget_warehouse+10);
    *ms++ = (unsigned long) 42;
    *ms++ = (unsigned long) do_exit;
    //*/

    // smaller rop chain to do stack pivot
    *saved_rbp = (unsigned long) malicious_stack + (MALICIOUS_STACK_SIZE / 2);
    *saved_rip = (unsigned long) (gadget_warehouse+8); // leave;ret;
    *(saved_rip+1) = (unsigned long) 0x4141414141414141; // padding

    // kick off smaller rop chain
    puts("[I] Pausing... Press Any Key to stack pivot");
    /*
    getchar();
    //*/
    puts("[I] doing stack pivot...");
    return;
}

void do_wait_thread(pthread_attr_t *attr)
{
    int res;
    pthread_t tid;

    printf("[I] creating thread...\n");
    res = pthread_create(&tid, attr, (void *)do_stack_pivot, NULL);
    if (res != 0) {
        perror("pthread_create");
        exit(1);
    }

    res = pthread_join(tid, NULL);
    if (res != 0) {
        perror("pthread_join");
        exit(1);
    }
    printf("[I] thread %ld joined\n", tid);
}

void usage(char *name)
{
    printf("[I] %s [-l/-t]\n", name);
    printf("\t-l: test detection in thread group leader ('main' thread)\n");
    printf("\t-t: test detection in non-leader thread ('non-main' thread)\n");
    printf("\tif no argument is supplied, assume non-leader thread case\n");
}

int main(int argc, char **argv)
{
    int res;
    pid_t pid, tid;
    pthread_attr_t attr = {};

    int test_in_thread_group_leader = 0;

    if (argc == 1) {
        printf("[I] no arguments. testing detection in non-leader thread\n");
    }
    else if (argc != 2) {
        usage(argv[0]);
        exit(-1);
    }
    else {
        // check for -l or -t (-l == leader, -t == non-leader thread)
        if (strcmp("-l", argv[1]) == 0) {
            // check thread group leader detection
            printf("[I] checking detection in thread group leader\n");
        } else if (strcmp("-t", argv[1]) == 0) {
            printf("[I] checking detection in non-leader thread\n");
        }
    }

    pid = getpid();
    tid = gettid();
    printf("[I] pid:tid %d:%d\n", pid, tid);

    malicious_stack = malloc(MALICIOUS_STACK_SIZE);
    if (malicious_stack == NULL) {
        perror("malloc");
        exit(-1);
    }

    printf("[I] malicious stack allocated beginning at %p\n", malicious_stack);

    // do a stack pivot, either in thread group leader or non-leader thread.
    if (test_in_thread_group_leader == 1) {
        do_stack_pivot();
    } else {
        res = pthread_attr_init(&attr);
        if (res != 0) {
            perror("pthread_attr_init");
            exit(1);
        }

        do_wait_thread(&attr);

        res = pthread_attr_destroy(&attr);
        if (res != 0) {
            perror("pthread_attr_destroy");
            exit(1);
        }
    }

    return 0;
}
