/* call mmap & mprotect to test observing/checking these syscalls.
 *
 * mmap & mprotect would be necessary/very useful for shellcode to
 * use to execute a new program/2nd stage shellcode without using execve.
*/

// TODO: borrow tricks from stackpivot.c to do an mmap/mprotect from a stack pivoted ROP chain

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "util.h"

static void *misc_page = NULL;

void do_mmap_mprotect(void *arg)
{
    int res;
    pid_t mypid = getpid();
    pid_t mytid = gettid();
    void *myrsp;
    GET_SP(myrsp);

    printf("[I] %d:%d non-leader thread rsp: %p\n", mypid, mytid, myrsp);

    // These should not trip any kind of stack pivot detection
    misc_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
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

    printf("[I] allocated page with mmap, and remapped it RWX\n");
}

void do_wait_thread(pthread_attr_t *attr)
{
    int res;
    pthread_t tid;

    printf("[I] creating thread...\n");
    res = pthread_create(&tid, attr, (void *)do_mmap_mprotect, NULL);
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

int main(int argc, char **argv)
{
    int res;
    pid_t pid, tid;
    pthread_attr_t attr = {};

    pid = getpid();
    tid = gettid();
    printf("[I] pid:tid %d:%d\n", pid, tid);

    res = pthread_attr_init(&attr);
    if (res != 0) {
        perror("pthread_attr_init");
        exit(1);
    }

    do_wait_thread(&attr);

    do_wait_thread(&attr);

    res = pthread_attr_destroy(&attr);
    if (res != 0) {
        perror("pthread_attr_destroy");
        exit(1);
    }

    return 0;
}
