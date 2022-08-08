/* call mmap & mprotect to test observing/checking these syscalls.
 *
 * mmap & mprotect would be necessary/very useful for shellcode to
 * use to execute a new program/2nd stage shellcode without using execve.
*/

// TODO: borrow tricks from stackpivot.c to do an mmap/mprotect from a stack pivoted ROP chain

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

static void *misc_page = NULL;

int main(int argc, char **argv)
{
    int res;
    pid_t pid, tid;

    pid = getpid();
    tid = gettid();
    printf("[I] pid:tid %d:%d\n", pid, tid);

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

    return 0;
}
