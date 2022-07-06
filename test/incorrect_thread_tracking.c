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

/* Attempt to replicate incorrect thread tracking observed from firefox
 * and opening a new tab in gnome-terminal.
 *
 * It appears that a multi-threaded process which forks from a non-thread-group-leader
 * thread doesn't have its stack properly tracked/checked by our bpf programs (yet).
 */
 
#include <stdio.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>

#include "util.h"

void run_thread(void *arg)
{
    pid_t mypid = getpid();
    pid_t mytid = gettid();
    void *myrsp;
    GET_SP(myrsp);
    printf("[I] %d:%d non-leader thread rsp: %p\n", mypid, mytid, myrsp);

    pid_t pid = fork();
    if (pid == 0) {
        // child
        pid_t childpid = getpid();
        pid_t childtid = gettid();
        void *childrsp;
        GET_SP(childrsp);
        printf("[I] %d:%d child process from non-leader thread, rsp: %p\n", childpid, childtid, childrsp);

        exit(0);

        //*
        char *argv[2] = { "./stackpivot.bin", NULL};
        //*/
        /*
        char *argv[2] = { "./report_rsp.bin", NULL};
        //*/
        char *envp[1] = { NULL };
        printf("[I] %d:%d child process from non-leader thread, execve'ing `%s`, rsp: %p\n", childpid, childtid, argv[0], childrsp);
        execve(argv[0], argv, envp);
    } else {
        // parent
        int status;
        wait(&status);
        printf("[I] process exited: %d\n", status);
    }
}

void do_wait_thread(pthread_attr_t *attr)
{
    int res;
    pthread_t tid;

    printf("[I] creating thread...\n");
    res = pthread_create(&tid, attr, (void *)run_thread, NULL);
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

// create a thread which will fork+execve
int main(int argc, char **argv)
{
    int res;
    pid_t mypid, mytid;

    pthread_attr_t attr = {};

    mypid = getpid();
    mytid = gettid();
    void *rsp;
    GET_SP(rsp);
    printf("[I] main process: %d:%d rsp %p\n", mypid, mytid, rsp);

    
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
