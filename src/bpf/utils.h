/* SPDX-License-Identifier: GPL-2.0 */

/* 
 * Copyright (C) 2023  BlackBerry Limited
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef UTILS_H_
#define UTILS_H_

// stolen definitions
// include/linux/sched.h
#define CLONE_VM    0x00000100  /* set if VM shared between processes */
#define CLONE_THREAD    0x00010000  /* Same thread group? */
#define CLONE_VFORK	0x00004000	/* set if the parent wants the child to wake it up on mm_release */

// include/uapi/asm-generic/mman-common.h
#define PROT_EXEC 0x4

// end stolen definitions

#define BUF_SIZE 128

#define ERR_LEVEL_WARNING 1
#define ERR_LEVEL_ALERT 2

#define ERR_TYPE_NONE 0
#define ERR_TYPE_UNK_STACK ((ERR_LEVEL_WARNING << 12) | 1)
#define ERR_TYPE_STACK_PIVOT ((ERR_LEVEL_ALERT << 12) | 1)


// our own check_stack_pivot return codes
#define ERR_LOOKS_OK 0

#define ERR_NO_VMA ((ERR_LEVEL_WARNING << 12) | 1)
#define ERR_ANCIENT_THREAD ((ERR_LEVEL_WARNING << 12) | 2)
#define ERR_POSSIBLE_GOLANG_STACK ((ERR_LEVEL_WARNING << 12) | 3)

#define ERR_STACK_PIVOT ((ERR_LEVEL_ALERT << 12) | 1)



#define MAX_RB_NODE_BOUNDS 51

#define PF_KTHREAD 0x00200000

#define STACK_SRC_SELF 0
#define STACK_SRC_UNK -1
#define STACK_SRC_ERR -2

#define FIND_VMA_SUCCESS 0
#define FIND_VMA_FAILURE -1

// a define for each location we can emit a stack pivot event from
// janky lowercase to work cleanly with macros
#define LOC_UNKNOWN 0
#define LOC_clone 1
#define LOC_clone3 2
#define LOC_execve 3
#define LOC_execveat 4
#define LOC_fork 5
#define LOC_vfork 6
#define LOC_socket 7
#define LOC_dup2 8
#define LOC_dup3 9
#define LOC_mmap 10
#define LOC_mprotect 11

// only relevant for if a stack pivot is detected
#define ACTION_UNKNOWN 0
#define ACTION_REPORT 1
#define ACTION_KILL 2

typedef unsigned long ulong;

// refactored stack event type. Only for suspicious/bad events,
// "OK" events only made/sent for debugging
// TODO:
//    - send "OK" events only when debugging build
//    - consider adding: sp vma info, ppid, 'source' of assumed stack
struct stack_pivot_event {
    ulong time;
    int pid;
    int tid;
    ulong sp;
    ulong stack_start;
    ulong stack_end;
    int kind; // "type" is a keyword in rust
    int location;
    int action; // do we kill the process, or just report? (only in case of stack pivot)
};

#define CLONE_DATA_TYPE 1
#define WAKE_UP_NEW_TASK_DATA_TYPE 2
#define DO_EXIT_DATA_TYPE 3
#define UNKNOWN_DATA_TYPE -1

// combines separate tgid, pid into combined tgid_pid like from bpf_get_current_pid_tgid helper
#define MAKE_COMBINED_TGID_PID(dest, tgid, pid) \
    dest = tgid << 32 | pid

// macros for slightly nicer CO-RE use
#define BPF_READ(dest, source) \
    bpf_core_read(&dest, sizeof(dest), &source)
#define BPF_READ_STR(dest, source) \
    bpf_core_read_str(&dest, sizeof(dest), &source)

/* Macros for ringbuf definitions for userland communication */
#define BPF_MAP_DEF(name) \
    struct { \
        __uint(type, BPF_MAP_TYPE_RINGBUF); \
        __uint(max_entries, 256 * 4096); \
    } ringbuf_map_##name SEC(".maps");

#define BPF_MAP_NAME(name) ringbuf_map_##name

/* Searches a task's virtual memory ranges for a specified address, using the
 * specified rb_node as the starting point. The discovered range's boundaries 
 * are written to the start and end reference parameters.
 *
 * NOTE: BPF helper function bpf_find_vma was introduced in Linux 5.17
 * on Nov 7, 2021 and performs the same task as my wrapper function below.
 * Since this is a very recent introduction and (most recently) distros still 
 * rely on 5.15, I will continue to use the wrapper function.
 *
 * mm_struct *mm        : mm_struct to search
 * ulong addr           : address to search for
 * ulong *start         : write found range's starting address to this
 * ulong *end           : write found range's ending address to this */
static int find_vma_range(struct mm_struct *mm, ulong addr, ulong *start,
        ulong *end)
{
    struct vm_area_struct *tmp;
    ulong vm_start, vm_end;
    struct vm_area_struct *mmap;
    struct rb_node *rb_node;
    ulong vm_flags = 0;
    ulong off_vm_rb = 0;

    /* these fields have changed.
    vm_area_struct vm_rb field gone in 6.1
    mm_struct fields mmap and mm_rb gone in 6.1
    */
    BPF_READ(mmap, mm->mmap);
    BPF_READ(rb_node, mm->mm_rb);
    off_vm_rb = __CORE_RELO(mmap, vm_rb, BYTE_OFFSET);

    /* NOTE: kernel >= v5.3 is needed for bounded loops in BPF.
     * See https://lwn.net/Articles/794934/ for details. */
    for (int i = 0; i < MAX_RB_NODE_BOUNDS && rb_node; i++) {
        tmp = (struct vm_area_struct *)((ulong)rb_node - off_vm_rb);
        BPF_READ(vm_end, tmp->vm_end);
        BPF_READ(vm_start, tmp->vm_start);
        BPF_READ(vm_flags, tmp->vm_flags);
        if (vm_end > addr) {
            if (vm_start <= addr) {
                // Valid stack pointer
                *start = vm_start;
                *end = vm_end;
                return FIND_VMA_SUCCESS;
            }
            BPF_READ(rb_node, rb_node->rb_left);
        } 
        else {
            BPF_READ(rb_node, rb_node->rb_right);
        }
    }
    return FIND_VMA_FAILURE;
}

/* Initialize stack pivot event type with common info
 *
 * returns task struct of current task (helpful for other common work)
*/
struct task_struct *init_stack_pivot_event(struct stack_pivot_event *event)
{
    struct task_struct *t;
    ulong pid_tgid;

    event->time = bpf_ktime_get_ns();
    pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->tid = pid_tgid & 0xffffffff;
    t = bpf_get_current_task_btf();

    BPF_READ(event->tid, t->pid);

    return t;
}

#endif // UTILS_H_
