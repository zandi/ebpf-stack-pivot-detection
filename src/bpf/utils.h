#ifndef UTILS_H_
#define UTILS_H_

// stolen definitions
// linux/sched.h
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

typedef unsigned long ulong;

// args for various functions we monitor
struct clone_user_args {
    ulong clone_flags;
    ulong newsp;
    int parent_tid;
    int child_tid;
    /*
    int *parent_tidptr;
    int *child_tidptr;
    //*/
};

//*
struct wake_up_new_task_args {
    struct task_struct *task;
};
//*/

struct do_exit_args {
    long code;
};

// generic data (included in all events)
struct data_t {
    int err;
    int pid;
    int ppid;
    int tid;
    int retval;
    int new_pid;
    int stack_src;
    int stack_pid; // pid of parent thread created with newsp
    ulong time;
    ulong sp;
    //ulong stack;
    ulong start_stack;
    ulong start_stack_addr;
    ulong task;
    ulong stack_start;
    ulong stack_end;
    char buf[BUF_SIZE];
};

// my slimmed-down version of data_t type to be more efficient
// still a catch-all struct, so refactor that later
struct slim_data_t {
    ulong time;
    int pid;
    int tid;
    int ppid;
    ulong sp;
    ulong start_stack;
    ulong start_stack_addr;
    ulong task;

    int stack_src;
    int stack_pid; // pid of parent thread created with newsp
    ulong stack_start;
    ulong stack_end;

    int new_pid;
    int retval;

    int err;
};

// refactored stack event type. Only for suspicious/bad events,
// "OK" events only made/sent for debugging
// TODO:
//    - send "OK" events only when debugging build
//    - consider adding: sp vma info, ppid, 'source' of assumed stack
struct stack_pivot_event_v2 {
    ulong time;
    int pid;
    int tid;
    ulong sp;
    ulong stack_start;
    ulong stack_end;
    int type;
};

// combine generic data with function-specific args
struct clone_data {
    struct slim_data_t data;
    struct clone_user_args args;
};

//*
struct wake_up_new_task_data {
    struct slim_data_t data;
    struct wake_up_new_task_args args;
};
//*/

struct do_exit_data {
    struct slim_data_t data;
    struct do_exit_args args;
};

union generic_event_data_union {
    struct clone_data clone_data;
    //struct wake_up_new_task_data wake_up_new_task_data;
    struct do_exit_data do_exit_data;
};

#define CLONE_DATA_TYPE 1
#define WAKE_UP_NEW_TASK_DATA_TYPE 2
#define DO_EXIT_DATA_TYPE 3
#define UNKNOWN_DATA_TYPE -1

struct event_data_t {
    int inner_type;
    union generic_event_data_union data;
};

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

/* Initializes probe data with a time stamp, PID, PPID, and LWP (TID).
 *
 * Returns a pointer to the current task. */
struct task_struct *init_probe_data(struct slim_data_t *data)
{
    struct task_struct *t;
    struct task_struct *real_parent;
    ulong pid_tgid;

    data->time = bpf_ktime_get_ns();
    pid_tgid = bpf_get_current_pid_tgid();
    data->pid = pid_tgid >> 32;
    data->tid = pid_tgid & 0xffffffff; // unnecessary?
    t = bpf_get_current_task_btf();
    BPF_READ(data->tid, t->pid);
    BPF_READ(real_parent, t->real_parent);
    BPF_READ(data->ppid, real_parent->pid);

    return t;
}

/* Initialize stack pivot event type with common info
 *
 * returns task struct of current task (helpful for other common work)
*/
struct task_struct *init_stack_pivot_event_v2(struct stack_pivot_event_v2 *event)
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
