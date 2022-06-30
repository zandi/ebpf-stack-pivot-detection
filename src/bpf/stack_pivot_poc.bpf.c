#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "utils.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// struct definitions

struct stack_data {
    int source; // where the stack VMA was found
    int pid; // original task that created stack
    ulong start;
    ulong end;
};

// TODO: use this to report detected stack pivot attempts/events to userland
struct stack_pivot_data_t {
    pid_t pid; // use kernel terminology
    pid_t tgid;
    unsigned long newsp;
};


// maps

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} stack_pivot_events SEC(".maps");

// maps (tgid << 32 | pid) values to observed newsp value from clone args
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536); // no idea what a sane value is
    __type(key, u64); // in (tgid, pid) format as given by bpf helper
    __type(value, u64);
} thread_stacks SEC(".maps");

/* Backlog of new stack pointers for individual process threads. If a thread
 * was created with its own stack area (ie. newsp is non-null in a call to
 * clone), we save this to a BPF map. Each entry in the map comprises a key
 * (the thread ID) and a value (a pointer, ie. an address within the thread's
 * new stack range). This map is the secondary source of information for stack
 * checking (the primary source is start_stack). Stack checking requires
 * several steps:
 * 1. In the cgroup_post_fork kprobe, we update stack_map with the
 *    new stack base value retrieved from the stack field in kernel_clone_args.
 *    This field gets its value from clone's newsp parameter.
 * 2. Any subsequent calls to execve or clone can then check for valid stack
 *    ranges using the up-to-date list of stack addresses in this map.
 * 3. When threads exit, we free up space in the map in the do_exit kprobe. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, int);
    __type(value, struct stack_data);
} stack_map SEC(".maps");

// force exporting the type to rust skeleton
struct stack_pivot_data_t __unused = {0};


/* Searches backlog of stack VMAs for one that contains the current stack
 * pointer. If none found, then checks SP against VMA of the current task's
 * start_stack. Returns a warning error code if SP is in a VMA that is 
 * not known to us as a valid stack VMA. If SP is not in any VMA of the
 * current task, returns an alert error code.
 *
 * struct data_t *data      sp should be set before calling this function;
 *                          stack_start and stack_end are updated
 * struct task_struct *t    pointer to current user thread's task_struct
 *
 * Note that any child threads created by a fork will inherit their parent's
 * stack area. Hence, threads created with a non-null newsp will pass an
 * unflagged stack area down to forked child threads, starting a legacy of 
 * threads with unflagged stack areas. This can continue indefinitely, with 
 * nested fork calls in user threads. Unflagged stack area progenitors going 
 * back further than the parent are rare in the wild. Nevertheless it is easy 
 * to demonstrate this. */
static int check_stack_vma(struct data_t *data, struct task_struct *t)
{
    struct stack_data *stack;
    struct mm_struct *mm;
    uint pid;

    BPF_READ(pid, t->pid);
    BPF_READ(mm, t->mm);
    BPF_READ(data->start_stack, mm->start_stack);
    data->start_stack_addr = (ulong)(&mm->start_stack);
    data->task = (ulong)t;

    // Check stack map first
    stack = (struct stack_data *)bpf_map_lookup_elem(&stack_map, &pid);
    if (stack && data->sp >= stack->start && data->sp < stack->end) {
        data->stack_pid = stack->pid;
        data->stack_start = stack->start;
        data->stack_end = stack->end;
        data->stack_src = stack->source;
        return ERR_TYPE_NONE;
    }
    else {
        data->stack_pid = pid;
        // Not in map, check task's start_stack
        find_vma(mm, data->start_stack, &data->stack_start, &data->stack_end);
        if (data->sp >= data->stack_start && data->sp < data->stack_end) {
            data->stack_src = STACK_SRC_SELF;
            return ERR_TYPE_NONE;
        }
        else {
            // Unknown stack source, use sp's VMA
            find_vma(mm, data->sp, &data->stack_start, &data->stack_end);
            if (data->sp >= data->stack_start && data->sp < data->stack_end) {
                data->stack_src = STACK_SRC_UNK;
                return ERR_TYPE_UNK_STACK;
            }
            else {
                // sp's VMA not in process memory, possible stack pivot
                data->stack_src = STACK_SRC_ERR;
                return ERR_TYPE_STACK_PIVOT;
            }
        }
    }
}

// eBPF programs for keeping track of thread stack areas
// NOTE: some of these are also syscalls where we'll need
// to check for a stack pivot

/* Function prototype:
 *
 * long clone(ulong clone_flags, void *child_stack,
 *            void *parent_tidptr, void *child_tidptr, 
 *            struct pt_regs *regs);
 *
 * observe creation of new threads to track thread stack areas
 * This will see the newsp value which gives us the stack, but doesn't
 * have the thread's pid yet (hasn't been allocated yet)
 */
SEC("kprobe/clone")
int kprobe_clone(struct pt_regs *ctx)
{
    return 0;
}

// I don't think I need this one?
// TODO: maybe this would be good for _not_ adding a thread stack if
// the clone fails for some reason
SEC("kretprobe/clone")
int kretprobe_clone(struct pt_regs *ctx)
{
    return 0;
}

// TODO: not actually used in most recent version of Anthony's research code
/* Function prototype:
 *
 * void cgroup_post_fork(struct task_struct *child,
 *                       struct kernel_clone_args *kargs)
 *
 * called late enough to have thread's newly allocated pid, and
 * also (since kernel 5.7) has access to kargs which will contain newsp.
 *
 * Call flow to cgroup_post_fork is like so:
 * clone > kernel_clone > copy_process > cgroup_post_fork
 */
SEC("kprobe/cgroup_post_fork")
int kprobe_cgroup_post_fork(struct pt_regs *ctx)
{
    return 0;

    struct stack_pivot_data_t data = { 0 };
    u64 tgid_pid;

    struct task_struct *child = (struct task_struct *)ctx->di;
    struct kernel_clone_args *kargs = (struct kernel_clone_args *)ctx->si;

    // get thread id + process id from new child task_struct
    bpf_core_read(&data.pid, sizeof(data.pid), &child->pid);
    bpf_core_read(&data.tgid, sizeof(data.tgid), &child->tgid);

    // juse like bpf_get_current_pid_tgid, but for new child task_struct
    MAKE_COMBINED_TGID_PID(tgid_pid, data.tgid, data.pid);

    // get newsp from kernel clone args
    bpf_core_read(&data.newsp, sizeof(data.newsp), &kargs->stack);

    // only track stack pointers of non-main threads of userland programs
    // (new kworker tasks will have a stack sp in kernel address space)
    if (data.newsp != 0 && data.newsp < 0x800000000000) {
        bpf_printk("[cgroup_post_fork] adding %#lx -> %#lx", tgid_pid, &data.newsp);
        bpf_map_update_elem(&thread_stacks, &tgid_pid, &data.newsp, BPF_ANY);
    }

    // send the event
    // TODO: turn this into events only for stack pivots
    bpf_ringbuf_output(&stack_pivot_events, &data, sizeof(data), 0);
}

/* Function prototype:
 *
 * void wake_up_new_task(struct task_struct *p)
 *
 * Called each time a new thread is created, so we can update the map with
 * a new entry with a valid thread ID (key) and stack base (value). This 
 * kprobe is required to catch a new thread's ID before it starts.
 */
SEC("kprobe/wake_up_new_task")
int kprobe_wake_up_new_task(struct pt_regs *ctx)
{
    return 0;
}

SEC("kprobe/do_exit")
int kprobe_do_exit(struct pt_regs *ctx)
{
    return 0;
}


// Everything below here are eBPF programs only for monitoring syscalls shellcode
// using a stack pivot may use. This is where we check if a stack pivot is happening

/* Function prototype:
 *
 * int execve(const char *filename, const char *argv, const char *envp);
 * 
 * watch for stack pivots by checking userland stack pointer
 */
SEC("kprobe/execve")
int kprobe_execve(struct pt_regs *ctx)
{
    struct pt_regs *uctx;
    unsigned long user_sp;

    uctx = (struct pt_regs *)ctx->di;

    bpf_core_read(&user_sp, sizeof(user_sp), uctx->sp);

    return 0;
}

//*
// TODO: fix this, use a proper syscall handling function
SEC("kprobe/ksys_mmap_pgoff")
int handle_mmap(struct pt_regs *ctx)
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    pid_t tgid = tgid_pid >> 32;
    pid_t pid = tgid_pid;


    // fetch user's stack pointer, check against map entry (should one exist)
    unsigned long user_sp = ctx->sp;

    bpf_printk("[ksys_mmap_pgoff] %d:%d (%#lx)", tgid, pid, tgid_pid);
    if (tgid != pid){
        // non-main thread case, check map
        bpf_printk("[do_mmap] lookup up %#lx", tgid_pid);
        void *val = bpf_map_lookup_elem(&thread_stacks, &tgid_pid);
        if (val != NULL) {
            // check user sp against newsp value from clone call which created this thread
            bpf_printk("\tuser_sp: %#lx, newsp: %#lx", user_sp, *((unsigned long *)val));
        }
        else {
            // no entry; assume thread exists before we were loaded
            bpf_printk("\tuser_sp: %#lx, (thread creation not observed)", user_sp);
        }
    } else {
        // main thread case, task_struct info should be accurate
        bpf_printk("\tmain thread case. TODO: look up stack from current task_struct");
    }

    return 0;
}
//*/

/*
// Actually, seems like a tracepoint won't work; we don't get the user's sp register
// taken from /sys/kernel/debug/tracing/events/syscalls/sys_enter_mmap/format
struct sys_enter_mmap_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    int __syscall_nr;
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    unsigned long fd;
    unsigned long off;
};

SEC("tracepoint/syscalls/sys_enter_mmap")
int handle__sys_enter_mmap(struct sys_enter_mmap_args *ctx)
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    pid_t tgid = tgid_pid >> 32;
    pid_t pid = tgid_pid;

    bpf_printk("[sys_enter_mmap] %d:%d\n", tgid, pid);

    return 0;
}
//*/
