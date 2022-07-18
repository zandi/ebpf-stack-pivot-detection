#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "utils.h"

//#define SIGKILL_ENABLED 1

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// struct definitions

struct stack_data {
    int source; // where the stack VMA was found
    int pid; // original task that created stack
    ulong start;
    ulong end;
};

// TODO: use this to report detected stack pivot attempts/events to userland
struct stack_pivot_event_t {
    struct slim_data_t data;
    // TODO: add only the necessary fields below, based on experience
};

// maps
BPF_MAP_DEF(register_kprobe)
BPF_MAP_DEF(execve)
BPF_MAP_DEF(clone)
BPF_MAP_DEF(clone_ret)
BPF_MAP_DEF(wake_up_new_task)
BPF_MAP_DEF(cgroup_post_fork)
BPF_MAP_DEF(do_exit)
BPF_MAP_DEF(new_stack)
BPF_MAP_DEF(stack_pivot_event)

// use a single ringbuf map to simplify things for now for the rust side
// later we'll just have a single ringbuf to report events, and not have a
// type/ringbuf for every eBPF program
BPF_MAP_DEF(generic_event)

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

// force exporting types to rust skeleton
#define EXPORT_TYPE(t) \
    struct t __unused_##t = {0}
EXPORT_TYPE(event_data_t);
EXPORT_TYPE(clone_data);
EXPORT_TYPE(do_exit_data);
EXPORT_TYPE(stack_data);
EXPORT_TYPE(slim_data_t);
EXPORT_TYPE(stack_pivot_event_t);

/* our version of the sp checking routine
 *
 * determine (to the best of our ability) if the given stack pointer user_sp
 * is within the current task's stack region.
 *
 * For main threads of a process this is relatively straightforward. For other
 * threads in a process we have to manually track the stack region when the
 * thread is first created (clone is passed a newsp argument by the userland program,
 * which is responsible for setting up the new thread's stack).
 *
 * For non-main threads which exist before our programs are loaded to track thread creation,
 * we will also fail this lookup. So we need to determine if a thread is 'ancient' and
 * thus not properly tracked by us, or if it's 'recent' and is.
 */
static int check_stack_pivot(struct slim_data_t *data, struct task_struct *t)
{
    struct stack_data *stack;
    struct mm_struct *mm;
    uint pid, tgid;
    int res;
    unsigned long start_stack;
    unsigned long found_stack_start, found_stack_end;
    unsigned long user_sp;

    BPF_READ(pid, t->pid);
    BPF_READ(tgid, t->tgid);
    BPF_READ(mm, t->mm);
    BPF_READ(start_stack, mm->start_stack);
    user_sp = data->sp;

    // side-affects in data struct taken from check_stack_vma
    data->start_stack_addr = (ulong)(&mm->start_stack);
    data->task = (ulong)t;

    /*
    data->stack_pid = stack->pid;
    data->stack_start = stack->start;
    data->stack_end = stack->end;
    data->stack_src = stack->source;
    //*/

    // regardless of case, check our map first. We've observed main threads of a thread group (process)
    // which have their stack residing somewhere besides where current->mm->start_stack indicates.
    stack = (struct stack_data *)bpf_map_lookup_elem(&stack_map, &pid);
    if (stack) {
        // recent thread where we know the stack region allocated for it
        found_stack_start = stack->start;
        found_stack_end = stack->end;
        bpf_printk("[check_stack_pivot] %d:%d", tgid, pid);
        bpf_printk("[check_stack_pivot] tracked thread stack [%lx, %lx)", found_stack_start, found_stack_end);
        if (found_stack_start <= user_sp && user_sp < found_stack_end) {
            // good
            data->stack_pid = stack->pid;
            data->stack_start = found_stack_start;
            data->stack_end = found_stack_end;
            data->stack_src = STACK_SRC_SELF;
            return ERR_LOOKS_OK;
        }
        else {
            // bad
            data->stack_pid = pid;
            data->stack_start = found_stack_start;
            data->stack_end = found_stack_end;
            data->stack_src = STACK_SRC_SELF;
            return ERR_STACK_PIVOT;
        }
    }
    // no tracked stack region, fall back to other checks (if possible)
    else {
        if (pid == tgid) {
            // this case may be fatally flawed (we're unable to consistently answer), do more testing.
            res = find_vma(mm, start_stack, &found_stack_start, &found_stack_end);
            if (res == FIND_VMA_FAILURE) {
                // start_stack in task_struct not backed by a vma? Is this just a segfault?
                bpf_printk("[check_stack_pivot] %d:%d main thread, untracked, but mm->start_stack has no VMA?", tgid, pid);
                data->stack_pid = pid;
                data->stack_start = 0;
                data->stack_end = 0;
                data->stack_src = STACK_SRC_ERR;
                return ERR_NO_VMA;
            }
            bpf_printk("[check_stack_pivot] %d:%d", tgid, pid);
            bpf_printk("[check_stack_pivot] main thread, untracked, start_stack vma [%lx, %lx)", found_stack_start, found_stack_end);
            if (found_stack_start <= user_sp && user_sp < found_stack_end) {
                // stack pointer in stack VMA, everything looks good here
                data->stack_pid = pid;
                data->stack_start = found_stack_start;
                data->stack_end = found_stack_end;
                data->stack_src = STACK_SRC_SELF;
                return ERR_LOOKS_OK;
            }
            else {
                // stack pointer _outside_ the main thread's stack VMA, stack pivot
                data->stack_pid = pid;
                data->stack_start = found_stack_start;
                data->stack_end = found_stack_end;
                data->stack_src = STACK_SRC_SELF;
                return ERR_STACK_PIVOT;
            }
                // main thread, start_stack _might_ work (but might also have false positive risk?)
        }
        else {
            // non-main thread without a tracked stack region (before we loaded). Pretty sure we have no hope here of being correct
            bpf_printk("[check_stack_pivot] %d:%d ancient non-main thread, untracked. sp:%lx", tgid, pid, user_sp);
            data->stack_pid = pid;
            data->stack_start = 0;
            data->stack_end = 0;
            data->stack_src = STACK_SRC_UNK;
            return ERR_ANCIENT_THREAD;
        }
    }

    /*
    // case 1: main thread (tid == pid)
    if (pid == tgid) {
        // start_stack *should* lead us to the stack VMA. Find this VMA and check if user_sp
        // is within it.
        res = find_vma(mm, start_stack, &found_stack_start, &found_stack_end);
        if (res == FIND_VMA_FAILURE) {
            // start_stack in task_struct not backed by a vma? Is this just a segfault?
            bpf_printk("[check_stack_pivot] %d:%d main thread, but mm->start_stack has no VMA?", tgid, pid);
            data->stack_pid = pid;
            data->stack_start = 0;
            data->stack_end = 0;
            data->stack_src = STACK_SRC_ERR;
            return ERR_NO_VMA;
        }
        bpf_printk("[check_stack_pivot] %d:%d", tgid, pid);
        bpf_printk("[check_stack_pivot] main thread stack [%lx, %lx)", found_stack_start, found_stack_end);
        if (found_stack_start <= user_sp && user_sp < found_stack_end) {
            // stack pointer in stack VMA, everything looks good here
            data->stack_pid = pid;
            data->stack_start = found_stack_start;
            data->stack_end = found_stack_end;
            data->stack_src = STACK_SRC_SELF;
            return ERR_LOOKS_OK;
        }
        else {
            // stack pointer _outside_ the main thread's stack VMA, stack pivot
            data->stack_pid = pid;
            data->stack_start = found_stack_start;
            data->stack_end = found_stack_end;
            data->stack_src = STACK_SRC_SELF;
            return ERR_STACK_PIVOT;
        }
    }
    // case 2: non-main thread (tid != pid)
    else {
        // check if we have a known stack area for this task
        stack = (struct stack_data *)bpf_map_lookup_elem(&stack_map, &pid);
        if (stack) {
            // recent thread where we know the stack region allocated for it
            found_stack_start = stack->start;
            found_stack_end = stack->end;
            bpf_printk("[check_stack_pivot] %d:%d", tgid, pid);
            bpf_printk("[check_stack_pivot] non-main thread stack [%lx, %lx)", found_stack_start, found_stack_end);
            if (found_stack_start <= user_sp && user_sp < found_stack_end) {
                // good
                data->stack_pid = stack->pid;
                data->stack_start = found_stack_start;
                data->stack_end = found_stack_end;
                data->stack_src = STACK_SRC_SELF;
                return ERR_LOOKS_OK;
            }
            else {
                // bad
                data->stack_pid = pid;
                data->stack_start = found_stack_start;
                data->stack_end = found_stack_end;
                data->stack_src = STACK_SRC_SELF;
                return ERR_STACK_PIVOT;
            }
        }
        else {
            // ancient thread? (no tracked stack region found)
            bpf_printk("[check_stack_pivot] %d:%d ancient non-main thread? no recorded stack from clone newsp", tgid, pid);
            data->stack_pid = pid;
            data->stack_start = 0;
            data->stack_end = 0;
            data->stack_src = STACK_SRC_UNK;
            return ERR_ANCIENT_THREAD;
        }
    }
    //*/
}

/* Searches backlog of stack VMAs for one that contains the current stack
 * pointer. If none found, then checks SP against VMA of the current task's
 * start_stack. Returns a warning error code if SP is in a VMA that is 
 * not known to us as a valid stack VMA. If SP is not in any VMA of the
 * current task, returns an alert error code.
 *
 * struct slim_data_t *data      sp should be set before calling this function;
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
static int check_stack_vma(struct slim_data_t *data, struct task_struct *t)
{
    struct stack_data *stack;
    struct mm_struct *mm;
    uint pid;
    int res;

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
        res = find_vma(mm, data->start_stack, &data->stack_start, &data->stack_end);
        if (res == FIND_VMA_FAILURE) {
            bpf_printk("[check_stack_vma] find_vma failed for data->start_stack");
        }
        if (data->sp >= data->stack_start && data->sp < data->stack_end) {
            data->stack_src = STACK_SRC_SELF;
            return ERR_TYPE_NONE;
        }
        else {
            // Unknown stack source, use sp's VMA
            res = find_vma(mm, data->sp, &data->stack_start, &data->stack_end);
            if (res == FIND_VMA_FAILURE) {
                bpf_printk("[check_stack_vma] find_vma failed for data->sp");
            }
            if (data->sp >= data->stack_start && data->sp < data->stack_end) {
                data->stack_src = STACK_SRC_UNK;
                return ERR_TYPE_UNK_STACK;
            }
            else { // TODO: is this case even possible? Shouldn't any sp which is valid (doesn't segfault) have a VMA?
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
SEC("kprobe/__x64_sys_clone")
int kprobe_clone(struct pt_regs *ctx)
{
    struct clone_user_args clone_args = { 0 };
    struct stack_pivot_event_t sp_event = { 0 };

    struct slim_data_t *data = &sp_event.data;
    struct pt_regs *uctx;
    struct task_struct *t;
    int *tid_tmp;
    int stack_pivot_res;

    t = init_probe_data(data);

    if (t->flags & PF_KTHREAD)
        return 0;

    // sys_clone user args
    uctx = (struct pt_regs *)ctx->di;
    BPF_READ(clone_args.clone_flags, uctx->di);
    BPF_READ(clone_args.newsp, uctx->si);

    BPF_READ(tid_tmp, uctx->dx);
    bpf_probe_read(&clone_args.parent_tid, sizeof(clone_args.parent_tid), tid_tmp);
    BPF_READ(tid_tmp, uctx->r10);
    bpf_probe_read(&clone_args.child_tid, sizeof(clone_args.child_tid), tid_tmp);

    BPF_READ(data->sp, uctx->sp);

    int has_clone_vm = (clone_args.clone_flags & CLONE_VM) ? 1 : 0;
    int has_clone_thread = (clone_args.clone_flags & CLONE_THREAD) ? 1 : 0;
    bpf_printk("[clone] %d:%d", data->pid, data->tid);
    bpf_printk("[clone]\tclone_vm: %d, clone_thread: %d", has_clone_vm, has_clone_thread);
    bpf_printk("[clone]\tnewsp: %lx", clone_args.newsp);

    //data->err = check_stack_vma(data, t);

    // TODO: we're having weird issues here. Lots of false positives.
    // for a process which has a non-leader thread fork+execve something else
    //*
    stack_pivot_res = check_stack_pivot(data, t);
    if (stack_pivot_res != ERR_LOOKS_OK) {
        bpf_printk("[clone]\tnot-ok stack pivot check: %x", stack_pivot_res);
        if (stack_pivot_res == ERR_STACK_PIVOT) {
            bpf_printk("\t***** stack pivot! sp:%lx *****", data->sp);
        }
    }
    data->err = stack_pivot_res;

    bpf_ringbuf_output(&BPF_MAP_NAME(stack_pivot_event), data, sizeof(struct slim_data_t), 0);
    //*/

    /*
    if (data->err == ERR_TYPE_STACK_PIVOT) {
        bpf_printk("\t***** stack pivot detected! *****");
    }
    //*/

    return 0;
}

// if we need to kprobe like this, we'll have to make sure we catch
// all possible entrypoints so we aren't evaded
// TODO: verify we can reach this (int 0x80?)
SEC("kprobe/__ia32_sys_clone")
int kprobe_clone_ia32(struct pt_regs *ctx)
{
    return 0;
}

// TODO: basically just for debugging, could disable/remove
SEC("kretprobe/__x64_sys_clone")
int kretprobe_clone(struct pt_regs *ctx)
{
    struct clone_data clone_data = { 0 };
    struct slim_data_t *data = &clone_data.data;
    struct task_struct *t;

    t = init_probe_data(data);

    if (t->flags & PF_KTHREAD)
        return 0;

    // PT_REGS_RC_CORE macro not found. Just use rax, since we're only x86_64
    BPF_READ(data->retval, ctx->ax);

    bpf_printk("[clone return] %d:%d -> %d", data->pid, data->tid, data->retval);

    return 0;
}

/* Function prototype:
 *
 * void wake_up_new_task(struct task_struct *p)
 *
 * Called each time a new thread is created, so we can update the map with
 * a new entry with a valid thread ID (key) and stack base (value). This 
 * kprobe is required to catch a new thread's ID before it starts.
 *
 * Really, this is necessary because it has the new task's task_struct, which
 * allows us to find the stack region's VMA, and thus full start/end address, which
 * is far more useful than just a known good stack pointer.
 */
SEC("kprobe/wake_up_new_task")
int kprobe_wake_up_new_task(struct pt_regs *ctx)
{
    struct wake_up_new_task_data wake_up_new_task_data = { 0 };
    struct slim_data_t *data = &wake_up_new_task_data.data;
    struct task_struct *new_task;
    struct mm_struct *mm;
    struct fork_frame *fork_frame;
    struct stack_data stack = { 0 };
    uint flags;

    init_probe_data(data);
 
    // Get new task thread ID
    new_task = (struct task_struct *)ctx->di;
    BPF_READ(flags, new_task->flags);
    if (flags & PF_KTHREAD)
        return 0;
    BPF_READ(data->new_pid, new_task->pid);
    BPF_READ(mm, new_task->mm);
    BPF_READ(data->start_stack, mm->start_stack);
    wake_up_new_task_data.args.task = new_task;

    /* Get stack VMA using the new task's pt_regs->sp. In kernels >= 4.9 
     * the new task's pt_regs is saved to the regs field in a fork_frame
     * struct. This fork_frame is saved to the new task's thread.sp field. In 
     * kernels < 4.9 pt_regs is saved directly to thread.sp. */

    BPF_READ(fork_frame, new_task->thread.sp);
    BPF_READ(data->sp, fork_frame->regs.sp);
    find_vma(mm, data->sp, &stack.start, &stack.end);
    stack.pid = data->new_pid;
    if (stack.start && stack.end) {
        // Update stack map with new thread stack info
        bpf_map_update_elem(&stack_map, &data->new_pid, &stack, BPF_NOEXIST);
        data->stack_start = stack.start;
        data->stack_end = stack.end;
        data->stack_pid = stack.pid;

        bpf_printk("[wake_up_new_task] pid %d new stack: [%lx, %lx)", stack.pid, stack.start, stack.end);
    }
    else {
        // TODO: report some kind of error? we should be able to find the VMA
        bpf_printk("[wake_up_new_task] ERROR: no stack VMA found");
    }


    // tell the user about a new stack (debug output)
    //bpf_ringbuf_output(&BPF_MAP_NAME(new_stack), &stack, sizeof(stack), 0);

    return 0;
}

// Clean up our thread stack map when a thread exits.
SEC("kprobe/do_exit")
int kprobe_do_exit(struct pt_regs *ctx)
{
    struct do_exit_data do_exit_data = { 0 };
    struct slim_data_t *data = &do_exit_data.data;
    struct pt_regs *uctx;
    struct task_struct *t;

    t = init_probe_data(data);

    if (t->flags & PF_KTHREAD)
        return 0;

    // do_exit args
    uctx = (struct pt_regs *)ctx->di;
    BPF_READ(do_exit_data.args.code, uctx->di);

    // Delete entry for exiting thread
    bpf_map_delete_elem(&stack_map, &data->tid);
    data->time = bpf_ktime_get_ns();

    bpf_printk("[do_exit] %d:%d", data->pid, data->tid);

    return 0;
}


// Everything below here are eBPF programs only for monitoring syscalls that shellcode
// using a stack pivot may use. This is where we check if a stack pivot is happening

/* Function prototype:
 *
 * int execve(const char *filename, const char *argv, const char *envp);
 * 
 * watch for stack pivots by checking userland stack pointer
 */
SEC("kprobe/__x64_sys_execve")
int kprobe_execve(struct pt_regs *ctx)
{
    struct pt_regs *uctx;
    unsigned long user_sp;
    struct slim_data_t data = {0};
    struct task_struct *t;
    int stack_pivot_res;

    //uctx = (struct pt_regs *)ctx->di;
    //bpf_core_read(&user_sp, sizeof(user_sp), uctx->sp);
    BPF_READ(uctx, ctx->di);
    BPF_READ(user_sp, uctx->sp);
    data.sp = user_sp;

    t = init_probe_data(&data);

    //data.err = check_stack_vma(&data, t);
    bpf_printk("[execve] %d:%d", data.pid, data.tid);

    stack_pivot_res = check_stack_pivot(&data, t);
    if (stack_pivot_res != ERR_LOOKS_OK) {
        bpf_printk("[execve] not-ok stack pivot check: %x", stack_pivot_res);
        if (stack_pivot_res == ERR_STACK_PIVOT) {
            bpf_printk("\t***** stack pivot! sp:%lx *****", data.sp);
        }
    }
    data.err = stack_pivot_res;

    // just use raw slim_data_t type for execve (only conveying stack pivot check right now)
    bpf_ringbuf_output(&BPF_MAP_NAME(stack_pivot_event), &data, sizeof(data), 0);

    // invalidate this current task's tracked stack region; after the execve we'll
    // have an entirely different one, and will need to rediscover it. If we don't
    // clean up the tracked stack region here, we'll fail subsequent stack pivot checks
    // for this task.
    bpf_map_delete_elem(&stack_map, &data.tid);

    /*
    if (data.err == ERR_TYPE_STACK_PIVOT)
    {
        bpf_printk("[execve]\n\t***** stack pivot detected! *****");
    #ifdef SIGKILL_ENABLED
        // kill current task outright
        // SIGKILL = 9
        bpf_send_signal(9);
    #endif
    }
    //*/

    return 0;
}

// TODO: fix this, use a proper syscall handling function
SEC("kprobe/ksys_mmap_pgoff")
int handle_mmap(struct pt_regs *ctx)
{
    return 0;
}
