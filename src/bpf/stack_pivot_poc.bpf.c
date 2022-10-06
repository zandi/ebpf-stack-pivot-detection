#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "utils.h"

//#define SIGKILL_ENABLED 1

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Chosen based on observing false positives.
firefox 104.0 on Ubuntu 22.04 LTS, 5.15.0-46-generic

rsp:       0x00007fc6e5708f48
vma start: 0x00007fff402f2000
common:    0xffffffc000000000
*/
#define COMPARISON_MASK 0xffffff8000000000

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

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1);
    __type(key, u64);
    __type(value, struct stack_data);
} clone3_edgecase SEC(".maps");

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
 *
 * TODO: explore possibility of golang goroutine edge case. We get false positives
 * from golang because of how goroutines are implemented/scheduled on different
 * threads. If these false positives are predictable in some way, we may be able
 * to make an exception for them.
 */
static int check_stack_pivot(struct slim_data_t *data, struct task_struct *t)
{
    struct stack_data *stack;
    struct mm_struct *mm;
    uint pid, tgid;
    int res;
    unsigned long start_stack;
    unsigned long found_stack_start, found_stack_end;
    unsigned long sp_vma_start, sp_vma_end;
    unsigned long user_sp;

    BPF_READ(pid, t->pid);
    BPF_READ(tgid, t->tgid);
    BPF_READ(mm, t->mm);
    BPF_READ(start_stack, mm->start_stack);
    user_sp = data->sp;

    // side-affects in data struct taken from check_stack_vma
    data->start_stack_addr = (ulong)(&mm->start_stack);
    data->task = (ulong)t;

    // redone-redone check.
    // pid == tid => thread group leader, sp should be in mm->start_stack vma
    // pid != tid => non-leader thread, stack should be tracked in map.
    //    stack tracked in map => sp should be in tracked region
    //    stack not tracked in map => ancient thread, fail open (can't conclude good/bad)
    // special case: hardcoded exception regions for golang

    // TODO: verify correctness against golang runtime/extensive testing
    if (   (0xc000000000 <= user_sp && user_sp <= 0xc000ffffff)
        || (0xc420000000 <= user_sp && user_sp <= 0xc420ffffff) ) {
        data->stack_pid = stack->pid;
        data->stack_start = found_stack_start;
        data->stack_end = found_stack_end;
        data->stack_src = STACK_SRC_SELF;
        return ERR_POSSIBLE_GOLANG_STACK;
    }

    // look up vmas for mm->start_stack and observed sp
    res = find_vma_range(mm, start_stack, &found_stack_start, &found_stack_end);
    if (res == FIND_VMA_FAILURE) {
        // start_stack in task_struct not backed by a vma? Is this just a segfault?
        bpf_printk("[check_stack_pivot] %d:%d mm->start_stack has no VMA?", tgid, pid);
        data->stack_pid = pid;
        data->stack_start = 0;
        data->stack_end = 0;
        data->stack_src = STACK_SRC_ERR;
        return ERR_NO_VMA;
    }
    // for debugging
    res = find_vma_range(mm, user_sp, &sp_vma_start, &sp_vma_end);
    if (res == FIND_VMA_FAILURE) {
        bpf_printk("[check_stack_pivot] %d:%d sp has no VMA?", tgid, pid);
        data->stack_pid = pid;
        data->stack_start = 0;
        data->stack_end = 0;
        data->stack_src = STACK_SRC_ERR;
        return ERR_NO_VMA;
    }
    // debugging info
    bpf_printk("[check_stack_pivot] %d:%d", tgid, pid);
    bpf_printk("[check_stack_pivot] mm->start_stack vma [%lx, %lx)", found_stack_start, found_stack_end);
    bpf_printk("[check_stack_pivot] \tvma size: %lx", found_stack_end - found_stack_start);
    bpf_printk("[check_stack_pivot] user_sp vma [%lx, %lx)", sp_vma_start, sp_vma_end);
    bpf_printk("[check_stack_pivot] \tvma size: %lx", sp_vma_end - sp_vma_start);

    // we'll need to refer to our tracked stacks regardless of thread group leader status
    stack = (struct stack_data *)bpf_map_lookup_elem(&stack_map, &pid);

    // thread group leader case. check mm->start_stack
    // OR edge case of sp in [sp, end_addr) vma from wake_up_new_task (sp is start)
    if (pid == tgid) {

        // check if sp is in this found start_stack vma (thread group leader)
        unsigned long stack_start, stack_end;
        if (stack) {
            // edge case where sp is initially at start of a VMA.  we add a
            // tracked region in wake_up_new_task because the VMA we get from
            // mm->start_stack will in practice be wrong, so we have to
            // manually adjust.
            stack_start = stack->start;
            stack_end = stack->end;
            bpf_printk("[check_stack_pivot] tracked thread stack [%lx, %lx)", stack_start, stack_end);
        }
        else {
            stack_start = found_stack_start;
            stack_end = found_stack_end;
        }

        bpf_printk("[check_stack_pivot] assuming stack is [%lx, %lx)", stack_start, stack_end);
        if (stack_start <= user_sp && user_sp < stack_end) {
            // stack pointer in stack VMA, everything looks good here
            data->stack_pid = pid;
            data->stack_start = found_stack_start;
            data->stack_end = found_stack_end;
            data->stack_src = STACK_SRC_SELF;
            return ERR_LOOKS_OK;
        }
        else {
            // bad
            bpf_printk("[check_stack_pivot]\t*** stack pivot detected! ***");
            data->stack_pid = pid;
            data->stack_start = found_stack_start;
            data->stack_end = found_stack_end;
            data->stack_src = STACK_SRC_SELF;
            return ERR_STACK_PIVOT;
        }
    }
    // non-leader case. Check our map for the thread's stack (which cannot grow*)
    else {
        // check stack map
        if (stack) {
            // recent thread where we know the stack region allocated for it
            found_stack_start = stack->start;
            found_stack_end = stack->end;

            bpf_printk("[check_stack_pivot] %d:%d", tgid, pid);
            bpf_printk("[check_stack_pivot] tracked thread stack [%lx, %lx)", found_stack_start, found_stack_end);
            if (found_stack_start <= user_sp && user_sp < found_stack_end) {
            // heuristic for 'reasonably close' based on observed false positives
            //if ( ((user_sp ^ found_stack_start) & COMPARISON_MASK) == 0) {
                // good
                data->stack_pid = stack->pid;
                data->stack_start = found_stack_start;
                data->stack_end = found_stack_end;
                data->stack_src = STACK_SRC_SELF;
                return ERR_LOOKS_OK;
            }
            // golang exception case already handled above
            else {
                // bad
                bpf_printk("[check_stack_pivot]\t*** stack pivot detected! ***");
                data->stack_pid = stack->pid;
                data->stack_start = found_stack_start;
                data->stack_end = found_stack_end;
                data->stack_src = STACK_SRC_SELF;
                return ERR_STACK_PIVOT;
            }
        }
        else {
            // not tracked, ancient thread
            bpf_printk("[check_stack_pivot] %d:%d ancient non-main thread, untracked. sp:%lx", tgid, pid, user_sp);
            data->stack_pid = pid;
            data->stack_start = 0;
            data->stack_end = 0;
            data->stack_src = STACK_SRC_UNK;
            return ERR_ANCIENT_THREAD;
        }
    }

    /*
    ///////////////////////////////////////////////////////////////////
    // redone-redone check: try anthony's approach.
    // - check start_stack vma
    // - check stack map

    // TODO: verify correctness against golang runtime/extensive testing
    if (   (0xc000000000 <= user_sp && user_sp <= 0xc000ffffff)
        || (0xc420000000 <= user_sp && user_sp <= 0xc420ffffff) ) {
        data->stack_pid = stack->pid;
        data->stack_start = found_stack_start;
        data->stack_end = found_stack_end;
        data->stack_src = STACK_SRC_SELF;
        return ERR_POSSIBLE_GOLANG_STACK;
    }

    res = find_vma_range(mm, start_stack, &found_stack_start, &found_stack_end);
    if (res == FIND_VMA_FAILURE) {
        // start_stack in task_struct not backed by a vma? Is this just a segfault?
        bpf_printk("[check_stack_pivot] %d:%d mm->start_stack has no VMA?", tgid, pid);
        data->stack_pid = pid;
        data->stack_start = 0;
        data->stack_end = 0;
        data->stack_src = STACK_SRC_ERR;
        return ERR_NO_VMA;
    }
    res = find_vma_range(mm, user_sp, &sp_vma_start, &sp_vma_end);
    if (res == FIND_VMA_FAILURE) {
        bpf_printk("[check_stack_pivot] %d:%d sp has no VMA?", tgid, pid);
        data->stack_pid = pid;
        data->stack_start = 0;
        data->stack_end = 0;
        data->stack_src = STACK_SRC_ERR;
        return ERR_NO_VMA;
    }

    bpf_printk("[check_stack_pivot] %d:%d", tgid, pid);
    bpf_printk("[check_stack_pivot] mm->start_stack vma [%lx, %lx)", found_stack_start, found_stack_end);
    bpf_printk("[check_stack_pivot] \tvma size: %lx", found_stack_end - found_stack_start);
    bpf_printk("[check_stack_pivot] user_sp vma [%lx, %lx)", sp_vma_start, sp_vma_end);
    bpf_printk("[check_stack_pivot] \tvma size: %lx", sp_vma_end - sp_vma_start);

    // check if sp is in this found start_stack vma (thread group leader)
    if (found_stack_start <= user_sp && user_sp < found_stack_end) {
        // stack pointer in stack VMA, everything looks good here
        data->stack_pid = pid;
        data->stack_start = found_stack_start;
        data->stack_end = found_stack_end;
        data->stack_src = STACK_SRC_SELF;
        return ERR_LOOKS_OK;
    }

    // check stack map
    stack = (struct stack_data *)bpf_map_lookup_elem(&stack_map, &pid);
    if (stack) {
        // recent thread where we know the stack region allocated for it
        found_stack_start = stack->start;
        found_stack_end = stack->end;

        bpf_printk("[check_stack_pivot] %d:%d", tgid, pid);
        bpf_printk("[check_stack_pivot] tracked thread stack [%lx, %lx)", found_stack_start, found_stack_end);
        //if (found_stack_start <= user_sp && user_sp < found_stack_end) {
        // heuristic for 'reasonably close' based on observed false positives
        if ( ((user_sp ^ found_stack_start) & COMPARISON_MASK) == 0) {
            // good
            data->stack_pid = stack->pid;
            data->stack_start = found_stack_start;
            data->stack_end = found_stack_end;
            data->stack_src = STACK_SRC_SELF;
            return ERR_LOOKS_OK;
        }
        // golang exception case already handled above
        else {
            // bad
            data->stack_pid = stack->pid;
            data->stack_start = found_stack_start;
            data->stack_end = found_stack_end;
            data->stack_src = STACK_SRC_SELF;
            return ERR_STACK_PIVOT;
        }
    }
    // at this point, we know 1) not golang, 2) not in mm->start_stack (thread group leader)
    // 3) not in a tracked region for this task. (not thread group leader)
    // so, all that's left is either an ancient thread, or stack pivot.
    // no tracked stack region, fall back to other checks (if possible)
    else {
        if (pid == tgid) {
            // this case may be fatally flawed (we're unable to consistently answer), do more testing.
            res = find_vma_range(mm, start_stack, &found_stack_start, &found_stack_end);
            if (res == FIND_VMA_FAILURE) {
                // start_stack in task_struct not backed by a vma? Is this just a segfault?
                bpf_printk("[check_stack_pivot] %d:%d main thread, untracked, but mm->start_stack has no VMA?", tgid, pid);
                data->stack_pid = pid;
                data->stack_start = 0;
                data->stack_end = 0;
                data->stack_src = STACK_SRC_ERR;
                return ERR_NO_VMA;
            }
            // false positives here (hasn't happened yet)
            bpf_printk("[check_stack_pivot] %d:%d", tgid, pid);
            bpf_printk("[check_stack_pivot] main thread, untracked, start_stack vma [%lx, %lx)", found_stack_start, found_stack_end);
            //if (found_stack_start <= user_sp && user_sp < found_stack_end) {
            if ( ((user_sp ^ found_stack_start) & COMPARISON_MASK) == 0) {
                // stack pointer in stack VMA, everything looks good here
                data->stack_pid = pid;
                data->stack_start = found_stack_start;
                data->stack_end = found_stack_end;
                data->stack_src = STACK_SRC_SELF;
                return ERR_LOOKS_OK;
            }
            // special-case for golang (TODO: verify correctness)
            else if (0xc000000000 <= user_sp && user_sp <= 0xc000ffffff) {
                data->stack_pid = pid;
                data->stack_start = found_stack_start;
                data->stack_end = found_stack_end;
                data->stack_src = STACK_SRC_SELF;
                return ERR_POSSIBLE_GOLANG_STACK;
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
    */
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

    struct mm_struct *mm;
    ulong vma_start, vma_end;
    int res;

    t = init_probe_data(data);

    BPF_READ(mm, t->mm);

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

    res = find_vma_range(mm, clone_args.newsp, &vma_start, &vma_end);
    if (res == FIND_VMA_SUCCESS) {
        bpf_printk("[clone]\tnewsp vma: [%lx, %lx)", vma_start, vma_end);
    }

    stack_pivot_res = check_stack_pivot(data, t);
    if (stack_pivot_res != ERR_LOOKS_OK) {
        bpf_printk("[clone]\tnot-ok stack pivot check: %x", stack_pivot_res);
        if (stack_pivot_res == ERR_STACK_PIVOT) {
            bpf_printk("\t***** stack pivot! sp:%lx *****", data->sp);
        }
    }
    data->err = stack_pivot_res;

    bpf_ringbuf_output(&BPF_MAP_NAME(stack_pivot_event), data, sizeof(struct slim_data_t), 0);

    return 0;
}

SEC("kprobe/__x64_sys_clone3")
int kprobe_clone3(struct pt_regs *ctx)
{
    struct clone_user_args clone_args = { 0 };
    struct stack_pivot_event_t sp_event = { 0 };

    struct clone_args *uargs;
    struct clone_args local_uargs = { 0 };
    size_t size;

    ulong clone_flags;
    ulong new_stack;
    u64 stack_size;

    struct slim_data_t *data = &sp_event.data;
    struct pt_regs *uctx;
    struct task_struct *t;
    struct mm_struct *mm;
    struct stack_data stack = { 0 };

    t = init_probe_data(data);

    if (t->flags & PF_KTHREAD)
        return 0;

    BPF_READ(mm, t->mm);

    // get the flags/stack from uargs struct
    // CLONE_VM flag implies we must have stack provided in uargs

    // load args
    BPF_READ(uctx, ctx->di);
    BPF_READ(uargs, uctx->di);
    BPF_READ(size, uctx->si);
    bpf_probe_read(&local_uargs, sizeof(local_uargs), uargs);

    clone_args.clone_flags = local_uargs.flags;
    clone_args.newsp = local_uargs.stack;
    stack_size = local_uargs.stack_size;

    find_vma_range(mm, clone_args.newsp, &stack.start, &stack.end);

    int has_clone_vm = (clone_args.clone_flags & CLONE_VM) ? 1 : 0;
    int has_clone_vfork = (clone_args.clone_flags & CLONE_VFORK) ? 1 : 0;
    int has_clone_thread = (clone_args.clone_flags & CLONE_THREAD) ? 1 : 0;

    bpf_printk("[clone3] %d:%d, clone_vm: %d", data->pid, data->tid, has_clone_vm);
    bpf_printk("\tuargs: %lx, size: %d", uargs, size);
    bpf_printk("\tflags: %lx, newsp suggested region: [%lx, %lx)", clone_args.clone_flags, clone_args.newsp, clone_args.newsp + stack_size);
    bpf_printk("\tnewsp vma: [%lx, %lx)", stack.start, stack.end);
    if (clone_args.newsp != stack.start || (clone_args.newsp + stack_size != stack.end)) {
        bpf_printk("\t*** user-defined stack is not identical to VMA it resides in ***");
    }

    // observed false positive case from `apt instal` on Ubuntu 22.04
    // mmap_mprotect case exhibits clone_vm and clone_thread (among others)
    // but handling that mmap_mprotect case introduces worse false positives...
    //if (has_clone_vm && (has_clone_vfork || has_clone_thread)) {
    if (has_clone_vm && has_clone_vfork) {
        bpf_printk("\t*** observed false positive case. Adding caller-specified stack to map ***");
        u32 tid = data->tid; // tid is unique, safe to use to identify tasks (threads)
        int res = bpf_map_update_elem(&clone3_edgecase, &tid, &stack, BPF_NOEXIST);
        if (res < 0) {
            bpf_printk("\tERROR: unable to add stack info to clone3_edgecase map");
        }
    }

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

// TODO: basically just for debugging, could disable/remove
SEC("kretprobe/__x64_sys_clone3")
int kretprobe_clone3(struct pt_regs *ctx)
{
    struct clone_data clone_data = { 0 };
    struct slim_data_t *data = &clone_data.data;
    struct task_struct *t;

    t = init_probe_data(data);

    if (t->flags & PF_KTHREAD)
        return 0;

    // PT_REGS_RC_CORE macro not found. Just use rax, since we're only x86_64
    BPF_READ(data->retval, ctx->ax);

    bpf_printk("[clone3 return] %d:%d -> %d", data->pid, data->tid, data->retval);

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
    int res;

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
    stack.pid = data->new_pid;

    // handle clone3 edge-case. Our normal fork_frame inspection gets us
    // the wrong VMA in this case, so we get it directly from clone3 entry
    void *clone3_stack = bpf_map_lookup_elem(&clone3_edgecase, &(data->tid));
    if (clone3_stack != NULL) {
        bpf_printk("[wake_up_new_task] pid %d", stack.pid);
        bpf_printk("\tfrom clone3 sp: %lx, vma: [%lx, %lx)", data->sp, stack.start, stack.end);
        /* TODO: testing sp == vma.start edge-case detection
        res = bpf_map_update_elem(&stack_map, &data->new_pid, clone3_stack, BPF_NOEXIST);
        if (res < 0) {
            bpf_printk("[wake_up_new_task] ERROR: failed to write clone3 info to stack_map");
        }
        */
        res = bpf_map_delete_elem(&clone3_edgecase, &(data->tid));
        if (res < 0) {
            bpf_printk("[wake_up_new_task] ERROR: failed to remove clone3 info from clone3_edgecase");
        }

        /* TODO: testing sp == vma.start edge-case detection
        return 0;
        */
    }

    /* Get stack VMA using the new task's pt_regs->sp. In kernels >= 4.9 
     * the new task's pt_regs is saved to the regs field in a fork_frame
     * struct. This fork_frame is saved to the new task's thread.sp field. In 
     * kernels < 4.9 pt_regs is saved directly to thread.sp. */

    bpf_printk("[wake_up_new_task] pid %d", stack.pid);

    BPF_READ(fork_frame, new_task->thread.sp);
    BPF_READ(data->sp, fork_frame->regs.sp);
    find_vma_range(mm, data->sp, &stack.start, &stack.end);
    if (stack.start && stack.end) {
        if (data->sp == stack.start) {
            bpf_printk("\t*** sp initialized to beginning of VMA! in practice it will reside in the *previous* VMA to the one we've found. Adjusting... ***");
            // current gross hack: decrement observed fork_frame sp by 8, find _that_ vma,
            // and use that for the tracked stack. Would be nicer to use vma->vm_prev,
            // but we need to write a helper to get us the whole vma object to do that.
            ulong prev_vma_start, prev_vma_end;
            find_vma_range(mm, (data->sp - 8), &stack.start, &stack.end);
        }

        // NOTE: apparently we track the new task's stack based on sp, regardless
        // of anything else? This at least is incorrect in some clone3-based cases
        // observed using CLONE_VM and CLONE_VFORK
        bpf_printk("\tfrom fork_frame sp: %lx, vma: [%lx, %lx)", data->sp, stack.start, stack.end);

        // Update stack map with new thread stack info
        data->stack_start = stack.start;
        data->stack_end = stack.end;
        data->stack_pid = stack.pid;

        bpf_map_update_elem(&stack_map, &data->new_pid, &stack, BPF_NOEXIST);
    }
    else {
        // TODO: report some kind of error? we should be able to find the VMA
        bpf_printk("[wake_up_new_task] ERROR: no stack VMA found");
    }

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

    BPF_READ(uctx, ctx->di);
    BPF_READ(user_sp, uctx->sp);
    data.sp = user_sp;

    t = init_probe_data(&data);

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

    return 0;
}

SEC("kretprobe/__x64_sys_execve")
int kretprobe_execve(struct pt_regs *ctx)
{
    struct slim_data_t data = { 0 };
    struct task_struct *t;

    t = init_probe_data(&data);

    if (t->flags & PF_KTHREAD)
        return 0;

    // PT_REGS_RC_CORE macro not found. Just use rax, since we're only x86_64
    BPF_READ(data.retval, ctx->ax);

    bpf_printk("[execve return] %d:%d -> %d", data.pid, data.tid, data.retval);

    // invalidate this current task's tracked stack region; after the execve we'll
    // have an entirely different one, and will need to rediscover it. If we don't
    // clean up the tracked stack region here, we'll fail subsequent stack pivot checks
    // for this task.
    // However, only do so if execve succeeds. If it fails, this task's virtual memory
    // is not changed.
    if (data.retval == 0) {
        bpf_map_delete_elem(&stack_map, &data.tid);
    }

    return 0;
}

SEC("kprobe/__x64_sys_mmap")
int kprobe_mmap(struct pt_regs *ctx)
{
    struct pt_regs *uctx;
    unsigned long user_sp;
    unsigned long prot;

    struct slim_data_t data = {0};
    struct task_struct *t;
    int stack_pivot_res;

    BPF_READ(uctx, ctx->di);
    BPF_READ(user_sp, uctx->sp);
    data.sp = user_sp;

    // heuristic: only worry about executable pages (rdx)
    // (cuts down on events)
    BPF_READ(prot, uctx->dx);
    if (prot & PROT_EXEC == 0) {
        return 0;
    }

    t = init_probe_data(&data);

    bpf_printk("[mmap] %d:%d", data.pid, data.tid);

    stack_pivot_res = check_stack_pivot(&data, t);
    if (stack_pivot_res != ERR_LOOKS_OK) {
        bpf_printk("[mmap] not-ok stack pivot check: %x", stack_pivot_res);
        if (stack_pivot_res == ERR_STACK_PIVOT) {
            bpf_printk("\t***** stack pivot! sp:%lx *****", data.sp);
        }
    }
    data.err = stack_pivot_res;

    bpf_ringbuf_output(&BPF_MAP_NAME(stack_pivot_event), &data, sizeof(data), 0);

    return 0;
}

SEC("kprobe/__x64_sys_mprotect")
int kprobe_mprotect(struct pt_regs *ctx)
{
    struct pt_regs *uctx;
    unsigned long user_sp;
    unsigned long prot;

    struct slim_data_t data = {0};
    struct task_struct *t;
    int stack_pivot_res;

    BPF_READ(uctx, ctx->di);
    BPF_READ(user_sp, uctx->sp);
    data.sp = user_sp;

    // heuristic: only worry about executable pages (rdx)
    // (cuts down on events)
    BPF_READ(prot, uctx->dx);
    if (prot & PROT_EXEC == 0) {
        return 0;
    }

    t = init_probe_data(&data);

    bpf_printk("[mprotect] %d:%d", data.pid, data.tid);

    stack_pivot_res = check_stack_pivot(&data, t);
    if (stack_pivot_res != ERR_LOOKS_OK) {
        bpf_printk("[mprotect] not-ok stack pivot check: %x", stack_pivot_res);
        if (stack_pivot_res == ERR_STACK_PIVOT) {
            bpf_printk("\t***** stack pivot! sp:%lx *****", data.sp);
        }
    }
    data.err = stack_pivot_res;

    bpf_ringbuf_output(&BPF_MAP_NAME(stack_pivot_event), &data, sizeof(data), 0);

    return 0;
}

// for debug/testing only, too hot to hook in production
/*
SEC("kprobe/__x64_sys_write")
int handle_write(struct pt_regs *ctx)
{
    struct pt_regs *uctx;
    unsigned long user_sp;
    struct slim_data_t data = {0};
    struct task_struct *t;
    int stack_pivot_res;

    BPF_READ(uctx, ctx->di);
    BPF_READ(user_sp, uctx->sp);
    data.sp = user_sp;

    t = init_probe_data(&data);

    bpf_printk("[write] %d:%d", data.pid, data.tid);

    stack_pivot_res = check_stack_pivot(&data, t);
    if (stack_pivot_res != ERR_LOOKS_OK) {
        bpf_printk("[write] not-ok stack pivot check: %x", stack_pivot_res);
        if (stack_pivot_res == ERR_STACK_PIVOT) {
            bpf_printk("\t***** stack pivot! sp:%lx *****", data.sp);
        }
    }
    data.err = stack_pivot_res;

    bpf_ringbuf_output(&BPF_MAP_NAME(stack_pivot_event), &data, sizeof(data), 0);

    return 0;
}
//*/

// TODO: fix this, use a proper syscall handling function
SEC("kprobe/ksys_mmap_pgoff")
int handle_mmap(struct pt_regs *ctx)
{
    return 0;
}
