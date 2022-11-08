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

// maps
BPF_MAP_DEF(stack_pivot_event)

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
EXPORT_TYPE(stack_pivot_event);

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
 * TODO: improve golang exception by researching golang runtime
 */
static int check_stack_pivot(struct stack_pivot_event *event, struct task_struct *t)
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
    user_sp = event->sp;

    // TODO: verify correctness against golang runtime/extensive testing
    if (0xc000000000 <= user_sp && user_sp <= 0xc000ffffff) {
        event->stack_start = 0xc000000000;
        event->stack_end = 0xc000ffffff;
        return ERR_POSSIBLE_GOLANG_STACK;
    }
    else if (0xc420000000 <= user_sp && user_sp <= 0xc420ffffff) {
        event->stack_start = 0xc420000000;
        event->stack_end = 0xc420ffffff;
        return ERR_POSSIBLE_GOLANG_STACK;
    }

    // look up vmas for mm->start_stack and observed sp
    res = find_vma_range(mm, start_stack, &found_stack_start, &found_stack_end);
    if (res == FIND_VMA_FAILURE) {
        // start_stack in task_struct not backed by a vma? Is this just a segfault?
        bpf_printk("[check_stack_pivot] %d:%d mm->start_stack has no VMA?", tgid, pid);
        event->stack_start = 0;
        event->stack_end = 0;
        return ERR_NO_VMA;
    }

    // for debugging
    unsigned long sp_vma_start, sp_vma_end;
    res = find_vma_range(mm, user_sp, &sp_vma_start, &sp_vma_end);
    if (res == FIND_VMA_FAILURE) {
        bpf_printk("[check_stack_pivot] %d:%d sp has no VMA?", tgid, pid);
        event->stack_start = 0;
        event->stack_end = 0;
        return ERR_NO_VMA;
    }

    // debugging info
    bpf_printk("[check_stack_pivot] %d:%d", tgid, pid);
    bpf_printk("[check_stack_pivot] mm->start_stack vma [%lx, %lx)", found_stack_start, found_stack_end);
    bpf_printk("[check_stack_pivot] \tvma size: %lx", found_stack_end - found_stack_start);
    // for debugging
    bpf_printk("[check_stack_pivot] user_sp vma [%lx, %lx)", sp_vma_start, sp_vma_end);
    bpf_printk("[check_stack_pivot] \tvma size: %lx", sp_vma_end - sp_vma_start);

    // we'll need to refer to our tracked stacks regardless of thread group leader status
    stack = (struct stack_data *)bpf_map_lookup_elem(&stack_map, &pid);

    // thread group leader case. check mm->start_stack
    // OR edge case of sp in [sp, end_addr) vma from wake_up_new_task (sp is start)
    if (pid == tgid) {

        // check if sp is in this found start_stack vma (thread group leader)
        if (stack) {
            // edge case where sp is initially at start of a VMA.  we add a
            // tracked region in wake_up_new_task because the VMA we get from
            // mm->start_stack will in practice be wrong, so we have to
            // manually adjust.
            // 
            // Also, loosen the check here to handle rare cases where we track
            // a region (mistakenly) but sp resides in mm->start_stack's vma.
            bpf_printk("[check_stack_pivot] tracked thread stack [%lx, %lx)", stack->start, stack->end);
            if (stack->start <= user_sp && user_sp < stack->end) {
                // OK case
                event->stack_start = stack->start;
                event->stack_end = stack->end;
                return ERR_LOOKS_OK;
            }
            else if (found_stack_start <= user_sp && user_sp < found_stack_end) {
                event->stack_start = found_stack_start;
                event->stack_end = found_stack_end;
                return ERR_LOOKS_OK;
            }
        }
        else if (found_stack_start <= user_sp && user_sp < found_stack_end) {
            // stack pointer in stack VMA, everything looks good here
            event->stack_start = found_stack_start;
            event->stack_end = found_stack_end;
            return ERR_LOOKS_OK;
        }
        else {
            // bad
            bpf_printk("[check_stack_pivot]\t*** stack pivot detected! ***");
            event->stack_start = found_stack_start;
            event->stack_end = found_stack_end;
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
                // good
                event->stack_start = found_stack_start;
                event->stack_end = found_stack_end;
                return ERR_LOOKS_OK;
            }
            // golang exception case already handled above
            else {
                // bad
                bpf_printk("[check_stack_pivot]\t*** stack pivot detected! ***");
                event->stack_start = found_stack_start;
                event->stack_end = found_stack_end;
                return ERR_STACK_PIVOT;
            }
        }
        else {
            // not tracked, ancient thread
            bpf_printk("[check_stack_pivot] %d:%d ancient non-main thread, untracked. sp:%lx", tgid, pid, user_sp);
            event->stack_start = 0;
            event->stack_end = 0;
            return ERR_ANCIENT_THREAD;
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
    struct stack_pivot_event sp_event = { 0 };
    struct task_struct *t;
    struct pt_regs *uctx;
    int stack_pivot_res;

    t = init_stack_pivot_event(&sp_event);

    if (t->flags & PF_KTHREAD)
        return 0;

    uctx = (struct pt_regs *)ctx->di;
    BPF_READ(sp_event.sp, uctx->sp);


    /* DEBUGGING BEGIN */
    struct mm_struct *mm;
    int res;
    ulong vma_start, vma_end;
    ulong clone_flags, newsp;

    BPF_READ(mm, t->mm);

    // sys_clone user args
    BPF_READ(clone_flags, uctx->di);
    BPF_READ(newsp, uctx->si);

    int has_clone_vm = (clone_flags & CLONE_VM) ? 1 : 0;
    int has_clone_thread = (clone_flags & CLONE_THREAD) ? 1 : 0;
    bpf_printk("[clone] %d:%d", sp_event.pid, sp_event.tid);
    bpf_printk("[clone]\tclone_vm: %d, clone_thread: %d", has_clone_vm, has_clone_thread);
    bpf_printk("[clone]\tnewsp: %lx", newsp);

    res = find_vma_range(mm, newsp, &vma_start, &vma_end);
    if (res == FIND_VMA_SUCCESS) {
        bpf_printk("[clone]\tnewsp vma: [%lx, %lx)", vma_start, vma_end);
    }
    /* DEBUGGING END */


    // stack pivot check
    stack_pivot_res = check_stack_pivot(&sp_event, t);
    if (stack_pivot_res != ERR_LOOKS_OK) {
        bpf_printk("[clone]\tnot-ok stack pivot check: %x", stack_pivot_res);
        if (stack_pivot_res == ERR_STACK_PIVOT) {
            bpf_printk("\t***** stack pivot! sp:%lx *****", sp_event.sp);
        }
    }
    sp_event.kind = stack_pivot_res;

    bpf_ringbuf_output(&BPF_MAP_NAME(stack_pivot_event), &sp_event, sizeof(sp_event), 0);

    return 0;
}

// TODO: clean this up to just be stack pivot checking/debug output, like clone
SEC("kprobe/__x64_sys_clone3")
int kprobe_clone3(struct pt_regs *ctx)
{
    struct stack_pivot_event sp_event = { 0 };
    struct task_struct *t;
    struct pt_regs *uctx;
    int stack_pivot_res;

    t = init_stack_pivot_event(&sp_event);

    if (t->flags & PF_KTHREAD)
        return 0;

    BPF_READ(uctx, ctx->di);

    /* DEBUGGING BEGIN */
    struct clone_args *uargs;
    struct clone_args local_uargs = { 0 };
    struct mm_struct *mm;
    struct stack_data stack = { 0 };
    size_t size;
    ulong clone_flags, newsp, stack_size;

    BPF_READ(mm, t->mm);

    // get the flags/stack from uargs struct
    // CLONE_VM flag implies we must have stack provided in uargs

    // load args
    BPF_READ(uargs, uctx->di);
    BPF_READ(size, uctx->si);
    bpf_probe_read(&local_uargs, sizeof(local_uargs), uargs);

    clone_flags = local_uargs.flags;
    newsp = local_uargs.stack;
    stack_size = local_uargs.stack_size;

    find_vma_range(mm, newsp, &stack.start, &stack.end);

    int has_clone_vm = (clone_flags & CLONE_VM) ? 1 : 0;
    int has_clone_vfork = (clone_flags & CLONE_VFORK) ? 1 : 0;
    int has_clone_thread = (clone_flags & CLONE_THREAD) ? 1 : 0;

    bpf_printk("[clone3] %d:%d, clone_vm: %d", sp_event.pid, sp_event.tid, has_clone_vm);
    bpf_printk("\tuargs: %lx, size: %d", uargs, size);
    bpf_printk("\tflags: %lx, newsp suggested region: [%lx, %lx)", clone_flags, newsp, newsp + stack_size);
    bpf_printk("\tnewsp vma: [%lx, %lx)", stack.start, stack.end);
    if (newsp != stack.start || (newsp + stack_size != stack.end)) {
        bpf_printk("\t*** user-defined stack is not identical to VMA it resides in ***");
    }
    /* DEBUGGING END */


    // stack pivot check
    BPF_READ(sp_event.sp, uctx->sp);
    stack_pivot_res = check_stack_pivot(&sp_event, t);
    if (stack_pivot_res != ERR_LOOKS_OK) {
        bpf_printk("[clone3]\tnot-ok stack pivot check: %x", stack_pivot_res);
        if (stack_pivot_res == ERR_STACK_PIVOT) {
            bpf_printk("\t***** stack pivot! sp:%lx *****", sp_event.sp);
        }
    }
    sp_event.kind = stack_pivot_res;

    bpf_ringbuf_output(&BPF_MAP_NAME(stack_pivot_event), &sp_event, sizeof(sp_event), 0);

    return 0;
}

// if we need to kprobe like this, we'll have to make sure we catch
// all possible entrypoints so we aren't evaded
// TODO: verify we can reach this (int 0x80?)
SEC("kprobe/__ia32_sys_clone")
int kprobe_clone_ia32(struct pt_regs *ctx)
{
    bpf_printk("[clone ia32] ****** __ia32_sys_clone hit! add instrumentation to this one too ******");

    return 0;
}

/* DEBUGGING BEGIN */
// TODO: basically just for debugging, could disable/remove
SEC("kretprobe/__x64_sys_clone")
int kretprobe_clone(struct pt_regs *ctx)
{
    struct stack_pivot_event sp_event = { 0 };
    struct task_struct *t;
    int retval;

    t = init_stack_pivot_event(&sp_event);

    if (t->flags & PF_KTHREAD)
        return 0;

    // PT_REGS_RC_CORE macro not found. Just use rax, since we're only x86_64
    BPF_READ(retval, ctx->ax);

    bpf_printk("[clone return] %d:%d -> %d", sp_event.pid, sp_event.tid, retval);

    return 0;
}

// TODO: basically just for debugging, could disable/remove
SEC("kretprobe/__x64_sys_clone3")
int kretprobe_clone3(struct pt_regs *ctx)
{
    struct stack_pivot_event sp_event = { 0 };
    struct task_struct *t;
    int retval;

    t = init_stack_pivot_event(&sp_event);

    if (t->flags & PF_KTHREAD)
        return 0;

    // PT_REGS_RC_CORE macro not found. Just use rax, since we're only x86_64
    BPF_READ(retval, ctx->ax);

    bpf_printk("[clone3 return] %d:%d -> %d", sp_event.pid, sp_event.tid, retval);

    return 0;
}
/* DEBUGGING END */

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
    struct task_struct *new_task;
    struct mm_struct *mm;
    struct fork_frame *fork_frame;
    struct stack_data stack = { 0 };
    uint flags;
    int new_pid;
    ulong sp;

    // Get new task thread ID
    new_task = (struct task_struct *)ctx->di;
    BPF_READ(flags, new_task->flags);

    if (flags & PF_KTHREAD)
        return 0;

    BPF_READ(new_pid, new_task->pid);
    BPF_READ(mm, new_task->mm);

    stack.pid = new_pid;

    /* Get stack VMA using the new task's pt_regs->sp. In kernels >= 4.9 
     * the new task's pt_regs is saved to the regs field in a fork_frame
     * struct. This fork_frame is saved to the new task's thread.sp field. In 
     * kernels < 4.9 pt_regs is saved directly to thread.sp. */

    /* DEBUGGING BEGIN */
    bpf_printk("[wake_up_new_task] pid %d", stack.pid);
    /* DEBUGGING END */

    BPF_READ(fork_frame, new_task->thread.sp);
    BPF_READ(sp, fork_frame->regs.sp);

    find_vma_range(mm, sp, &stack.start, &stack.end);
    if (stack.start && stack.end) {
        if (sp == stack.start) {
            /* DEBUGGING BEGIN */
            bpf_printk("\t*** sp initialized to beginning of VMA! in practice it will reside in the *previous* VMA to the one we've found. Adjusting... ***");
            /* DEBUGGING END */

            // current gross hack: decrement observed fork_frame sp by 8, find _that_ vma,
            // and use that for the tracked stack. Would be nicer to use vma->vm_prev,
            // but we need to write a helper to get us the whole vma object to do that.
            find_vma_range(mm, (sp - 8), &stack.start, &stack.end);
        }

        /* DEBUGGING BEGIN */
        bpf_printk("\tfrom fork_frame sp: %lx, vma: [%lx, %lx)", sp, stack.start, stack.end);
        /* DEBUGGING END */

        // Update stack map with new thread stack info
        bpf_map_update_elem(&stack_map, &new_pid, &stack, BPF_NOEXIST);
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
    struct stack_pivot_event sp_event;
    struct pt_regs *uctx;
    struct task_struct *t;
    long exit_code;

    t = init_stack_pivot_event(&sp_event);

    if (t->flags & PF_KTHREAD)
        return 0;

    // Delete entry for exiting thread
    bpf_map_delete_elem(&stack_map, &sp_event.tid);

    /* DEBUGGING BEGIN */
    // do_exit args
    uctx = (struct pt_regs *)ctx->di;
    BPF_READ(exit_code, uctx->di);

    bpf_printk("[do_exit] %d:%d -> %d", sp_event.pid, sp_event.tid, exit_code);
    /* DEBUGGING END */

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
    struct task_struct *t;
    struct stack_pivot_event sp_event = { 0 };
    int stack_pivot_res;

    t = init_stack_pivot_event(&sp_event);

    BPF_READ(uctx, ctx->di);
    BPF_READ(sp_event.sp, uctx->sp);

    /* DEBUGGING BEGIN */
    bpf_printk("[execve] %d:%d", sp_event.pid, sp_event.tid);
    /* DEBUGGING END */

    stack_pivot_res = check_stack_pivot(&sp_event, t);
    if (stack_pivot_res != ERR_LOOKS_OK) {
        bpf_printk("[execve] not-ok stack pivot check: %x", stack_pivot_res);
        if (stack_pivot_res == ERR_STACK_PIVOT) {
            bpf_printk("\t***** stack pivot! sp:%lx *****", sp_event.sp);
        }
    }
    sp_event.kind = stack_pivot_res;

    bpf_ringbuf_output(&BPF_MAP_NAME(stack_pivot_event), &sp_event, sizeof(sp_event), 0);

    return 0;
}

SEC("kretprobe/__x64_sys_execve")
int kretprobe_execve(struct pt_regs *ctx)
{
    struct stack_pivot_event sp_event;
    struct task_struct *t;
    int retval;

    t = init_stack_pivot_event(&sp_event);

    if (t->flags & PF_KTHREAD)
        return 0;

    // PT_REGS_RC_CORE macro not found. Just use rax, since we're only x86_64
    BPF_READ(retval, ctx->ax);

    /* DEBUGGING BEGIN */
    bpf_printk("[execve return] %d:%d -> %d", sp_event.pid, sp_event.tid, retval);
    /* DEBUGGING END */

    // invalidate this current task's tracked stack region; after the execve we'll
    // have an entirely different one, and will need to rediscover it. If we don't
    // clean up the tracked stack region here, we'll fail subsequent stack pivot checks
    // for this task.
    // However, only do so if execve succeeds. If it fails, this task's virtual memory
    // is not changed.
    if (retval == 0) {
        bpf_map_delete_elem(&stack_map, &sp_event.tid);
    }

    return 0;
}

SEC("kprobe/__x64_sys_execveat")
int kprobe_execveat(struct pt_regs *ctx)
{
    struct pt_regs *uctx;
    struct task_struct *t;
    struct stack_pivot_event sp_event = { 0 };
    int stack_pivot_res;

    t = init_stack_pivot_event(&sp_event);

    BPF_READ(uctx, ctx->di);
    BPF_READ(sp_event.sp, uctx->sp);

    /* DEBUGGING BEGIN */
    bpf_printk("[execveat] %d:%d", sp_event.pid, sp_event.tid);
    /* DEBUGGING END */

    stack_pivot_res = check_stack_pivot(&sp_event, t);
    if (stack_pivot_res != ERR_LOOKS_OK) {
        bpf_printk("[execveat] not-ok stack pivot check: %x", stack_pivot_res);
        if (stack_pivot_res == ERR_STACK_PIVOT) {
            bpf_printk("\t***** stack pivot! sp:%lx *****", sp_event.sp);
        }
    }
    sp_event.kind = stack_pivot_res;

    bpf_ringbuf_output(&BPF_MAP_NAME(stack_pivot_event), &sp_event, sizeof(sp_event), 0);

    return 0;
}

SEC("kprobe/__x64_sys_fork")
int kprobe_fork(struct pt_regs *ctx)
{
    struct pt_regs *uctx;
    struct task_struct *t;
    struct stack_pivot_event sp_event = { 0 };
    int stack_pivot_res;

    t = init_stack_pivot_event(&sp_event);

    BPF_READ(uctx, ctx->di);
    BPF_READ(sp_event.sp, uctx->sp);

    /* DEBUGGING BEGIN */
    bpf_printk("[fork] %d:%d", sp_event.pid, sp_event.tid);
    /* DEBUGGING END */

    stack_pivot_res = check_stack_pivot(&sp_event, t);
    if (stack_pivot_res != ERR_LOOKS_OK) {
        bpf_printk("[fork] not-ok stack pivot check: %x", stack_pivot_res);
        if (stack_pivot_res == ERR_STACK_PIVOT) {
            bpf_printk("\t***** stack pivot! sp:%lx *****", sp_event.sp);
        }
    }
    sp_event.kind = stack_pivot_res;

    bpf_ringbuf_output(&BPF_MAP_NAME(stack_pivot_event), &sp_event, sizeof(sp_event), 0);

    return 0;
}

SEC("kprobe/__x64_sys_vfork")
int kprobe_vfork(struct pt_regs *ctx)
{
    struct pt_regs *uctx;
    struct task_struct *t;
    struct stack_pivot_event sp_event = { 0 };
    int stack_pivot_res;

    t = init_stack_pivot_event(&sp_event);

    BPF_READ(uctx, ctx->di);
    BPF_READ(sp_event.sp, uctx->sp);

    /* DEBUGGING BEGIN */
    bpf_printk("[vfork] %d:%d", sp_event.pid, sp_event.tid);
    /* DEBUGGING END */

    stack_pivot_res = check_stack_pivot(&sp_event, t);
    if (stack_pivot_res != ERR_LOOKS_OK) {
        bpf_printk("[vfork] not-ok stack pivot check: %x", stack_pivot_res);
        if (stack_pivot_res == ERR_STACK_PIVOT) {
            bpf_printk("\t***** stack pivot! sp:%lx *****", sp_event.sp);
        }
    }
    sp_event.kind = stack_pivot_res;

    bpf_ringbuf_output(&BPF_MAP_NAME(stack_pivot_event), &sp_event, sizeof(sp_event), 0);

    return 0;
}

SEC("kretprobe/__x64_sys_execveat")
int kretprobe_execveat(struct pt_regs *ctx)
{
    struct stack_pivot_event sp_event;
    struct task_struct *t;
    int retval;

    t = init_stack_pivot_event(&sp_event);

    if (t->flags & PF_KTHREAD)
        return 0;

    // PT_REGS_RC_CORE macro not found. Just use rax, since we're only x86_64
    BPF_READ(retval, ctx->ax);

    /* DEBUGGING BEGIN */
    bpf_printk("[execveat return] %d:%d -> %d", sp_event.pid, sp_event.tid, retval);
    /* DEBUGGING END */

    // invalidate this current task's tracked stack region; after the execve we'll
    // have an entirely different one, and will need to rediscover it. If we don't
    // clean up the tracked stack region here, we'll fail subsequent stack pivot checks
    // for this task.
    // However, only do so if execve succeeds. If it fails, this task's virtual memory
    // is not changed.
    if (retval == 0) {
        bpf_map_delete_elem(&stack_map, &sp_event.tid);
    }

    return 0;
}

SEC("kprobe/__x64_sys_socket")
int kprobe_socket(struct pt_regs *ctx)
{
    struct pt_regs *uctx;
    struct task_struct *t;
    struct stack_pivot_event sp_event = { 0 };
    int stack_pivot_res;

    t = init_stack_pivot_event(&sp_event);

    BPF_READ(uctx, ctx->di);
    BPF_READ(sp_event.sp, uctx->sp);

    /* DEBUGGING BEGIN */
    bpf_printk("[socket] %d:%d", sp_event.pid, sp_event.tid);
    /* DEBUGGING END */

    stack_pivot_res = check_stack_pivot(&sp_event, t);
    if (stack_pivot_res != ERR_LOOKS_OK) {
        bpf_printk("[socket] not-ok stack pivot check: %x", stack_pivot_res);
        if (stack_pivot_res == ERR_STACK_PIVOT) {
            bpf_printk("\t***** stack pivot! sp:%lx *****", sp_event.sp);
        }
    }
    sp_event.kind = stack_pivot_res;

    bpf_ringbuf_output(&BPF_MAP_NAME(stack_pivot_event), &sp_event, sizeof(sp_event), 0);

    return 0;
}

SEC("kprobe/__x64_sys_dup2")
int kprobe_dup2(struct pt_regs *ctx)
{
    struct pt_regs *uctx;
    struct task_struct *t;
    struct stack_pivot_event sp_event = { 0 };
    int stack_pivot_res;

    t = init_stack_pivot_event(&sp_event);

    BPF_READ(uctx, ctx->di);
    BPF_READ(sp_event.sp, uctx->sp);

    /* DEBUGGING BEGIN */
    bpf_printk("[dup2] %d:%d", sp_event.pid, sp_event.tid);
    /* DEBUGGING END */

    stack_pivot_res = check_stack_pivot(&sp_event, t);
    if (stack_pivot_res != ERR_LOOKS_OK) {
        bpf_printk("[dup2] not-ok stack pivot check: %x", stack_pivot_res);
        if (stack_pivot_res == ERR_STACK_PIVOT) {
            bpf_printk("\t***** stack pivot! sp:%lx *****", sp_event.sp);
        }
    }
    sp_event.kind = stack_pivot_res;

    bpf_ringbuf_output(&BPF_MAP_NAME(stack_pivot_event), &sp_event, sizeof(sp_event), 0);

    return 0;
}

SEC("kprobe/__x64_sys_dup3")
int kprobe_dup3(struct pt_regs *ctx)
{
    struct pt_regs *uctx;
    struct task_struct *t;
    struct stack_pivot_event sp_event = { 0 };
    int stack_pivot_res;

    t = init_stack_pivot_event(&sp_event);

    BPF_READ(uctx, ctx->di);
    BPF_READ(sp_event.sp, uctx->sp);

    /* DEBUGGING BEGIN */
    bpf_printk("[dup3] %d:%d", sp_event.pid, sp_event.tid);
    /* DEBUGGING END */

    stack_pivot_res = check_stack_pivot(&sp_event, t);
    if (stack_pivot_res != ERR_LOOKS_OK) {
        bpf_printk("[dup3] not-ok stack pivot check: %x", stack_pivot_res);
        if (stack_pivot_res == ERR_STACK_PIVOT) {
            bpf_printk("\t***** stack pivot! sp:%lx *****", sp_event.sp);
        }
    }
    sp_event.kind = stack_pivot_res;

    bpf_ringbuf_output(&BPF_MAP_NAME(stack_pivot_event), &sp_event, sizeof(sp_event), 0);

    return 0;
}

SEC("kprobe/__x64_sys_mmap")
int kprobe_mmap(struct pt_regs *ctx)
{
    struct pt_regs *uctx;
    struct stack_pivot_event sp_event = { 0 };
    struct task_struct *t;
    int stack_pivot_res;
    unsigned long prot;


    BPF_READ(uctx, ctx->di);
    BPF_READ(sp_event.sp, uctx->sp);

    // heuristic: only worry about executable pages (rdx)
    // (cuts down on events)
    BPF_READ(prot, uctx->dx);
    if (prot & PROT_EXEC == 0) {
        return 0;
    }

    t = init_stack_pivot_event(&sp_event);

    /* DEBUGGING BEGIN */
    bpf_printk("[mmap] %d:%d", sp_event.pid, sp_event.tid);
    /* DEBUGGING END */

    stack_pivot_res = check_stack_pivot(&sp_event, t);
    if (stack_pivot_res != ERR_LOOKS_OK) {
        bpf_printk("[mmap] not-ok stack pivot check: %x", stack_pivot_res);
        if (stack_pivot_res == ERR_STACK_PIVOT) {
            bpf_printk("\t***** stack pivot! sp:%lx *****", sp_event.sp);
        }
    }
    sp_event.kind = stack_pivot_res;

    bpf_ringbuf_output(&BPF_MAP_NAME(stack_pivot_event), &sp_event, sizeof(sp_event), 0);

    return 0;
}

SEC("kprobe/__x64_sys_mprotect")
int kprobe_mprotect(struct pt_regs *ctx)
{
    struct pt_regs *uctx;
    struct stack_pivot_event sp_event = { 0 };
    struct task_struct *t;
    int stack_pivot_res;
    unsigned long prot;


    BPF_READ(uctx, ctx->di);
    BPF_READ(sp_event.sp, uctx->sp);

    // heuristic: only worry about executable pages (rdx)
    // (cuts down on events)
    BPF_READ(prot, uctx->dx);
    if (prot & PROT_EXEC == 0) {
        return 0;
    }

    t = init_stack_pivot_event(&sp_event);

    /* DEBUGGING BEGIN */
    bpf_printk("[mprotect] %d:%d", sp_event.pid, sp_event.tid);
    /* DEBUGGING END */

    stack_pivot_res = check_stack_pivot(&sp_event, t);
    if (stack_pivot_res != ERR_LOOKS_OK) {
        bpf_printk("[mprotect] not-ok stack pivot check: %x", stack_pivot_res);
        if (stack_pivot_res == ERR_STACK_PIVOT) {
            bpf_printk("\t***** stack pivot! sp:%lx *****", sp_event.sp);
        }
    }
    sp_event.kind = stack_pivot_res;

    bpf_ringbuf_output(&BPF_MAP_NAME(stack_pivot_event), &sp_event, sizeof(sp_event), 0);

    return 0;
}
