#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} stack_pivot_events SEC(".maps");

struct stack_pivot_data_t {
    pid_t tid;
    unsigned long newsp;
};

// force exporing the type to rust skeleton
struct stack_pivot_data_t __unused = {0};

SEC("kprobe/cgroup_post_fork")
int kprobe_cgroup_post_fork(struct pt_regs *ctx)
{
    struct stack_pivot_data_t data = { 0 };
    struct task_struct *child = (struct task_struct *)ctx->di;
    struct kernel_clone_args *kargs = (struct kernel_clone_args *)ctx->si;
    // Grab new thread ID from child task and newsp from kernel clone args
    bpf_core_read(&data.tid, sizeof(data.tid), &child->pid);
    bpf_core_read(&data.newsp, sizeof(data.newsp), &kargs->stack);
    bpf_ringbuf_output(&stack_pivot_events, &data, sizeof(data), 0);
}
