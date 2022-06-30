#include "vmlinux.h"

#define BUF_SIZE 128

#define ERR_LEVEL_WARNING 1
#define ERR_LEVEL_ALERT 2

#define ERR_TYPE_NONE 0
#define ERR_TYPE_UNK_STACK ((ERR_LEVEL_WARNING << 12) | 1)
#define ERR_TYPE_STACK_PIVOT ((ERR_LEVEL_ALERT << 12) | 1)

#define MAX_RB_NODE_BOUNDS 51

#define STACK_SRC_SELF 0
#define STACK_SRC_UNK -1
#define STACK_SRC_ERR -2

// generic data
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

// combines separate tgid, pid into combined tgid_pid like from bpf_get_current_pid_tgid helper
#define MAKE_COMBINED_TGID_PID(dest, tgid, pid) \
    dest = tgid << 32 | pid

// macros for slightly nicer CO-RE use
#define BPF_READ(dest, source) \
    bpf_core_read(&dest, sizeof(dest), &source)
#define BPF_READ_STR(dest, source) \
    bpf_core_read_str(&dest, sizeof(dest), &source)

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
static void find_vma(struct mm_struct *mm, ulong addr, ulong *start,
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
                return;
            }
            BPF_READ(rb_node, rb_node->rb_left);
        } 
        else {
            BPF_READ(rb_node, rb_node->rb_right);
        }
    }
    return;
}

