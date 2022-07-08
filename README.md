PoC of detecting stack pivots using eBPF

# Stack Pivots

situation: you have a stack-based buffer overflow and can overwrite the
saved RIP to get code execution. You have a ROP chain payload, but it
is too large to deliver with the overflow that you have, or otherwise fit
on the stack. Enter the stack pivot!

using a 'leave; ret;' gadget (or other gadgets) we take control of the RSP
register, thus pointing the stack somewhere we control for the next gadgets to
be popped from. Now we are free to place our full ROP chain elsewhere (such as
the heap) and pivot to it. This is very useful.

## Detecting Stack Pivots

This should be easy enough: instrument likely syscalls a ROP chain would use,
and check if the stack pointer is outside the stack region for the process.
This requires tracking each thread's stack region, which is unfortunately tricky.

# Stacks & Thread Stacks

A single-threaded process on Linux has a somewhat well-defined stack, tracked
both in the memory mappings of the current task's task_struct (mm field points to
VMAs which can have VM_STACK flag set in their vm_flags field), and in the
process's mm_struct start_stack field (initial stack for main thread).

Unfortunately this is imprecise on its own, and definitely inaccurate for
multithreaded programs. Each thread in a process must have its own stack,
but the entries in the kernel tracking this are inaccurate for locating
the actual stack in use by a thread.

## Tracking Thread Stacks

Fortunately Anthony Blanton did research on properly tracking thread stacks
using eBPF programs. Ultimately, the `clone` syscall observes the new thread's
stack via the `newsp` parameter, used during thread creation. However we won't
know the new thread's tid until `clone` is returning. Likewise a retprove would
have the new tid, but no longer have the newsp parameter.

One solution (try this later) would be to store the newsp in a map for the retprobe
to retrieve. The currently implemented solutions here though use the approaches
outlined by Anthony, using `wake_up_new_task` and `cgroup_post_fork` as points
to observe both the new stack pointer, and the new thread's tid.

# Building

First you'll need the correct vmlinux.h file for your running kernel. I
generated mine with `bpftool btf dump file /sys/kernel/btf/vmlinux format c`,
using a bpftool for my kernel version. On ubuntu I installed bpftool using 
`apt install linux-tools-`uname -r``.

# Running

TODO

# Testing

Tests are under 'test' and are currently manual. Running programs normally installed
and under normal use should _never_ result in a "stack pivot" alert. However the programs
under 'test' should stack pivot at some point, cause and alert, and if enabled, be killed
immediately by a SIGKILL from within eBPF.

Build tests with `make`, run the main rust program (found under `target`), and then run
the test programs under `test`, observing events as they're handled by the main rust program.
You should see stack pivots are detected in the test programs, and (if enabled) they are killed.

# TODO

* Pull Anthony's research code in
* Adapt Anthony's code to our PoC use-case, refactor, etc.
** get working as-is
** move stack pivot detection logic fully into eBPF
** refactor data structures, event types as necessary (less userland events)
** double-check that we pull in updates from Anthony's code
* write test programs that exhibit stack pivot behavior and call various syscalls/simulated ROP chains
* make eBPF programs for syscalls an exploit is likely to use, check user sp against known stack regions
** failing check gets kill signal sent immediately

# GOTCHAS

...?

# References

https://ir0nstone.gitbook.io/notes/types/stack/stack-pivoting
https://wikis.rim.net/display/VR/Linux+threading+and+the+stack

Anthony's research on tracking thread stacks to detect a stack pivot (libbpf-core directory):
https://gitlab.rim.net/bart/bpftest
