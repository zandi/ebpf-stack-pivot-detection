PoC of detecting stack pivots using eBPF

# Stack Pivots

Situation: you have a stack-based buffer overflow and can overwrite the
saved RIP to get code execution. You have a ROP chain payload, but it
is too large to deliver with the overflow that you have, or otherwise fit
on the stack. Enter the stack pivot!

Using a `leave; ret;` gadget (or other gadgets) we take control of the RSP
register, thus pivoting the stack somewhere we control for the next gadgets to
be popped from. Now we can split our ROP chain into stages. The full ROP chain
is placed wherever it will fit (such as the heap) and is our 2nd stage. The 1st
stage ROP chain simply pivots to it, and can be very small. This is very
useful.

## Detecting Stack Pivots

This should be easy enough: instrument likely syscalls a ROP chain would use,
and check if the stack pointer is outside the stack region for the process.
This requires tracking each thread's stack region, which is unfortunately tricky.

# Stacks & Thread Stacks

A single-threaded process on Linux has a more well-defined stack, tracked both
in the memory mappings of the current task's `task_struct` (`mm` field points
to VMAs which can have `VM_STACK` flag set in their `vm_flags` field), and in
the process's `mm_struct` `start_stack` field (initial stack for main thread).

Unfortunately this is definitely inaccurate for multithreaded programs. Each
thread in a process must have its own stack since the memory space is shared
with other threads, but the previously mentioned 'stack' entries in the kernel
are inaccurate for locating the actual stack in use by a thread.

This can be observed by running a multithreaded program and observing its
`/proc/$pid/maps` list of memory regions, only one of which is marked as the
stack.

## Tracking Thread Stacks

Fortunately Anthony Blanton did research on properly tracking thread stacks
using eBPF programs
(https://gitlab.rim.net/bart/bpftest/-/blob/85df2d83b95e96cfa26c5635c1d3c29684202b25/libbpf-core/prog.c).
Ultimately, the `clone` syscall observes the new thread's stack via the `newsp`
parameter, used during thread creation. However we won't know the new thread's
tid until `clone` is returning. Likewise a retprobe would have the new tid, but
no longer have the newsp parameter.

One solution (try this later) would be to store the newsp in a map for the
retprobe to retrieve. The currently implemented solution uses the approach
outlined by Anthony, using `wake_up_new_task` as a point to observe both the
new stack pointer, and the new thread's tid.

This is focused on the view of threads from the kernel, so while testing of
libraries beyond pthread should happen, if a thread library relies on the
`clone` system call to implement its threads at the OS level (thus letting the
kernel handle scheduling, signals, etc.) then this approach should still be
useful.

# Building

## Dependencies

You'll need (at least) the following packages to build, based on Ubuntu 20.04/22.04 LTS.
Some may already be installed, or have to be explicitly installed.

```
build-essential
pkg-config
libelf-dev
zlib1g-dev
clang
cargo
rustfmt
linux-tools-`uname -r`
```

## Build Process

First you'll need the correct vmlinux.h file for your running kernel. I
generated mine with `bpftool btf dump file /sys/kernel/btf/vmlinux format c`,
using a bpftool for my kernel version. On ubuntu I installed bpftool using 
`apt install linux-tools-`uname -r``.

You can then build with `cargo build`. The `build.rs` file will include
the bpf program building automatically. You will also need to install the
`rustfmt` utility for the libbpf-rs crate to build the rust skeleton for
the eBPF object.

# Running

Binaries will be under `target/`, then under either `debug` or `release`
depending on the build. The build produces a `stack_pivot_poc` binary which
must be run as root (or presumably with `CAP_SYS_BPF`).

Once running the eBPF programs will start tracking thread stacks and checking
for stack pivots, reporting events to userland for display by the userland
agent.

# Testing

Tests are under 'test' and are currently manual. Running programs normally
installed and under normal use should _never_ result in a "stack pivot" alert.
However certain programs under 'test' should stack pivot at some point, cause
an alert, and if enabled, be killed immediately by a SIGKILL from within eBPF.

Build tests with `make`, and run them before the main userland agent (under
`target`) or after, to test different start orders of our agent & of protected
workloads. We should detect/kill actual stack pivots whenever possible, and
_never_ kill legitimate processes.

## Building/Running Tests

Some of the test programs require extra toolchains to be installed.

### C#

Follow the instructions from the official Mono website https://www.mono-project.com/download/stable/#download-lin

The Makefile handles building with the `mcs` utility, run with `mono program.exe`.

### Erlang

Install Erlang with `apt install erlang`. An Erlang program can be
built from the Erlang shell, started with `erl`. A module can be built/loaded
with `c(module_name).`, then an exported function called with `module_name:function().`.

Exit the Erlang shell with `init:stop().`.

### Golang

Given `program.go`, run with `go run program.go`.

# TODO

* Refactor & simplify code
** refactor data structures, event types as necessary (less userland events)
** double-check that we pull in updates from Anthony's code
* make eBPF programs for syscalls an exploit is likely to use, check user sp against known stack regions
** failing check gets kill signal sent immediately
* Revisit `check_stack_pivot` logic, simplify function
* test against go binaries
* test program which takes input string describing clones/forks/execves to do (randomly by default) for better stress testing of dealing with process/thread creation.
* heavier testing against expected workload binaries (nginx, nodejs/go/java apps)

# Caveats

A Stack Pivot is not necessary for all ROP chains, so this is a detection only
for a certain ROP-based exploitation technique, not ROP-based exploits in
general.  This can make a ROP-based exploit harder (or in certain situations
unfeasible), but not impossible.

It is also possible an exploit could avoid using the syscalls we are checking for
stack pivots at, or could simply manipulate process memory to accomplish its goals
and avoid syscalls entirely.

# Appendix

Miscellaneous useful things.

## pid/tid & tgid/pid

From a userland perspective, every process has a "Process ID" (PID), and each
thread in a process has a "Thread ID" (TID). A process has one or more threads.
Every thread belongs to a process. These identifiers can be retrieved by the
`getpid` and `gettid` syscalls. However in the kernel, we have a "Thread Group
ID" (TGID) and a "Process ID" (PID). From the kernel's perspective, we simply
have tasks (with PIDs) which belong to thread groups (which have a TGID). The
thread group leader has a PID which matches the TGID. This causes some
confusion, but is essentially just a change in terminology.

| userland | kernel |
|----------|--------|
|   pid    |  tgid  |
|   tid    |   pid  |

# References

https://ir0nstone.gitbook.io/notes/types/stack/stack-pivoting
https://wikis.rim.net/display/VR/Linux+threading+and+the+stack

Anthony's research on tracking thread stacks to detect a stack pivot (libbpf-core directory):
https://gitlab.rim.net/bart/bpftest
