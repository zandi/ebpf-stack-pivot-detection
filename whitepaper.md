
# Detecting and Preventing Stack Pivots in Linux Userland Programs Using eBPF

Michael Zandi, Anthony Blanton

## Abstract

The Linux kernel's eBPF subsystem is perfect for getting telemetry from the
kernel to use for things such as exploit detection, but can eBPF be used for
exploit prevention? The case of ROP using a stack pivot was examined.

Many modern exploits use Return Oriented Programming (ROP) for their payload,
and a common technique used in ROP payloads is a stack pivot. This paper
demonstrates a novel technique for detecting and preventing exploits involving
a stack pivot on Linux, not requiring any recompilation or static binary
re-writing/patching of programs. Measured overhead of an un-optimized
proof-of-concept ranges from negligible to 15% depending on workload, and false
positives are currently rare. This demonstrates that eBPF can be used in
certain circumstances for exploitation countermeasures rather than only
reporting exploitation attempts.

In cases where a memory corruption used to overwrite the saved RIP value on the
stack (overflow, write-what-where, etc) is unable to accomodate a full ROP
chain, a stack pivot is used to enable a two-stage approach. The full ROP chain
is placed wherever in memory it can fit (and someplace the attacker knows the
address of), while the initial overwrite uses a small ROP chain that changes
the stack pointer register to the location of the full ROP chain. This is the
"stack pivot".

# Prior Work & Existing Research

| Solution          | Platform        | Userland/Kernalland | Intervention Point                       | Binary Modification Required     | Designed For "Production"                |
|-------------------|-----------------|---------------------|------------------------------------------|----------------------------------|------------------------------------------|
| PBlocker          | Linux, Windows? | Userland            | Compile-Time (LLVM-based implementation) | Yes, recompilation from source   | Yes                                      |
| StackPivotChecker | Windows         | Userland            | Runtime (Hook Windows API)               | No, Windows API Hooking          | No (single-stepping, analyst automation) |
| ROPGuard          | Windows         | Userland            | Runtime (Hook Windows API)               | No, Windows API Hooking          | Yes (later implemented in EMET)          |
| Grsecurity RAP    | Linux           | Userland            | Compile-Time (GCC-based implementation)  | Yes, recompilation from source   | Yes                                      |
| This Work         | Linux           | Userland            | Runtime (eBPF instrumentation in-kernel) | No, Linux kernel instrumentaiton | Yes                                      |

Existing techniques for detecting stack pivots are primarily focused on the
Windows platform, where stack region information is readily available in
the Win32 Thread Information Block (TIB). Other approaches involve either
compiler-based mitigations which require source code access and recompiling
the program, or static binary modification of the program.

The closest readily found existing work to our technique is found in ROPGuard
which implements a TIB-based check, among others, to protect Windows programs
at runtime without modification. However our work protects Linux programs
without this readily available stack information, and without any program
modification, by leveraging the more recent eBPF system.

We should note that "Baseline Is Fragile: On the Effectiveness of Stack Pivot
Defense", published at the 2016 IEEE 22nd International Conference on Parallel
and Distributed Systems (ICPADS) demonstrates defeating TIB-based protections
by modifying the TIB in the attack, since the TIB is writeable from userland.

A more thorough review of prior work can be found in Appendix I.

# Short ROP Introduction

ROP, a generalization of code reuse attacks like return-to-libc, is a response
to mitigations preventing memory pages from being both writeable and
executable. Rather than injecting shellcode into the process, existing code is
reused to have the same effects within the process.

Where return-to-libc uses a return pointer overwrite to execute a full libc
function such as `system`, return oriented programming chains together multiple
short instruction sequences referred to as 'gadgets'. Gadgets are one or more
instructions that end in a return instruction, such as `pop r12 ; ret ;`.
Through clever combination these gadgets can often be used to set registers and
call syscalls as effectively as traditional shellcode. These fuller
combinations of ROP gadgets are called ROP chains.

Where a typical shellcode-based exploit would overwrite the saved return
pointer on the stack to jump to the shellcode payload, ROP overwrites a
significant portion of the stack with its ROP chain payload, starting at the
saved return pointer. As gadgets are executed, they end in a `ret` instruction
which pops an address off the stack (the next gadget's address) and jumps to
it.

## Stack Pivots

Often the initial memory corruption will be enough to overwrite the saved
return pointer on the stack, but will not allow writing the full ROP chain to
the stack.  In cases like these an initial short ROP chain that allows for RSP
control can be used to pivot the stack to elsewhere in memory. For example the
full payload can be placed in the heap or otherwise at an address the attacker
can know or discover.  An initial gadget like `leave ; ret ;` can then be used
to change the RSP register to point at the full ROP chain payload. After the
initial gadget is executed, the stack pointer now points to the full payload
and `ret` instructions will return to gadget addresses like before.

The important difference is that the RSP register may no longer be pointing
into the region initially set up as the stack.

```
                     Typical Situation   ROP Payload                  ROP + Stack Pivot

0x 00000000 00000000 ┌───────────────┐   ┌───────────────┐            ┌───────────────┐
                     │               │   │               │            │               │
                     │Program────────┤   │Program────────┤            │Program────────┤
                     │...............│   │...............│◄───gadget1 │...............│◄───gadget1
                     │...............│   │...............│            │...............│
                     │Heap───────────┤   │Heap───────────┤            │Heap───────────┤
                     │...............│   │...............│            │&gadget2       │◄─────────────┐
                     │...............│   │...............│            │&gadget3       │              │
                     ├───────────────┤   ├───────────────┤            ├───────────────┤              │
                     │               │   │               │            │               │              │
                     │               │   │               │            │               │              │
                     │Libraries──────┤   │Libraries──────┤            │Libraries──────┤              │
                     │...............│   │...............│◄───gadget2 │...............│◄───gadget2   │
                     │...............│   │...............│◄ ──gadget3 │...............│◄───gadget3   │
                     ├───────────────┤   ├───────────────┤            ├───────────────┤              │
                     │               │   │               │            │               │              │
                     │               │   │               │            │               │              │
                     │Current Frame──┤   │Current Frame──┤            │Current Frame──┤              │
                     │...............│   │...............│            │...............│              │
                     │...............│   │...............│            │...............│              │
                     │local buffer───┤   │overflow!~~~~~~│            │overflow!~~~~~~│              │
                     │...............│   │~~~~~~~~~~~~~~~│            │~~~~~~~~~~~~~~~│              │
                     │...............│   │~~~~~~~~~~~~~~~│            │~~~~~~~~~~~~~~~│              │
                     │...............│   │(padding)~~~~~~│            │(padding)~~~~~~│              │
                     ├───────────────┤   │~~~~~~~~~~~~~~~│            │~~~~~~~~~~~~~~~│              │
                     │Saved RBP      │   │~~~~~~~~~~~~~~~│            │~~~~~~~~~~~~~~~│              │
                     │Saved RIP      │   │&gadget1       │            │&pivot_gadget  ├───Update RSP─┘
                     │Previous Frame─┤   │&gadget2       │            │Previous Frame─┤
                     │...............│   │&gadget3       │            │...............│
                     │...............│   │    .          │            │...............│
                     │...............│   │    .          │            │...............│
                     │...............│   │    .          │            │...............│
0x 00007fff ffffffff └───────────────┘   └───────────────┘            └───────────────┘
```

> Figure: Typical ROP payload and ROP + Stack Pivot situations, as compared
> with a typical non-ROP situation.

# Design

We would expect most exploit payloads on linux to use syscalls at some point,
such as `execve`, `fork`, `mmap` and `mprotect`. We can use eBPF to monitor
these syscalls and inspect the RSP register (amd64). In order to detect if a
stack pivot has occured, we will need to determine if the RSP register points
into a 'legitimate' stack region.

This is easier said than done, as the userland stack isn't strictly
well-defined from the perspective of the kernel. The stack of a new process is
set up by the kernel, but thread stacks are handled by the user, and there is
no expectation that the stack as initially set up by the kernel will be where
the actually-in-use stack always resides (though it nearly always is). A
program is free to relocate its stack anywhere else and manually manage it
(such as dynamically growing the stack) without breaking any assumptions about
how it interacts with the kernel. This can be learned from the `is_stack`
function in `fs/proc/task_mmu.c`, used in printing a process's memory maps
through `/proc/PID/maps`. While the code itself is simple, the accompanying
comment illustrates the issue:

```
/*
 * We make no effort to guess what a given thread considers to be
 * its "stack".  It's not even well-defined for programs written
 * languages like Go.
 */
```

So, in order to keep track of where 'legitimate' stacks are, we need to track
stack creation for new processes, user-managed stacks for multi-threaded
processes, and other edge-cases such as Golang's user stacks.

Once we have this, we can simply check the RSP register on important syscalls,
compare it with that task's 'legitimate' stack region(s), and make a
determination of "safe" or "unsafe". We can alert on "unsafe" events to have
detection of in-progress exploitation, and if false positives are eliminated,
we can even SIGKILL the process from within the kernel using `bpf_send_signal`
and stop the exploitation attempt entirely.

```
 ┌─Process─┐          ┌─Kernel─────────────────────────────────────────────────────────────┐
 │Proof-of-│          │                                                                    │
 │Concept  │◄───────────Ringbuf Events─────────┬───────┐                                   │
 │Agent    │          │                        │       │                                   │
 └─────────┘          │  ┌─eBPF Program─┐      │       │                                   │
                      │  │mprotect      │      │       │                                   │
                      │  │mmap          │      │       │                                   │
                      │  │execve        │  ┌───┴─────┐ │      ┌─eBPF Program───┐           │
                      │  │execveat      ├─►│Check RSP│ │   ┌─►│wake_up_new_task├─Update──┐ │
┌─Process──┐          │  │socket        │  └─────────┘ │   │  └────────────────┘         │ │
│Arbitrary │          │  │dup2          │   ▲          │   │                             │ │
│          ├─syscall────►│dup3          │   │          │   │  ┌─eBPF Retprobe───┐        │ │
│ Program  │          │  ├──────────────┤   │          │   │  │execve (return)  ├─Delete─┤ │
└──────────┘          │  │fork          │   │  ┌───────┴─┐ │  │execveat (return)│        │ │
                      │  │vfork         ├─────►│Check RSP├─┘  └─────────────────┘        │ │
                      │  │clone         │   │  └─────────┘                               │ │
                      │  │clone3        │   │   ▲                                        │ │
                      │  ├──────────────┤   │   │      ┌─eBPF Map────────────┐           │ │
                      │  │exit          │   └───┴─Read─┤Tracked Stack Regions│◄──────────┘ │
                      │  └───────┬──────┘              └──────▲──────────────┘             │
                      │          └─────────Delete─────────────┘                            │
                      └────────────────────────────────────────────────────────────────────┘
```

> Figure: Proof-of-Concept design diagram

## Stack and Thread Details

We need to understand some details of stacks and threads in order to keep track
of each thread's stack.

### Linux Tasks & Thread Groups (pid/tgid, etc.)

From the user perspective, there are processes with threads. Processes have
strict separations between them, such as having their own private virtual
memory, while threads belong to a process and all share the same virtual
memory. Processes always have at least one thread, with the first (and
sometimes only) thread often being called the 'main' thread.

However from the perspective of the Linux kernel all threads are tasks, have
their own `task_struct`, and belong to a thread group. All thread groups have
at least one task, and the first task in a thread group has a task ID matching
the thread group's ID.

```
   ┌──────────────────────────┐
   │                          │
   │            ┌─────┬─────┐ │
   │            │PID  │  TID│ │
   │            └─────┴─────┘ │
   │               ▲     ▲    │
   │ User Land     │     │    │
   ├───────────────┼─────┼────┤
   │ Kernel Land   │     │    │
   │               ▼     ▼    │
   │            ┌─────┬─────┐ │
   │            │TGID │  PID│ │
   │            └─────┴─────┘ │
   │                          │
   └──────────────────────────┘
```

> Figure: Inconsistencies between user and kernel terminology around process &
> thread IDs

So to bridge userland and kernelland terms, a process is a task group, and a
thread is a task. A Process ID (PID) in userland is a Thread Group ID (TGID) in
the kernel, and a Thread ID (TID) in userland is a `pid` in the kernel. From
now on we'll be using kernel terminology, since the more technical eBPF
components operate in the kernel. Understanding this quirk of terminology
will help avoid confusion later.

### Thread Group Leader Stack ("Process")

For the first task in a thread group, which is that thread group's leader, the
kernel handles setting up its stack. This includes allocating the stack and
initializing it with the appropriate arguments and environment, as well as
setting the requested executable stack permission. Additionally, this Virtual
Memory Area (VMA) has its `vm_flags` field initialized to have the flags
specified by the `VM_STACK_FLAGS` macro set. In our case of using amd64, this
ultimately includes the `VM_GROWSDOWN` macro. This all begins when a userspace
program begins execution of a new process via the `execve` syscall, which kicks
off the loading of a binary into its own virtual memory space and begins its
execution.

This is important for allowing the kernel to automatically expand the stack for
the user. Many things happen during a userland pagefault, but for our interests
this is where stack expansion happens. When the stack outgrows its current
allocation, for example by allocating space for local variables when entering a
function, it causes a page fault. Within `do_user_addr_fault` there is a check
for if the nearest VMA above the faulting address has the `VM_GROWSDOWN` flag
set. If so, then `expand_stack` is called, which is a simple wrapper for either
`expand_downwards` or `expand_upwards` in `mm/mmap.c`. `expand_downwards`
checks that the expansion wouldn't violate the configured stack guard gap, then
expands the VMA downwards to include the faulting address.

So, the first thread of a process (the task which is the thread group leader)
has a stack that is fully automatic from the user's perspective. It's allocated
and initialized by the kernel and is automatically expanded by the kernel
without any user intervention.

### Non-Thread Group Leader Stack ("Thread")

Subsequent threads created in the process do not have this kind of kernel
support for their stacks. To have multithreading from the user's perspective,
ultimately the `clone` (or `clone3`) syscall is used to create a new task which
shares certain resources with the task that created it, such as its virtual
memory space. Because the virtual memory is shared, new threads cannot use the
stack that the kernel created for the thread group leader. This could cause
all manner of chaos as threads corrupt each other's stacks.

Instead, the user must manage the stack of the threads they create. The user
must allocate the stack for a thread before creating it, and provide this
information to the kernel as an argument to the `clone` syscall, or within the
argument struct for `clone3`. In practice this bookkeeping is done by
libraries, frameworks and languages that the programmer uses.

As a common example, the pthreads threading implementation used in glibc
handles allocation of thread stacks automatically for the user. Internally a
stack is allocated using `mmap` with a size that is optionally configurable by
the user. A guard region (by default a page) is used to detect thread stack
overflow and prevent unintentional corruption. Threads created through pthreads
have stacks which are fixed in size, and cannot dynamically grow.

### Other Various Edge Cases

The most notable edge case to this has been from Golang. Golang manages its own
stacks for user code, separate from the system stack which Linux allocates and
manages for the first thread in a thread group. These user stacks are allocated
on the Golang runtime's heap, which on the amd64 architecture has somewhat
predictable locations. The result is that syscalls from Golang programs can
have a stack pointer in an unusual region, such as `[0xc000000000,
0xc000ffffff).`

Manually adding regions to an allowlist as they are observed is enough for
quick development, but a more reliable solution using knowledge of Golang heap
internals is necessary to handle long-running and more stressed Golang
applications. One such solution taking advantage of predictable hint addresses
provided to mmap when allocating new Golang heap arenas was used to eliminate
observed false positives in testing.

```
┌─Virtual Memory ────────────────────┐ 0x 00007fff ffffffff
│....................................│
│....................................│
│....................................│
│Stack───────────────────────────────┤ 0x 00007fff fffd6000
│                                    │
├────────────────────────────────────┤ 0x 00007fff b7d00000
│....................................│
│pthread stack───────────────────────┤ 0x 00007fff b7cc0000
│                                    │
├────────────────────────────────────┤ 0x 00007fff bc444000
│................. ..................│
│pthread stack───────────────────────┤ 0x 00007fff bc404000
│                                    │
├────────────────────────────────────┤ 0x 00007fff b4a7e000
│....................................│
│pthread stack───────────────────────┤ 0x 00007fff b4a3e000
│                                    │
│                                    │
│                                    │
├────────────────────────────────────┤ 0x 000000c4 21000000
│....................................│
│Golang user stack───────────────────┤ 0x 000000c4 20000000
│                                    │
├────────────────────────────────────┤ 0x 000000c0 04000000
│0x 000000c0 03631270................│
│0x 000000c0 01fc4670..(Example SPs).│
│0x 000000c0 0003c000................│
│Golang user stack───────────────────┤ 0x 000000c0 00000000
│                                    │
│                                    │
└────────────────────────────────────┘ 0x 00000000 00000000
```

> Figure: Examples of observed legitimate stack regions

# Results

Following are some results from testing a Proof-of-Concept implementation of
this technique.

## In-Development Testing

Limited testing was done during development running typical Linux desktop
software, basic benchmarking suites, and simple test programs for various
languages to test threading & concurrency situations similar to Golang's
goroutines. For example, web browsing with Firefox 112 was used to exercise the
PoC against a relatively complicated multi-threaded & multi-process
application. Additionally Phoronix Test Suite was used to exercise common
server workloads Apache, Nginx, Redis and Postgresql.

### Concurrency Primitives

Golang reliably and trivially produced false positives at first, due to its
runtime-managed user stacks allocated on the Golang runtime's heap.  These
dynamic stacks appear to be primarily due to Golang's scheduling model to
enable goroutines as a lightweight concurrency primitive.

Hardcoding these regions into an allowlist as they trigger a false positive was
enough to quiet Golang-related false positives in development. However more
rigorous solutions are necessary to be reliable in production environments.

Basic tests with threading & concurrency support in the following languages was
done to search for similar false-positive situations, and did not uncover
further false positives: Erlang processes (lightweight threads), C# Tasks via
`System.Threading.Tasks`, Kotlin coroutines from `kotlinx.coroutines` running
in a native binary built using GraalVM.

## Events From Test Kubernetes Cluster

A two-node Kubernetes cluster (control plane node and worker node) was used for testing
and benchmarking. A fuller description of the cluster setup is included in the
Performance Overhead section. Besides benchmarks, a small Nextcloud instance
behind a Traefik reverse proxy/load balancer was used to simulate a more
realistic workload. Over 5 days of light usage of Treafik+Nextcloud, and 9
days of running the proof-of-concept on the cluster, no stack pivots or false
positives were logged.

| Event Kind              | Count     | Description                                                     |
|-------------------------|-----------|-----------------------------------------------------------------|
| OK events               | 308592978 | Expected benign case (RSP in "legitimate" stack region)         |
| "No VMA" events         | 706       | Unable to find the VMA for an address                           |
| "Ancient Thread" events | 3576      | Thread predates PoC being loaded, cannot locate stack           |
| "Golang Stack" events   | 22648885  | Detected Golang user stack address, assumed legitimate          |
| Stack Pivot events      | 0         | RSP outside "legitimate" stack region(s), not apparently Golang |
| "Unknown" events        | 0         | Catch for improperly set return code                            |

### False Positives

The most significant false positives were with Golang applications. This is due
to Golang user stacks being allocated in the Golang runtime's heap. Golang user
stacks can be relocated elsewhere in the runtime heap as they grow or shrink,
and heap arenas can by dynamically allocated. Hints are used to guide heap
arena allocations to addresses with a specific predictable format, but mmap on
linux doesn't guarantee allocations related to the provided address hint if
it's unable to allocate at the hint.

The current edge-case handling for Golang compares the address against this
known hint format and allows it if it conforms to the known Golang arena hints.
Over 9 days of runtime and 5 days of light Traefik+Nextcloud usage no false
positives were detected. This approach seems sufficient to eliminate
Golang-based false positives, but testing on in-production clusters will be
necessary for confidence and understanding of rare circumstances where false
positives may still occur.

Testing has yet to uncover other false positives that weren't the result of a
bug or otherwise couldn't be quickly remedied.

### False Negatives

There are a few false negative cases uncovered in testing, some of which may be
resolved with further research, and some which may not.

* Golang allowlist ranges could allow a full bypass, if an attacker could first
achieve a controlled memory allocation at that address. For example, if the attacker
controlled an mmap call.

* Pivoting elsewhere in the stack is not detectable with this approach and would
require stricter CFG enforcement. The full stack region is considered legitimate,
regardless of how function frames have been allocated in it.

## Debug build Performance Overhead

Benchmarking was done on a two-node kubernetes cluster (one control plane, one
worker node) managed by Rancher v2.5.8, running on vSphere, with Kubernetes
v1.20.11. The worker node was allocated 2 CPU cores at 2GHz, 8GB of RAM,
running Ubuntu 20.04.4 LTS with kernel 5.15.0-60-generic (x86_64). Besides
internal Rancher and Kubernetes containers, the cluster was running a Busybox
pod for miscellaneous in-container testing, an internal docker registry for
provisioning PoC docker images (installed via helm chart docker-registry-2.2.2,
app version 2.8.1), and a phoronix pod for running benchmarks. Tests run were:
pts/apache-3.0.0, pts/build-linux-kernel-1.15.0, pts/osbench-1.0.2,
pts/perf-bench-1.0.5, and pts/pgbench-1.13.0.

Baseline tests were performed on this cluster on the single worker node, while
tests with the proof-of-concept had an additional pod with the docker image of
the proof-of-concept running.

| Benchmark                                                 | Baseline   | Proof-of-Concept | Standard Deviation | Better | Overhead                     | Winner           |
|-----------------------------------------------------------|------------|------------------|--------------------|--------|------------------------------|------------------|
| Apache HTTP Server - 100 (Reqs/sec)                       | 12616      | 11483            | 0.2%, 0.3%         | More   | 9%                           | Baseline         |
| Timed Linux Kernel Compilation - defconfig (sec)          | 1026       | 1076             | 2.4%, 5.5%         | Less   | 5%                           | Baseline         |
| OSBench - Create Files (us/Event)                         | 27.933909  | 26.823105        | 2.1%, 2.1%         | Less   | -4%                          | Proof-of-Concept |
| OSBench - Create Threads (us/Event)                       | 15.239716  | 35.490195        | 2.3%, 1.2%         | Less   | 57%                          | Baseline         |
| OSBench - Launch Programs (us/Event)                      | 197.153092 | 233.280659       | 0.5%, 0.7%         | Less   | 15%                          | Baseline         |
| OSBench - Create Processes (us/Event)                     | 53.283374  | 57.943463        | 1.8%, 2.5%         | Less   | 8%                           | Baseline         |
| OSBench - Memory Allocations (Ns/Event)                   | 112.217983 | 106.676738       | 0.7%, 0.5%         | Less   | -5%                          | Proof-of-Concept |
| perf-bench - Syscall Basic (ops/sec)                      | 9033372    | 9111270          | 0.8%, 0.4%         | More   | Negligible (<1%, within SD)  | N/A              |
| PostgreSQL - 100 - 50 - Read Only (TPS)                   | 53630      | 52927            | 0.4%, 1.5%         | More   | Negligible (1.3%, within SD) | N/A              |
| PostgreSQL - 100 - 50 - Read Only - Average Latency (ms)  | 0.932      | 0.945            | 0.4%, 1.4%         | Less   | Negligible (1.3%, within SD) | N/A              |
| PostgreSQL - 100 - 50 - Read Write (TPS)                  | 4431       | 4437             | 2.5%, 2.5%         | More   | Negligible (<1%, within SD)  | N/A              |
| PostgreSQL - 100 - 50 - Read Write - Average Latency (ms) | 11.291     | 11.275           | 2.5%, 2.5%         | Less   | Negligible (<1%, within SD)  | N/A              |

In general tests saw the proof-of-concept with an overhead ranging from
negligible to 15%, with some notable outliers. Apache saw a 9% decrease in
requests-per-second, while building Linux took about 5% longer, though with a
standard deviation at 5.5%. OSBench saw 8% overhead in process creation, 16%
overhead in program launch, and a massive doubling in time to create new
threads. Strangely, the proof-of-concept situation was faster than baseline for
creating files and allocating memory (4% and 5% respectively, sd 2.1% and 0.7%)
despite only introducing more code to various syscalls. This may be due to
fluctuations on shared hosting infrastructure or other uncontrolled factors.
perf-bench's basic syscall benchmark saw negligible overhead, with the baseline
0.85% slower with a standard deviation of 0.8%. pgbench had similar results,
with the proof-of-concept case beating baseline in read-only cases by 1.4%
(standard deviation 1.5%), while having 0.15% overhead in read-write cases
(standard deviation 2.5%).

Based on this an estimate of 5%-10% overhead for various workloads seems
reasonable though conservative, with some lucky workloads being negligible.
Since these benchmarks were done with an unoptimized proof-of-concept, these
can be considered something like worst-case numbers. This can be reduced by
omitting certain syscalls from stack pivot checking, short-circuiting
uninteresting cases such as clone in the thread creation case, removing
unnecessary VMA lookups, and removing the currently extensive debugging output.

# Conclusion

This demonstrates that the eBPF-based technique of tracking 'legitimate' stacks
of running programs in order to detect stack pivots on a Linux system is
feasible, and with further work may be reliable and low-overhead enough to
implement in production systems. Linux's agnostic approach to where a running
program should have its stack complicates detection, but existing real-world
software is still predictable enough for this approach to be amenable.

This also demonstrates that at least in certain cases, using eBPF to implement
exploitation countermeasures is feasible, allowing for a more proactive defense
than simple alert-based systems.

## Further Research

This initial approach to tracking and determining 'legitimate' stack regions
works, but alternative approaches should be tested in hopes of finding
techniques with better performance or fewer false negatives.

Current techniques to detect and allow Golang user stacks need to be tested on
more in-production clusters to evaluate if Golang false positives can still
occur, and if so how often.

More research is needed on how VMAs are allocated and merged, to improve
distinguishing between different memory regions.

Rare cases of a VMA for an address not being found need to be analyzed.

Techniques for better handling of "Ancient" thread events should be
explored. For example, a Trust-on-First-Use approach where the VMA used
by RSP on the first monitored syscall of a thread with no tracked stack
is trusted and saved for later checks may be sufficient.

Testing against in-the-wild exploits using a stack pivot is necessary for a
clearer picture on real-world efficacy. Previous attempts faced issues in
replicating public exploits.

Running the proof-of-concept on in-production systems and clusters is necessary
for further stress testing and uncovering of rarer false positives.

# Appendix I: Prior Work

This is a quick review of existing research on stopping ROP exploits. We're
most interested in work that is on Linux, focused on userland ROP rather than
the kernel, and does not require any modification of the target software.
None of the reviewed research has all three of these features.

Included is a brief description of the research, and its applicability for
our intended use-case.

## "Defeating ROP Through Denial of Stack Pivot"

https://www.cs.ucr.edu/~heng/pubs/pblocker-acsac15.pdf

PBlocker, LLVM-based. Enforces `StackBase < StackPointer < StackLimit` by "The
assertion is performed using code that is instrumented through a LLVM compiler
pass", by instrumenting instruction(s) that absolutely update the stack
pointer. PBlocker is described as "a source code level implementation".

Modifying binaries is probably not practical for our intended use-case.

## "StackPivotChecker" from McAfee

https://www.blackhat.com/docs/asia-16/materials/arsenal/asia-16-Li-StackPivotChecker.pdf

Windows-focused. Use `_NT_TIB` or `_TEB` to get stack limitation. Possibly more
of an automated tool for analysts than an in-production tool for
detection/response?

## "Deep Dive Into ROP Payload Analysis"

https://dl.packetstormsecurity.net/papers/general/rop-deepdive.pdf

Windows-focused. Examples of an analyst/forensics role examining a malicious
file and determining a ROP payload/stack pivot exists. For example, using a
debugger to analyze how a malicious pdf file is processed, and using the
StackLimit field in the TEB to detect a stack pivot.

There is analysis of a ROP exploit which uses stack pivots, but is careful to
avoid stack pivot detection (neat!).

This is for an analyst to manually analyze a malicious file/pcap, not an
automated system.

## "Baseline Is Fragile: On the Effectiveness of Stack Pivot Defense"

https://ieeexplore.ieee.org/abstract/document/7823777

Did not have full access. Abstract only mentions Windows and TIB.

Essentially claims that solutions which compare RSP against the TIB entries are
vulnerable to those TIB fields being altered from userland. This should not be
a concern on Linux, assuming we protect our hashmap storing tid -> range info.
Though, that should only be modifiable by root which is not actually our threat
model for this PoC. Additionally, any hashmaps we use can be frozen to prevent
modification from userland (depending on Linux kernel version).

## Patent for "Stack pivot exploit detection and mitigation"

https://patents.google.com/patent/US10853480B2/en

This patent seems to describe checking the stack base/stack limit in the TIB
against the stack pointer, which is essentially what ROPGuard and other
research did long before this patent was filed in 2018. The technique and
design described in the patent is not new when filed in 2018.

## ROPGuard

https://github.com/ivanfratric/ropguard

Windows-focused and 10 years old, but an actual working prototype!

Some similarities:
- can be applied to any process at runtime
- no need to recompile programs or statically patch/rewrite
- syscalls are the point of check/visibility (must be called from ROP payload)

The checks it implements:
1) Checks for stack pivot by comparing stack pointer to designated stack area in TIB
2) In a 'critical function' f, checks for &f on the stack just above stack pointer, indicating entry by RETN rather than CALL
3) on critical function entry, checks that the return adress is 1) executable and 2) the pointed-to instruction is preceded by a CALL instruction
4) if using EBP as frame pointer, can check preceding stack frames. eg: that preceding EBP values point into the stack
5) some limited simulation of instruction execution after the function's return (didn't read this closely)

1 is essentially identical to our approach. However where Windows stores the
necessary info in the TIB to do a simple check, Linux has no corresponding
fields, and the OS doesn't even have or enforce a consistent notion of what the
stack actually is for a userland process/thread.

The rest require reading userland memory which we don't do. This could be an
area for further study, but would be more complicated and may have unacceptable
overhead.

## Grsecurity RAP

https://grsecurity.net/rap_faq

Looks powerful but "RAP is implemented as a GCC compiler plugin.", so not
exactly applicable for our use-case. It requires rebuilding software to protect
it.

# Append II: Extra Diagrams

## x86_64 Address Space

Some abridged diagrams of a typical userspace program's virtual memory space on
amd64, with ASLR turned off to simplify addresses.

### Statically Linked ELF (minimal example)

This program only calls the exit syscall, is statically linked, and doesn't
include the C standard library. It's a minimal example for a very simple
address space. Only regions with a name/filled with '.' indicate mapped memory.

```
┌─────────────┐ 0x 00007fff ffffffff
│.............│
│.............│
│[stack]──────┤ 0x 00007fff fffde000
│             │
│             │
├─────────────┤ 0x 00007fff f7fff000
│.............│
│[vdso]───────┤ 0x 00007fff f7ffd000
│.............│
│[vvar]───────┤ 0x 00007fff f7ff9000
│             │
│             │
├─────────────┤ 0x 00000000 00401000
│.............│
│.............│
│ELF Image ───┤ 0x 00000000 00400000
│             │
│             │
└─────────────┘ 0x 00000000 00000000
```

### Dynamically Linked ELF (Python3.10)

This is more complicated, but is more typical of any given running program.

```
┌─────────────┐ 0x 00007fff ffffffff
│.............│
│.............│
│[stack]──────┤ 0x 00007fff fffde000
│             │
│             │
├─────────────┤ 0x 00007fff f7fff000
│.............│
│.............│
│linker.so────┤ 0x 00007fff f7fc3000 ld-linux-x86-64.so.2
│.............│
│[vdso]───────┤ 0x 00007fff f7fc1000
│.............│
│[vvar]───────┤ 0x 00007fff f7fbd000
│.............│
│.............│ (various shared objects)
│.............│
│other .so's──┤ 0x 00007fff f6a34000
│             │
│             │
├─────────────┤ 0x 00005555 55c8f000
│.............│
│.............│
│[heap]───────┤ 0x 00005555 55af8000
│.............│
│.............│
│python3.10───┤ 0x 00005555 55554000
│             │
│             │
└─────────────┘ 0x 00000000 00000000
```

### Kernel Address Space

For those curious, the upper end of the address space is mostly inaccessible to
the user, but a simplified version is something like this. Details are
irrelevant, but can be found in kernel documentation for each architecture's
memory management.

```
┌─────────────┐ 0x ffffffff ffffffff
│.............│
│.............│
│kernel───────┤ 0x ffff8000 00000000
│             │
│    hole     │
│             │
└─────────────┘ 0x 00008000 00000000
```
