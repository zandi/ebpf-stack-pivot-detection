
# Detecting Stack Pivots in Linux Userland Programs Using eBPF

Many modern exploits use Return Oriented Programming (ROP) for their payload,
and a common technique used in ROP payloads is a stack pivot.

In cases where a memory corruption used to overwrite the saved RIP value on the
stack (overflow, write-what-where, etc) is unable to accomodate a full ROP
chain, a stack pivot is used to enable a two-stage approach. The full ROP chain
is placed wherever in memory it can fit (and someplace the attacker knows the
address of), while the initial overwrite uses a small ROP chain that changes
the stack pointer register to the location of the full ROP chain. This is the
"stack pivot".

# Methodology

We would expect most payloads on linux to use syscalls at some point, such as
`execve`, `fork`, `mmap` and `mprotect`. We can use eBPF to monitor these
syscalls and inspect the RSP register (amd64). In order to detect if a stack
pivot has occured, we will need to determine if the RSP register points into a
'legitimate' stack region.

This is easier said than done, as the userland stack isn't strictly
well-defined from the perspective of the kernel. The stack of a new process is
set up by the kernel, but thread stacks are handled by the user, and there is
no expectation that the stack as initially set up by the kernel will be where
the actually-in-use stack always resides (though it often is). A program is
free to relocate its stack anywhere else and manually manage it (such as
dynamically growing the stack) without breaking any assumptions about how it
interacts with the kernel.

So, in order to keep track of what 'legitimate' stacks are, we need to both
track stack creation for new processes, user-controlled stacks for
multi-threaded processes, and other edge-cases such as Golang's goroutine
stacks.

If we can manage this, we can simply check the RSP register on important
syscalls, compare it with that task's 'legitimate' stack region(s), and make a
determination of "safe or unsafe". If false positives are kept low enough, or
even eliminated, we can provide an instant alert of an exploitation attempt, or
even SIGKILL the process within the kernel, stopping the exploit attempt.

## Details

### Linux Tasks & Thread Groups (pid/tgid, etc.)
### Thread Group Leader Stack ("Process")
### Non-Thread Group Leader Stack ("Thread")
### Other Various Edge Cases

# Results

## stopping proftpd exploit CVE-2020-9273 (do we?)

https://github.com/lockedbyte/CVE-Exploits/blob/master/CVE-2020-9273/exploit_rop.py

We won't be doing this actually, since we can't replicate the memory corruption.

## real-world stats on event breakdown for a production server

TODO: get this running on some kind of in-use server

### false positives, false negatives

## performance overhead (debug vs release)

TODO: come up with some test cases to determine this

## Complications (part of results?)

TODO: main issue is the gaps we have, both to avoid false positives, and due to
our design of relying on VMAs. We've perhaps made some inaccurate assumptions about
VMAs that make them not useful for what we're relying on them for.

## Conclusion

TODO: Is this effective enough for whatever overhead we have?

# Existing Research

Here's a few things we turned up with a quick search on google about
detecting stack pivots in ROP exploits, with a quick description. We're
chiefly looking for existing work closely related to our work. Specifically,
1) on Linux 2) focused on userland exploit detection/defense, not the kernel
3) deployable with existing software without modification (no need to recompile
userland programs or rebuild kernels).

A number of these have small parts which are reminiscent of what our PoC does;
compare the RSP register against a known stack region at certain points in
program execution. However none have all 3 of our desired properties.

All seem to be entirely or mainly focused on Windows except for GRSecurity's
RAP, which is a source-level approach.

## "Defeating ROP Through Denial of Stack Pivot"

https://www.cs.ucr.edu/~heng/pubs/pblocker-acsac15.pdf

PBlocker, LLVM-based. Enforces `StackBase < StackPointer < StackLimit` by " The
assertion is performed using code that is instrumented through a LLVM compiler
pass", by instrumenting instruction(s) that absolutely update the stack
pointer. PBlocker is described as "a source code level implementation".

Not applicable, modifying binaries is probably not practical for our intended
use-case.

## "StackPivotChecker" from McAfee

https://www.blackhat.com/docs/asia-16/materials/arsenal/asia-16-Li-StackPivotChecker.pdf

Windows-focused. Use `_NT_TIB` or `_TEB` to get stack limitation. Possibly more
of an automated tool for analysts than an in-production tool for
detection/response?

## "Deep Dive Into ROP Payload Analysis"

https://dl.packetstormsecurity.net/papers/general/rop-deepdive.pdf

Windows-focused. Examples of an analyst/forensics type person examining a
malicious file and determining a ROP payload/stack pivot exists. For example,
using a debugger to analyze how a malicious pdf file is processed, and using
the StackLimit field in the TEB to detect a stack pivot.

There is analysis of a ROP exploit which uses stack pivots, but is careful to
avoid stack pivot detection (neat!).

This is for an analyst to manually analyze a malicious file/pcap, not an
automated system.

## "Baseline Is Fragile: On the Effectiveness of Stack Pivot Defense"

https://ieeexplore.ieee.org/abstract/document/7823777

Need to get full access later. Abstract only mentions Windows and TIB.

Essentially claims that solutions which compare RSP against the TIB entries are
vulnerable to those TIB fields being altered from userland (which is
possible?!?). This should not be a concern on Linux, assuming we protect our hashmap
storing tid -> range info. Though, that should only be modifiable by root which
is not actually our threat model for this PoC.

## Patent for "Stack pivot exploit detection and mitigation"

https://patents.google.com/patent/US10853480B2/en

I don't care about patents.

## ROPGuard

https://github.com/ivanfratric/ropguard

Windows-focused and 10 years old, but an actual working prototype!

TODO: examine this

## grsecurity RAP

Looks powerful but "RAP is implemented as a GCC compiler plugin.", so not
exactly applicable for our use-case. Looks like it requires kernel support, and
to rebuild userland software to include instrumented checks.
