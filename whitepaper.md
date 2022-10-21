
# Detecting Stack Pivots in Linux Userland Programs Using eBPF

Many modern exploits use Return Oriented Programming (ROP) for their payload,
and a common technique using in ROP payloads is a stack pivot.

In cases where an initial memory corruption (overflow, write-what-where, etc)
is unable to accomodate a full ROP chain, a stack pivot is used to enable a
two-stage approach. The full ROP chain is placed wherever in memory it can fit
(and someplace the attacker knows the address of), while the initial overwrite
uses a small ROP chain that changes the stack pointer register to the location
of the full ROP chain. This is the "stack pivot".

# Methodology

We would expect most payloads on linux to use syscalls at some point, such as
`execve`, `fork`, `mmap` and `mprotect`. We can use eBPF to monitor these
syscalls and inspect the rsp register (amd64). In order to detect if a stack
pivot has occured, we will need to determine if the rsp register points into a
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
track stack creation for new processes, user-controlled stacks for threads, and
other edge-cases such as Golang's goroutine stacks.

If we can manage this, however, we can simply check the rsp register on
important syscalls, compare it with that task's 'legitimate' stack region(s),
and make a determination of "safe or unsafe". If false positives are kept low
enough, or even eliminated, we can provide an instant alert of an exploitation
attempt, or even sigkill the process within the kernel, stopping the exploit
attempt.

## Details

### Linux Tasks & Thread Groups (pid/tgid, etc.)
### Thread Group Leader Stack ("Process")
### Non-Thread Group Leader Stack ("Thread")
### Other Various Edge Cases

# Results

## stopping proftpd exploit CVE-2020-9273 (do we?)

https://github.com/lockedbyte/CVE-Exploits/blob/master/CVE-2020-9273/exploit_rop.py

## real-world stats on event breakdown for a production server
### false positives, false negatives
## performance overhead (debug vs release)

## Complications (part of results?)

## Conclusion
