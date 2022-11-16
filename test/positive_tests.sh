#!/usr/bin/bash

# run different variants of tests which produce stack pivot events

echo "start the PoC in /target/debug/stack_pivot_poc separately"

echo "Running tests!"

set -x

# stack pivot calling execve
./stackpivot.bin -l &> /dev/null
./stackpivot.bin -t &> /dev/null

# stack pivot calling mmap/mprotect
./mmap_mprotect.bin -l &> /dev/null
./mmap_mprotect.bin -t &> /dev/null

set +x

echo "Done! End the PoC with ctrl-c, you should see 6 stack pivot events in total."
