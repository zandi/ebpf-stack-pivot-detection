#!/usr/bin/bash

# these tests should _not_ produce stack pivot events

echo "start the PoC in /target/debug/stack_pivot_poc separately"

echo "Running tests!"

set -x

# goroutines
go run goroutines.go > /dev/null

# csharp coroutines
mono csharp_task_example.exe > /dev/null

# incorrect thread tracking test
./incorrect_thread_tracking.bin > /dev/null

# apt install spawns some processes
sudo apt install > /dev/null

# erlang
# do this later, looks annoying

# kotlin
./kotlin-coroutines/app/build/native/nativeBuild/app > /dev/null

# do this last since it takes a while
# firefox startup
firefox --new-instance &> /dev/null &
sleep 8
kill %%

set +x

echo "Done! End the PoC with ctrl-c, you should see 0 stack pivot events in total."
