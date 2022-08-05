/*
* This is for exhibiting false positives from golang
* programs using goroutines.
*
* Start the sensor, then run this script with `go run goroutines.go`
* What we've seen so far is that the golang runtime will cause
* false positive stack pivots, since goroutines are scheduled and
* implemented in the golang runtime, rather than at the kernel level.
*
* So our assumption that a thread's stack is fixed is inaccurate in this case;
* golang could have different goroutines scheduled to the same thread
* at different times, thus presenting different stacks (if I understand correctly)
*/

// NOTE: make sure you're using the __x64_sys_write debug hook to check
// this test, since the goroutines should definitely call write

package main

import (
    "fmt"
    "time"
    "os"
)

func f(from string) {
    fmt.Println(from)
    for i := 0; i < 10; i++ {
        go func(num int) {
            var buf [4096 * 10]int; // just to take up stack space
            buf[ (10*i) % 10 ] = i
            fmt.Println(from, ": ", num)
        }(i)
    }
}

func main() {
    fmt.Println("process: ", os.Getpid())

    for i := 0; i < 100; i++ {
        go f(fmt.Sprintf("goroutine %d", i))
    }

    time.Sleep(time.Second)
    fmt.Println("process", os.Getpid(), "done")
}
