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

package main

import (
    "fmt"
    "time"
)

func f(from string) {
    for i := 0; i < 3; i++ {
        fmt.Println(from, ":", i)
    }
}

func main() {

    f("direct")

    go f("goroutine")

    go func(msg string) {
        fmt.Println(msg)
    }("going")

    time.Sleep(time.Second)
    fmt.Println("done")
}
