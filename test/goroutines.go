/* Copyright (c) 2023 BlackBerry Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

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
