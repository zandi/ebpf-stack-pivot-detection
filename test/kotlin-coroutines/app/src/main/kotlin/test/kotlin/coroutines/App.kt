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
 * This Kotlin source file was generated by the Gradle 'init' task.
 */
package test.kotlin.coroutines

import kotlinx.coroutines.*

class App {
    val greeting: String
        get() {
            return "Standard Hello World!"
        }
}

class Junk {
    fun getItem(i: Int): Int {
        val data = Array(10000) { i -> i }

        return data[i]
    }
}

fun main() = runBlocking {
    println(App().greeting)

    for (i in 1..1000) {
        launch {
            delay(10)
            val j = Junk()
            println("example world " + i + ": " + j.getItem(i))
        }
    }
    println("example hello")
}
