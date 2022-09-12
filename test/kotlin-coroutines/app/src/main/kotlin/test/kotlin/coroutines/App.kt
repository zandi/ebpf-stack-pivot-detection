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