/*
This is pretty simple, but at least doesn't exhibit false positive
stack pivots yet
*/

using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

class Example
{
    static void Main()
    {
        Action<object> action = (object obj) =>
                                {
                                   // take up some stack space just to stress things
                                   int[] junk = new int[100];

                                   // just loop to take up time
                                   for (int i = 0; i < 1000000; i++)
                                   { junk[i % 100]++; }
                                   Console.WriteLine("Task={0}, obj={1}, Thread={2}",
                                   Task.CurrentId, obj,
                                   Thread.CurrentThread.ManagedThreadId);
                                };

        Process currentProcess = Process.GetCurrentProcess();
        String pid = currentProcess.Id.ToString();

        Console.WriteLine("pid {0}", pid);

        // make lots of tasks
        Console.WriteLine("Creating 100 Tasks");
        Task[] tasks = new Task[100];
        for (int i = 0; i < 100; i++) {
            tasks[i] = new Task(action, i);
        }

        // run them all
        Console.WriteLine("Starting 100 Tasks");
        foreach (Task t in tasks)
        {
            t.Start();
        }

        // wait for completion, so they have a fair chance to run
        Console.WriteLine("Waiting for 100 Tasks");
        foreach (Task t in tasks)
        {
            t.Wait();
        }

        Console.WriteLine("Done");
    }
}
