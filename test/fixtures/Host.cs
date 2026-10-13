using System;
using System.Threading;

// Keeps a Mono process alive with TestLib loaded so Frida can attach to it.
public static class Host
{
    public static int Main()
    {
        Console.WriteLine("LOADED " + typeof(FridaMono.Tests.Smoke).Assembly.GetName().Name);
        Console.WriteLine("READY");
        while (true) Thread.Sleep(1000);
    }
}
