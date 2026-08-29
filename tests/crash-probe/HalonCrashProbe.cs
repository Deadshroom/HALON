using System;

public class HalonCrashProbe
{
    public static void Main()
    {
        Console.WriteLine("HALON controlled crash probe starting...");

        throw new InvalidOperationException(
            "HALON_CONTROLLED_APPLICATION_ERROR"
        );
    }
}
