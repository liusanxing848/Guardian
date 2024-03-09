namespace GuardianService.Util
{
    public class GLogger
    {
        public static void Log(string op, string content)
        {
            DateTime now = DateTime.Now;
            Console.WriteLine($"{now}: [{op}] {content}");
        }

        public static void LogRed(string label, string op, string content)
        {
            DateTime now = DateTime.Now;
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"{now} [{label}][{op}] {content}");
            Console.ResetColor();
        }

        public static void LogYellow(string label, string op, string content) 
        {
            DateTime now = DateTime.Now;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"{now} [{label}][{op}] {content}");
            Console.ResetColor();
        }

        public static void LogGreen(string label, string op, string content)
        {
            DateTime now = DateTime.Now;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"{now} [{label}][{op}] {content}");
            Console.ResetColor();
        }
    }
}
