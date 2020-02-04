using System.Reflection;

using NUnitLite;

namespace Sodium.Tests
{
    public class Program
    {
        public static void Main(string[] args)
        {
            new AutoRun(typeof(Program).GetTypeInfo().Assembly).Execute(args);
        }
    }
}