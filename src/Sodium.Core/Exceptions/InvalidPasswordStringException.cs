using System;

namespace Sodium.Exceptions
{
    public class InvalidPasswordStringException : Exception
    {
        public InvalidPasswordStringException()
        {
        }

        public InvalidPasswordStringException(string message)
          : base(message)
        {
        }

        public InvalidPasswordStringException(string message, Exception inner)
          : base(message, inner)
        {
        }
    }
}
