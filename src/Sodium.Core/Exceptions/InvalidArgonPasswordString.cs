using System;

namespace Sodium.Exceptions
{
    class InvalidArgonPasswordString : Exception
    {
        public InvalidArgonPasswordString()
          : base("Invalid Password string for Argon 2")
        {
        }
    }
}
