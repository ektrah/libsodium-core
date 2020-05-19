using System;

namespace Sodium.Exceptions
{
    class InvalidSodiumPasswordString : Exception
    {
        public InvalidSodiumPasswordString()
          : base("Invalid Password string for SCrypt")
        {
        }
    }
}