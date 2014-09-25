using System;

namespace Sodium.Exceptions
{
  public class NonceOutOfRangeException : ArgumentOutOfRangeException
  {
    public NonceOutOfRangeException()
    {
    }

    public NonceOutOfRangeException(string message)
      : base(message)
    {
    }

    public NonceOutOfRangeException(string message, Exception inner)
      : base(message, inner)
    {
    }

    public NonceOutOfRangeException(string paramName, object actualValue, string message)
      : base(paramName, actualValue, message)
    {
    }
  }
}
