using System;

namespace Sodium.Exceptions
{
  public class SaltOutOfRangeException : ArgumentOutOfRangeException
  {
    public SaltOutOfRangeException()
    {
    }

    public SaltOutOfRangeException(string message)
      : base(message)
    {
    }

    public SaltOutOfRangeException(string message, Exception inner)
      : base(message, inner)
    {
    }

    public SaltOutOfRangeException(string paramName, object actualValue, string message)
      : base(paramName, actualValue, message)
    {
    }
  }
}
