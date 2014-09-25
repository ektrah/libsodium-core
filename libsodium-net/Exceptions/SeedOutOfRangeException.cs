using System;

namespace Sodium.Exceptions
{
  public class SeedOutOfRangeException : ArgumentOutOfRangeException
  {
    public SeedOutOfRangeException()
    {
    }

    public SeedOutOfRangeException(string message)
      : base(message)
    {
    }

    public SeedOutOfRangeException(string message, Exception inner)
      : base(message, inner)
    {
    }

    public SeedOutOfRangeException(string paramName, object actualValue, string message)
      : base(paramName, actualValue, message)
    {
    }
  }
}
