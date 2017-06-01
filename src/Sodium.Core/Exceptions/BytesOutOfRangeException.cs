using System;

namespace Sodium.Exceptions
{
  public class BytesOutOfRangeException : ArgumentOutOfRangeException
  {
    public BytesOutOfRangeException()
    {
    }

    public BytesOutOfRangeException(string message)
      : base(message)
    {
    }

    public BytesOutOfRangeException(string message, Exception inner)
      : base(message, inner)
    {
    }

    public BytesOutOfRangeException(string paramName, object actualValue, string message)
      : base(paramName, actualValue, message)
    {
    }
  }
}
