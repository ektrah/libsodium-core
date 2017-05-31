using System;

namespace Sodium.Exceptions
{
  public class SignatureOutOfRangeException : ArgumentOutOfRangeException
  {
    public SignatureOutOfRangeException()
    {
    }

    public SignatureOutOfRangeException(string message)
      : base(message)
    {
    }

    public SignatureOutOfRangeException(string message, Exception inner)
      : base(message, inner)
    {
    }

    public SignatureOutOfRangeException(string paramName, object actualValue, string message)
      : base(paramName, actualValue, message)
    {
    }
  }
}
