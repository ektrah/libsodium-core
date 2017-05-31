using System;

namespace Sodium.Exceptions
{
  public class AdditionalDataOutOfRangeException : ArgumentOutOfRangeException
  {
    public AdditionalDataOutOfRangeException()
    {
    }

    public AdditionalDataOutOfRangeException(string message)
      : base(message)
    {
    }

    public AdditionalDataOutOfRangeException(string message, Exception inner)
      : base(message, inner)
    {
    }

    public AdditionalDataOutOfRangeException(string paramName, object actualValue, string message)
      : base(paramName, actualValue, message)
    {
    }
  }
}
