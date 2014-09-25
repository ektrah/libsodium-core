using System;

namespace Sodium.Exceptions
{
  public class PersonalOutOfRangeException : ArgumentOutOfRangeException
  {
    public PersonalOutOfRangeException()
    {
    }

    public PersonalOutOfRangeException(string message)
      : base(message)
    {
    }

    public PersonalOutOfRangeException(string message, Exception inner)
      : base(message, inner)
    {
    }

    public PersonalOutOfRangeException(string paramName, object actualValue, string message)
      : base(paramName, actualValue, message)
    {
    }
  }
}
