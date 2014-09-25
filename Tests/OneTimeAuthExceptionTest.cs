using System.Text;
using NUnit.Framework;
using Sodium;
using Sodium.Exceptions;

namespace Tests
{
  /// <summary>Exception tests for the OneTimeAuth class</summary>
  [TestFixture]
  public class OneTimeAuthExceptionTest
  {
    [Test]
    [ExpectedException(typeof(KeyOutOfRangeException))]
    public void OneTimeAuthSignNoKey()
    {
      OneTimeAuth.Sign(Encoding.UTF8.GetBytes("Adam Caudill"), null);
    }

    [Test]
    [ExpectedException(typeof(KeyOutOfRangeException))]
    public void OneTimeAuthSignKeyWrongSize()
    {
      OneTimeAuth.Sign(Encoding.UTF8.GetBytes("Adam Caudill"),
        Encoding.UTF8.GetBytes("01234567890123456789012345678"));
    }
  }
}
