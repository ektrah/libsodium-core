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
        public void OneTimeAuthSignNoKey()
        {
            Assert.Throws<KeyOutOfRangeException>(() =>
            {
                OneTimeAuth.Sign(Encoding.UTF8.GetBytes("Adam Caudill"), null!);
            });
        }

        [Test]
        public void OneTimeAuthSignKeyWrongSize()
        {
            Assert.Throws<KeyOutOfRangeException>(() =>
            {
                OneTimeAuth.Sign(Encoding.UTF8.GetBytes("Adam Caudill"),
            Encoding.UTF8.GetBytes("01234567890123456789012345678"));
            });
        }
    }
}
