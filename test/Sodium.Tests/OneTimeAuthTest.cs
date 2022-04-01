using System.Text;
using NUnit.Framework;
using Sodium;

namespace Tests
{
    /// <summary>Tests for the OneTimeAuth class</summary>
    [TestFixture]
    public class OneTimeAuthTest
    {
        /// <summary>Verify that the length of the returned key is correct.</summary>
        [Test]
        public void TestGenerateKey()
        {
            Assert.AreEqual(32, OneTimeAuth.GenerateKey().Length);
        }

        /// <summary>Does OneTimeAuth.Sign() return the expected value?</summary>
        [Test]
        public void SimpleAuthTest()
        {
            var expected = Utilities.HexToBinary("07577518b48b4980354844c8fe1b253f");
            var actual = OneTimeAuth.Sign(Encoding.UTF8.GetBytes("Adam Caudill"),
              Encoding.UTF8.GetBytes("01234567890123456789012345678901"));
            CollectionAssert.AreEqual(expected, actual);
        }

        /// <summary>Does OneTimeAuth.Verify() return the expected value?</summary>
        [Test]
        public void SimpleVerifyTest()
        {
            var actual = OneTimeAuth.Verify(Encoding.UTF8.GetBytes("Adam Caudill"),
              Utilities.HexToBinary("07577518b48b4980354844c8fe1b253f"),
              Encoding.UTF8.GetBytes("01234567890123456789012345678901"));
            Assert.AreEqual(true, actual);
        }
    }
}
