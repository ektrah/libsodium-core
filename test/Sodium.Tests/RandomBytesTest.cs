using NUnit.Framework;

namespace Sodium.Tests
{
    /// <summary>Tests for Random Bytes support</summary>
    [TestFixture]
    public class RandomBytesTest
    {
        /// <summary>Does SodiumCore.GetRandomBytes() return something</summary>
        [Test]
        public void GetRandomBytesTest()
        {
            var v16 = SodiumCore.GetRandomBytes(16);
            var v32 = SodiumCore.GetRandomBytes(32);
            var v64 = SodiumCore.GetRandomBytes(64);

            Assert.IsNotNull(v16);
            Assert.IsNotNull(v32);
            Assert.IsNotNull(v64);

            Assert.AreEqual(16U, v16.Length);
            Assert.AreEqual(32U, v32.Length);
            Assert.AreEqual(64U, v64.Length);
        }
    }
}
