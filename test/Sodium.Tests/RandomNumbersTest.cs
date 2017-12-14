using NUnit.Framework;

namespace Sodium.Tests
{
    /// <summary>Tests for Random Numbers support</summary>
    [TestFixture]
    public class RandomNumbersTest
    {
        /// <summary>Does SodiumCore.GetRandomNumber() return something</summary>
        [Test]
        public void GetRandomNumbersTest()
        {
            var n1 = SodiumCore.GetRandomNumber(1600);
            var n2 = SodiumCore.GetRandomNumber(25550);
            var n3 = SodiumCore.GetRandomNumber(5);
            var n4 = SodiumCore.GetRandomNumber(2147483647);
            var n5 = SodiumCore.GetRandomNumber(0); //always 0

            Assert.IsNotNull(n1);
            Assert.IsNotNull(n2);
            Assert.IsNotNull(n3);
            Assert.IsNotNull(n4);
            Assert.IsNotNull(n5);

            Assert.Less(n1, 1600);
            Assert.Less(n2, 25550);
            Assert.Less(n3, 5);
            Assert.Less(n4, 2147483647);
            Assert.AreEqual(n5, 0);
        }
    }
}
