using System;
using NUnit.Framework;
using Sodium;

namespace Tests
{
    /// <summary>Exception tests for the Utilities class</summary>
    [TestFixture]
    public class UtilitiesExceptionTest
    {
        //TODO: implement, but first change the Exception types in HexBinary and Binary2Hex, because they are bad :)

        [Test]
        public void BinaryToBase64NullTest()
        {
            Assert.That(() => Utilities.BinaryToBase64(null!),
              Throws.Exception.TypeOf<ArgumentNullException>());
        }

        [Test]
        public void Base64ToBinaryNullTest()
        {
            Assert.That(() => Utilities.Base64ToBinary(null!, " "),
              Throws.Exception.TypeOf<ArgumentNullException>());
        }
    }
}
