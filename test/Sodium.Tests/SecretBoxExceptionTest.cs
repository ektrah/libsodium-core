using System.Text;
using NUnit.Framework;
using Sodium.Exceptions;

namespace Sodium.Tests
{
    /// <summary>Exception tests for the SecretBox class</summary>
    [TestFixture]
    public class SecretBoxExceptionTest
    {
        [Test]
        public void CreateSecretBoxBadKey()
        {
            Assert.Throws<KeyOutOfRangeException>(() => SecretBox.Create(
                Encoding.UTF8.GetBytes("Adam Caudill"),
                Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
                Encoding.UTF8.GetBytes("123456789012345678901234567890")));
        }

        [Test]
        public void CreateSecretBoxBadNonce()
        {
            Assert.Throws<NonceOutOfRangeException>(() => SecretBox.Create(
                Encoding.UTF8.GetBytes("Adam Caudill"),
                Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVW"),
                Encoding.UTF8.GetBytes("12345678901234567890123456789012")));
        }

        [Test]
        public void CreateDetachedSecretBoxBadKey()
        {
            Assert.Throws<KeyOutOfRangeException>(() => SecretBox.CreateDetached(
                Encoding.UTF8.GetBytes("Adam Caudill"),
                Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
                Encoding.UTF8.GetBytes("123456789012345678901234567890")));
        }

        [Test]
        public void CreateDetachedSecretBoxBadNonce()
        {
            Assert.Throws<NonceOutOfRangeException>(() => SecretBox.CreateDetached(
                Encoding.UTF8.GetBytes("Adam Caudill"),
                Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVW"),
                Encoding.UTF8.GetBytes("12345678901234567890123456789012")));
        }

        [Test]
        public void OpenSecretBoxBadKey()
        {
            Assert.Throws<KeyOutOfRangeException>(() => SecretBox.Open(
                Utilities.HexToBinary("00000000000000000000000000000000b58d3c3e5ae78770b7db54e29e3885138a2f1ddb738f2309d9b38164"),
                Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
                Encoding.UTF8.GetBytes("123456789012345678901234567890")));
        }

        [Test]
        public void OpenSecretBoxBadNonce()
        {
            Assert.Throws<NonceOutOfRangeException>(() => SecretBox.Open(
                Utilities.HexToBinary("00000000000000000000000000000000b58d3c3e5ae78770b7db54e29e3885138a2f1ddb738f2309d9b38164"),
                Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVW"),
                Encoding.UTF8.GetBytes("12345678901234567890123456789012")));
        }

        [Test]
        public void OpenDetachedSecretBoxBadKey()
        {
            var actual = SecretBox.CreateDetached(
                Encoding.UTF8.GetBytes("Adam Caudill"),
                Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
                Encoding.UTF8.GetBytes("12345678901234567890123456789012"));

            Assert.Throws<KeyOutOfRangeException>(() => SecretBox.OpenDetached(
                actual.CipherText,
                actual.Mac,
                Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
                Encoding.UTF8.GetBytes("123456789012345678901234567890")));
        }

        [Test]
        public void OpenDetachedSecretBoxBadNonce()
        {
            var actual = SecretBox.CreateDetached(
                Encoding.UTF8.GetBytes("Adam Caudill"),
                Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
                Encoding.UTF8.GetBytes("12345678901234567890123456789012"));

            Assert.Throws<NonceOutOfRangeException>(() => SecretBox.OpenDetached(
                actual.CipherText,
                actual.Mac,
                Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVW"),
                Encoding.UTF8.GetBytes("12345678901234567890123456789012")));
        }

        [Test]
        public void OpenDetachedSecretBoxBadMac()
        {
            var actual = SecretBox.CreateDetached(
                Encoding.UTF8.GetBytes("Adam Caudill"),
                Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
                Encoding.UTF8.GetBytes("12345678901234567890123456789012"));

            Assert.Throws<MacOutOfRangeException>(() => SecretBox.OpenDetached(
                actual.CipherText,
                null,
                Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
                Encoding.UTF8.GetBytes("12345678901234567890123456789012")));
        }
    }
}
