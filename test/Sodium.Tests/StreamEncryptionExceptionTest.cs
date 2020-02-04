using System.Security.Cryptography;
using System.Text;

using NUnit.Framework;

using Sodium;
using Sodium.Exceptions;

namespace Tests
{
    /// <summary>Exception tests for the StreamEncryption class</summary>
    [TestFixture]
    public class StreamEncryptionExceptionTest
    {
        [Test]
        public void StreamEncryptionEncryptBadKey()
        {
            Assert.Throws<KeyOutOfRangeException>(() =>
            {
                StreamEncryption.Encrypt(
            Encoding.UTF8.GetBytes("Adam Caudill"),
            Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
            Encoding.UTF8.GetBytes("123456789012345678901234567890"));
            });

        }

        [Test]
        public void StreamEncryptionEncryptBadNonce()
        {
            Assert.Throws<NonceOutOfRangeException>(() =>
            {
                StreamEncryption.Encrypt(
            Encoding.UTF8.GetBytes("Adam Caudill"),
            Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVW"),
            Encoding.UTF8.GetBytes("12345678901234567890123456789012"));
            });

        }

        [Test]
        public void StreamEncryptionDecryptBadKey()
        {
            Assert.Throws<KeyOutOfRangeException>(() =>
            {
                StreamEncryption.Decrypt(
            Utilities.HexToBinary("c7b7f04c00e14b02dd56c78c"),
            Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
            Encoding.UTF8.GetBytes("123456789012345678901234567890"));
            });

        }

        [Test]
        public void StreamEncryptionDecryptBadNonce()
        {
            Assert.Throws<NonceOutOfRangeException>(() =>
            {
                StreamEncryption.Decrypt(
            Utilities.HexToBinary("c7b7f04c00e14b02dd56c78c"),
            Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVW"),
            Encoding.UTF8.GetBytes("12345678901234567890123456789012"));
            });

        }

        [Test, Ignore("not implemented")]
        public void StreamEncryptionEncryptBadCrypto()
        {
            //TODO: implement
            Assert.Throws<CryptographicException>(() =>
            {

            });
        }

        [Test, Ignore("not implemented")]
        public void StreamEncryptionDecryptBadCrypto()
        {
            //TODO: implement
            Assert.Throws<CryptographicException>(() =>
            {

            });
        }

        [Test]
        public void StreamEncryptionEncryptChaCha20BadKey()
        {
            Assert.Throws<KeyOutOfRangeException>(() =>
            {
                StreamEncryption.EncryptChaCha20(
            Encoding.UTF8.GetBytes("Adam Caudill"),
            Encoding.UTF8.GetBytes("ABCDEFGH"),
            Encoding.UTF8.GetBytes("123456789012345678901234567890"));
            });

        }

        [Test]
        public void StreamEncryptionEncryptChaCha20BadNonce()
        {
            Assert.Throws<NonceOutOfRangeException>(() =>
            {
                StreamEncryption.EncryptChaCha20(
            Encoding.UTF8.GetBytes("Adam Caudill"),
            Encoding.UTF8.GetBytes("ABC"),
            Encoding.UTF8.GetBytes("12345678901234567890123456789012"));
            });

        }

        [Test]
        public void StreamEncryptionDecryptChaCha20BadKey()
        {
            Assert.Throws<KeyOutOfRangeException>(() =>
            {
                StreamEncryption.DecryptChaCha20(
            Utilities.HexToBinary("a6ce598d8b865fb328581bcd"),
            Encoding.UTF8.GetBytes("ABCDEFGH"),
            Encoding.UTF8.GetBytes("123456789012345678901234567890"));
            });

        }

        [Test]
        public void StreamEncryptionDecryptChaCha20BadNonce()
        {
            Assert.Throws<NonceOutOfRangeException>(() =>
            {
                StreamEncryption.DecryptChaCha20(
            Utilities.HexToBinary("a6ce598d8b865fb328581bcd"),
            Encoding.UTF8.GetBytes("ABC"),
            Encoding.UTF8.GetBytes("12345678901234567890123456789012"));
            });
        }

        [Test, Ignore("not implemented")]
        public void StreamEncryptionEncryptChaCha20BadCrypto()
        {
            //TODO: implement
            Assert.Throws<CryptographicException>(() =>
            {

            });
        }

        [Test, Ignore("not implemented")]
        public void StreamEncryptionDecryptChaCha20BadCrypto()
        {
            //TODO: implement
            Assert.Throws<CryptographicException>(() =>
            {

            });
        }
    }
}