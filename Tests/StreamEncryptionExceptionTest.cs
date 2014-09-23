using System.Text;
using Sodium;
using NUnit.Framework;
using System.Security.Cryptography;

namespace Tests
{
    /// <summary>Exception tests for the StreamEncryption class</summary>
  [TestFixture]
  public class StreamEncryptionExceptionTest
  {
      [Test]
      [ExpectedException(typeof(KeyOutOfRangeException))]
      public void StreamEncryptionEncryptBadKey()
      {
          StreamEncryption.Encrypt(
            Encoding.UTF8.GetBytes("Adam Caudill"),
            Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
            Encoding.UTF8.GetBytes("123456789012345678901234567890"));
      }

      [Test]
      [ExpectedException(typeof(NonceOutOfRangeException))]
      public void StreamEncryptionEncryptBadNonce()
      {
          StreamEncryption.Encrypt(
            Encoding.UTF8.GetBytes("Adam Caudill"),
            Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVW"),
            Encoding.UTF8.GetBytes("12345678901234567890123456789012"));
      }

      [Test]
      [ExpectedException(typeof(KeyOutOfRangeException))]
      public void StreamEncryptionDecryptBadKey()
      {
          StreamEncryption.Decrypt(
            Utilities.HexToBinary("c7b7f04c00e14b02dd56c78c"),
            Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
            Encoding.UTF8.GetBytes("123456789012345678901234567890"));
      }

      [Test]
      [ExpectedException(typeof(NonceOutOfRangeException))]
      public void StreamEncryptionDecryptBadNonce()
      {
          StreamEncryption.Decrypt(
            Utilities.HexToBinary("c7b7f04c00e14b02dd56c78c"),
            Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVW"),
            Encoding.UTF8.GetBytes("12345678901234567890123456789012"));
      }

      [Test]
      [ExpectedException(typeof(CryptographicException))]
      public void StreamEncryptionEncryptBadCrypto()
      {
          //TODO: implement
          throw new CryptographicException();
      }

      [Test]
      [ExpectedException(typeof(CryptographicException))]
      public void StreamEncryptionDecryptBadCrypto()
      {
          //TODO: implement
          throw new CryptographicException();
      }

      [Test]
      [ExpectedException(typeof(KeyOutOfRangeException))]
      public void StreamEncryptionEncryptChaCha20BadKey()
      {
          StreamEncryption.EncryptChaCha20(
          Encoding.UTF8.GetBytes("Adam Caudill"),
          Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP"),
          Encoding.UTF8.GetBytes("123456789012345678901234567890"));
      }

      [Test]
      [ExpectedException(typeof(NonceOutOfRangeException))]
      public void StreamEncryptionEncryptChaCha20BadNonce()
      {
          StreamEncryption.EncryptChaCha20(
          Encoding.UTF8.GetBytes("Adam Caudill"),
          Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMN"),
          Encoding.UTF8.GetBytes("12345678901234567890123456789012"));
      }

      [Test]
      [ExpectedException(typeof(KeyOutOfRangeException))]
      public void StreamEncryptionDecryptChaCha20BadKey()
      {
          StreamEncryption.DecryptChaCha20(
          Utilities.HexToBinary("a6ce598d8b865fb328581bcd"),
          Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP"),
          Encoding.UTF8.GetBytes("123456789012345678901234567890"));
      }

      [Test]
      [ExpectedException(typeof(NonceOutOfRangeException))]
      public void StreamEncryptionDecryptChaCha20BadNonce()
      {
          StreamEncryption.DecryptChaCha20(
          Utilities.HexToBinary("a6ce598d8b865fb328581bcd"),
          Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNO"),
          Encoding.UTF8.GetBytes("12345678901234567890123456789012"));
      }

      [Test]
      [ExpectedException(typeof(CryptographicException))]
      public void StreamEncryptionEncryptChaCha20BadCrypto()
      {
          //TODO: implement
          throw new CryptographicException();
      }

      [Test]
      [ExpectedException(typeof(CryptographicException))]
      public void StreamEncryptionDecryptChaCha20BadCrypto()
      {
          //TODO: implement
          throw new CryptographicException();
      }
  }
}
