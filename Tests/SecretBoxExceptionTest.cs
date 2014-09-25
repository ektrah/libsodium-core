using System.Text;
using NUnit.Framework;
using Sodium;
using Sodium.Exceptions;

namespace Tests
{
  /// <summary>Exception tests for the SecretBox class</summary>
  [TestFixture]
  public class SecretBoxExceptionTest
  {
    [Test]
    [ExpectedException(typeof (KeyOutOfRangeException))]
    public void CreateSecretBoxBadKey()
    {
      SecretBox.Create(
        Encoding.UTF8.GetBytes("Adam Caudill"),
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
        Encoding.UTF8.GetBytes("123456789012345678901234567890"));
    }

    [Test]
    [ExpectedException(typeof (NonceOutOfRangeException))]
    public void CreateSecretBoxBadNonce()
    {
      SecretBox.Create(
        Encoding.UTF8.GetBytes("Adam Caudill"),
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVW"),
        Encoding.UTF8.GetBytes("12345678901234567890123456789012"));
    }

    [Test]
    [ExpectedException(typeof (KeyOutOfRangeException))]
    public void CreateDetachedSecretBoxBadKey()
    {
      SecretBox.CreateDetached(
        Encoding.UTF8.GetBytes("Adam Caudill"),
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
        Encoding.UTF8.GetBytes("123456789012345678901234567890"));
    }

    [Test]
    [ExpectedException(typeof (NonceOutOfRangeException))]
    public void CreateDetachedSecretBoxBadNonce()
    {
      SecretBox.CreateDetached(
        Encoding.UTF8.GetBytes("Adam Caudill"),
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVW"),
        Encoding.UTF8.GetBytes("12345678901234567890123456789012"));
    }

    [Test]
    [ExpectedException(typeof (KeyOutOfRangeException))]
    public void OpenSecretBoxBadKey()
    {
      SecretBox.Open(
        Utilities.HexToBinary("00000000000000000000000000000000b58d3c3e5ae78770b7db54e29e3885138a2f1ddb738f2309d9b38164"),
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
        Encoding.UTF8.GetBytes("123456789012345678901234567890"));
    }

    [Test]
    [ExpectedException(typeof (NonceOutOfRangeException))]
    public void OpenSecretBoxBadNonce()
    {
      SecretBox.Open(
        Utilities.HexToBinary("00000000000000000000000000000000b58d3c3e5ae78770b7db54e29e3885138a2f1ddb738f2309d9b38164"),
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVW"),
        Encoding.UTF8.GetBytes("12345678901234567890123456789012"));
    }

    [Test]
    [ExpectedException(typeof (KeyOutOfRangeException))]
    public void OpenDetachedSecretBoxBadKey()
    {
      var actual = SecretBox.CreateDetached(
        Encoding.UTF8.GetBytes("Adam Caudill"),
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
        Encoding.UTF8.GetBytes("12345678901234567890123456789012"));

      SecretBox.OpenDetached(actual.CipherText, actual.Mac,
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
        Encoding.UTF8.GetBytes("123456789012345678901234567890"));
    }

    [Test]
    [ExpectedException(typeof (NonceOutOfRangeException))]
    public void OpenDetachedSecretBoxBadNonce()
    {
      var actual = SecretBox.CreateDetached(
        Encoding.UTF8.GetBytes("Adam Caudill"),
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
        Encoding.UTF8.GetBytes("12345678901234567890123456789012"));

      SecretBox.OpenDetached(actual.CipherText, actual.Mac,
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVW"),
        Encoding.UTF8.GetBytes("12345678901234567890123456789012"));
    }

    [Test]
    [ExpectedException(typeof (MacOutOfRangeException))]
    public void OpenDetachedSecretBoxBadMac()
    {
      var actual = SecretBox.CreateDetached(
        Encoding.UTF8.GetBytes("Adam Caudill"),
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
        Encoding.UTF8.GetBytes("12345678901234567890123456789012"));

      SecretBox.OpenDetached(actual.CipherText, null,
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
        Encoding.UTF8.GetBytes("12345678901234567890123456789012"));
    }
  }
}