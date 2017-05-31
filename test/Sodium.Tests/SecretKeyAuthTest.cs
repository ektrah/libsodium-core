using System.Text;
using NUnit.Framework;
using Sodium;

namespace Tests
{
  /// <summary>Tests for the SecretKeyAuth class</summary>
  [TestFixture]
  public class SecretKeyAuthTest
  {
    /// <summary>Verify that the length of the returned key is correct.</summary>
    [Test]
    public void TestGenerateKey()
    {
      Assert.AreEqual(32, SecretKeyAuth.GenerateKey().Length);
    }

    /// <summary>Does SecretKeyAuth.Sign() return the expected value?</summary>
    [Test]
    public void SimpleAuthTest()
    {
      var expected = Utilities.HexToBinary("9f44681a662b7cde80c4eb34db5102b62a8b482272e3cceef73a334ec1d321c0");
      var actual = SecretKeyAuth.Sign(Encoding.UTF8.GetBytes("Adam Caudill"), 
        Encoding.UTF8.GetBytes("01234567890123456789012345678901"));
      CollectionAssert.AreEqual(expected, actual);
    }

    /// <summary>Does SecretKeyAuth.SignHmacSha256() return the expected value?</summary>
    [Test]
    public void SimpleAuthHmacSha256Test()
    {
      var expected = Utilities.HexToBinary("1cc0012cfd200becfce64bba779025d02cb349d203e15d44a308e4249e2b7245");
      var actual = SecretKeyAuth.SignHmacSha256(Encoding.UTF8.GetBytes("Adam Caudill"), 
        Encoding.UTF8.GetBytes("01234567890123456789012345678901"));
      CollectionAssert.AreEqual(expected, actual);
    }

    /// <summary>Does SecretKeyAuth.SignHmacSha512() return the expected value?</summary>
    [Test]
    public void SimpleAuthHmacSha512Test()
    {
      var expected = Utilities.HexToBinary("9f44681a662b7cde80c4eb34db5102b62a8b482272e3cceef73a334ec1d321c06a99b828e2ff921b4d1304bbd9480adfacf8c4c2ffbcbb4e5663446fda1235d2");
      var actual = SecretKeyAuth.SignHmacSha512(Encoding.UTF8.GetBytes("Adam Caudill"), 
        Encoding.UTF8.GetBytes("01234567890123456789012345678901"));
      CollectionAssert.AreEqual(expected, actual);
    }

    /// <summary>Does SecretKeyAuth.Verify() return the expected value?</summary>
    [Test]
    public void SimpleVerifyTest()
    {
      var actual = SecretKeyAuth.Verify(Encoding.UTF8.GetBytes("Adam Caudill"),
        Utilities.HexToBinary("9f44681a662b7cde80c4eb34db5102b62a8b482272e3cceef73a334ec1d321c0"),
        Encoding.UTF8.GetBytes("01234567890123456789012345678901"));
      Assert.AreEqual(true, actual);
    }

    /// <summary>Does SecretKeyAuth.VerifyHmacSha256() return the expected value?</summary>
    [Test]
    public void SimpleVerifyHmacSha256Test()
    {
      var actual = SecretKeyAuth.VerifyHmacSha256(Encoding.UTF8.GetBytes("Adam Caudill"),
        Utilities.HexToBinary("1cc0012cfd200becfce64bba779025d02cb349d203e15d44a308e4249e2b7245"),
        Encoding.UTF8.GetBytes("01234567890123456789012345678901"));
      Assert.AreEqual(true, actual);
    }

    /// <summary>Does SecretKeyAuth.VerifyHmacSha512() return the expected value?</summary>
    [Test]
    public void SimpleVerifyHmacSha512Test()
    {
      var actual = SecretKeyAuth.VerifyHmacSha512(Encoding.UTF8.GetBytes("Adam Caudill"),
        Utilities.HexToBinary("9f44681a662b7cde80c4eb34db5102b62a8b482272e3cceef73a334ec1d321c06a99b828e2ff921b4d1304bbd9480adfacf8c4c2ffbcbb4e5663446fda1235d2"),
        Encoding.UTF8.GetBytes("01234567890123456789012345678901"));
      Assert.AreEqual(true, actual);
    }
  }
}
