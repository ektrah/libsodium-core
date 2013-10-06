using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Sodium;

namespace Tests
{
  /// <summary>
  /// Tests for the SecretKeyAuth class
  /// </summary>
  [TestClass()]
  public class SecretKeyAuthTest
  {
    /// <summary>
    /// Verify that the length of the returned key is correct.
    /// </summary>
    [TestMethod()]
    public void TestGenerateKey()
    {
      Assert.AreEqual(32, SecretKeyAuth.GenerateKey().Length);
    }
    
    /// <summary>
    /// Does SecretKeyAuth.Sign() return the expected value?
    /// </summary>
    [TestMethod()]
    public void SimpleAuthTest()
    {
      var expected = Utilities.HexToBinary("9f44681a662b7cde80c4eb34db5102b62a8b482272e3cceef73a334ec1d321c0");
      var actual = SecretKeyAuth.Sign(Encoding.UTF8.GetBytes("Adam Caudill"), Encoding.UTF8.GetBytes("01234567890123456789012345678901"));
      CollectionAssert.AreEqual(expected, actual);
    }

    /// <summary>
    /// Does SecretKeyAuth.Verify() return the expected value?
    /// </summary>
    [TestMethod()]
    public void SimpleVerifyTest()
    {
      var actual = SecretKeyAuth.Verify(Encoding.UTF8.GetBytes("Adam Caudill"),
        Utilities.HexToBinary("9f44681a662b7cde80c4eb34db5102b62a8b482272e3cceef73a334ec1d321c0"),
        Encoding.UTF8.GetBytes("01234567890123456789012345678901"));
      Assert.AreEqual(true, actual);
    }
  }
}
