using Sodium;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests
{
  /// <summary>
  /// Tests for the CryptoHash class
  /// </summary>
  [TestClass()]
  public class CryptoHashTest
  {
    //SHA512 of "Adam Caudill"
    private const string SHA512_HASH = "be4102c89b6d8af4be54ef72d66a19f49d86e245adb83019118fff716eabd3f27cfc2fa98285d239eb56e70249cffe814e385180caf6b3f7a31a133a34b2aa7e";

    /// <summary>
    /// Does CryptoHash.Hash(string) return the expected value?
    /// </summary>
    [TestMethod()]
    public void CryptoHashStringTest()
    {
      string actual;
      actual = CryptoHash.Hash("Adam Caudill");
      Assert.AreEqual(SHA512_HASH, actual);
    }

    /// <summary>
    /// Does CryptoHash.Hash(byte[]) return the expected value?
    /// </summary>
    [TestMethod()]
    public void CryptoHashArrayTest()
    {
      string actual;
      actual = CryptoHash.Hash(System.Text.Encoding.ASCII.GetBytes("Adam Caudill"));
      Assert.AreEqual(SHA512_HASH, actual);
    }

    /// <summary>
    /// Does CryptoHash.SHA512(string) return the expected value?
    /// </summary>
    [TestMethod()]
    public void CryptoHashSHA512StringTest()
    {
      string actual;
      actual = CryptoHash.SHA512("Adam Caudill");
      Assert.AreEqual(SHA512_HASH, actual);
    }

    /// <summary>
    /// Does CryptoHash.SHA512(byte[]) return the expected value?
    /// </summary>
    [TestMethod()]
    public void CryptoHashSHA512ArrayTest()
    {
      string actual;
      actual = CryptoHash.SHA512(System.Text.Encoding.ASCII.GetBytes("Adam Caudill"));
      Assert.AreEqual(SHA512_HASH, actual);
    }
  }
}
