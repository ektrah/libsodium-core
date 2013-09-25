using Sodium;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests
{
  /// <summary>
  /// Tests for the SodiumVersion class
  /// </summary>
  [TestClass()]
  public class CryptoHashTest
  {

    /// <summary>
    /// A test for SodiumVersionString
    /// </summary>
    [TestMethod()]
    public void BasicCryptoHashTest()
    {
      var expected = "be4102c89b6d8af4be54ef72d66a19f49d86e245adb83019118fff716eabd3f27cfc2fa98285d239eb56e70249cffe814e385180caf6b3f7a31a133a34b2aa7e";
      string actual;
      actual = CryptoHash.Hash("Adam Caudill");
      Assert.AreEqual(expected, actual);
    }
  }
}
