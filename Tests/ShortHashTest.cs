using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Sodium;

namespace Tests
{
  /// <summary>
  /// Tests for the ShortHash class
  /// </summary>
  [TestClass()]
  public class ShortHashTest
  {
    /// <summary>
    /// Verify that the length of the returned key is correct.
    /// </summary>
    [TestMethod()]
    public void TestGenerateKey()
    {
      Assert.AreEqual(16, ShortHash.GenerateKey().Length);
    }
    
    /// <summary>
    /// Does ShortHash.Hash() return the expected value?
    /// </summary>
    [TestMethod()]
    public void SimpleShortHash()
    {
      var expected = Utilities.HexToBinary("9ea31f0aa7ebaa82");
      var actual = ShortHash.Hash("Adam Caudill", "0123456789123456");
      CollectionAssert.AreEqual(expected, actual);
    }
  }
}
