using NUnit.Framework;
using Sodium;

namespace Tests
{
  /// <summary>Tests for the ShortHash class</summary>
  [TestFixture]
  public class ShortHashTest
  {
    /// <summary>Verify that the length of the returned key is correct.</summary>
    [Test]
    public void TestGenerateKey()
    {
      Assert.AreEqual(16, ShortHash.GenerateKey().Length);
    }
    
    /// <summary>Does ShortHash.Hash() return the expected value?</summary>
    [Test]
    public void SimpleShortHash()
    {
      var expected = Utilities.HexToBinary("9ea31f0aa7ebaa82");
      var actual = ShortHash.Hash("Adam Caudill", "0123456789123456");
      CollectionAssert.AreEqual(expected, actual);
    }
  }
}
