using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Sodium;

namespace Tests
{
  /// <summary>
  /// Tests for Random Bytes support
  /// </summary>
  [TestClass()]
  public class RandomBytesTest
  {
    /// <summary>
    /// Does SodiumCore.GetRandomBytes() return something
    /// </summary>
    [TestMethod()]
    public void GenerateBytesTest()
    {
      var actual = SodiumCore.GetRandomBytes(24);

      //need a better test
      Assert.IsNotNull(actual);
    }
  }
}
