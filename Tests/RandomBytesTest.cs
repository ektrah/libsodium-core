using System.Text;
using Sodium;
using NUnit.Framework;

namespace Tests
{
  /// <summary>
  /// Tests for Random Bytes support
  /// </summary>
  [TestFixture]
  public class RandomBytesTest
  {
    /// <summary>
    /// Does SodiumCore.GetRandomBytes() return something
    /// </summary>
    [Test]
    public void GenerateBytesTest()
    {
      var actual = SodiumCore.GetRandomBytes(24);

      //need a better test
      Assert.IsNotNull(actual);
    }
  }
}
