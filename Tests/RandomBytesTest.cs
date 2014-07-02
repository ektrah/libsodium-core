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
      byte[] v16, v32, v64;

      v16 = SodiumCore.GetRandomBytes(16);
      v32 = SodiumCore.GetRandomBytes(32);
      v64 = SodiumCore.GetRandomBytes(64);

      Assert.IsNotNull(v16);
      Assert.IsNotNull(v32);
      Assert.IsNotNull(v64);

      Assert.AreEqual(16U, v16.Length);
      Assert.AreEqual(32U, v32.Length);
      Assert.AreEqual(64U, v64.Length);
    }
  }
}
