using Sodium;
using NUnit.Framework;

namespace Tests
{
  /// <summary>Tests for the SodiumVersion class</summary>
  [TestFixture]
  public class VersionTest
  {
    /// <summary>A test for SodiumVersionString</summary>
    [Test]
    public void SodiumVersionStringTest()
    {
      const string EXPECTED = "0.7.0";
      var actual = SodiumCore.SodiumVersionString();
      Assert.AreEqual(EXPECTED, actual);
    }
  }
}
