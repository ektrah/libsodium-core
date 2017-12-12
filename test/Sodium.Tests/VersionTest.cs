using NUnit.Framework;
using Sodium;

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
      const string EXPECTED = "1.0.15";
      var actual = SodiumCore.SodiumVersionString();
      Assert.AreEqual(EXPECTED, actual);
    }
  }
}
