using Microsoft.VisualStudio.TestTools.UnitTesting;
using Sodium;

namespace Tests
{
  /// <summary>
  /// Tests for the SodiumVersion class
  /// </summary>
  [TestClass()]
  public class VersionTest
  {
    /// <summary>
    /// A test for SodiumVersionString
    /// </summary>
    [TestMethod()]
    public void SodiumVersionStringTest()
    {
      const string EXPECTED = "0.4.3";
      var actual = SodiumCore.SodiumVersionString();
      Assert.AreEqual(EXPECTED, actual);
    }
  }
}
