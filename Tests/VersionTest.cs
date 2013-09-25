using Sodium;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

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
      var expected = "0.4.3";
      string actual;
      actual = SodiumVersion.SodiumVersionString();
      Assert.AreEqual(expected, actual);
    }
  }
}
