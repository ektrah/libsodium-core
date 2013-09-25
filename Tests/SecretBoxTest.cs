using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Sodium;

namespace Tests
{
  /// <summary>
  /// Tests for the SodiumVersion class
  /// </summary>
  [TestClass()]
  public class SecretBoxTest
  {
    /// <summary>
    /// Does SecretBox.Create() return the expected value?
    /// </summary>
    [TestMethod()]
    public void CreateSecretBox()
    {
      var expected = "00000000000000000000000000000000b58d3c3e5ae78770b7db54e29e3885138a2f1ddb738f2309d9b38164";
      var actual = SecretBox.Create(
        Encoding.ASCII.GetBytes("Adam Caudill"),
        Encoding.ASCII.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
        Encoding.ASCII.GetBytes("12345678901234567890123456789012"));
      Assert.AreEqual(expected, actual);
    }

    /// <summary>
    /// Does SecretBox.open() return the expected value?
    /// </summary>
    [TestMethod()]
    public void OpenSecretBox()
    {
      var expected = "Adam Caudill";
      var actual = Encoding.UTF8.GetString(SecretBox.Open(
        "00000000000000000000000000000000b58d3c3e5ae78770b7db54e29e3885138a2f1ddb738f2309d9b38164",
        Encoding.ASCII.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
        Encoding.ASCII.GetBytes("12345678901234567890123456789012")));
      Assert.AreEqual(expected, actual);
    }
  }
}
