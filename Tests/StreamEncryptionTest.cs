using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Sodium;

namespace Tests
{
  /// <summary>
  /// Tests for the StreamEncryption class
  /// </summary>
  [TestClass()]
  public class StreamEncryptionTest
  {
    /// <summary>
    /// Does StreamEncryption.Encrypt() return the expected value?
    /// </summary>
    [TestMethod()]
    public void CreateSecretBox()
    {
      var expected = Utilities.HexToBinary("c7b7f04c00e14b02dd56c78c");
      var actual = StreamEncryption.Encrypt(
        Encoding.ASCII.GetBytes("Adam Caudill"),
        Encoding.ASCII.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
        Encoding.ASCII.GetBytes("12345678901234567890123456789012"));
      CollectionAssert.AreEqual(expected, actual);
    }

    /// <summary>
    /// Does StreamEncryption.Decrypt() return the expected value?
    /// </summary>
    [TestMethod()]
    public void OpenSecretBox()
    {
      var expected = "Adam Caudill";
      var actual = Encoding.UTF8.GetString(StreamEncryption.Decrypt(
        Utilities.HexToBinary("c7b7f04c00e14b02dd56c78c"),
        Encoding.ASCII.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
        Encoding.ASCII.GetBytes("12345678901234567890123456789012")));
      Assert.AreEqual(expected, actual);
    }
  }
}
