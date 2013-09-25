using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Sodium;

namespace Tests
{
  /// <summary>
  /// Tests for the SodiumVersion class
  /// </summary>
  [TestClass()]
  public class GenericHashTest
  {

    /// <summary>
    /// BLAKE2b, 32 bytes, no key
    /// </summary>
    [TestMethod()]
    public void GenericHashNoKey()
    {
      var expected = "53e27925e5786abe74e6bb7004980a6a38a8da2478efa1b6b2ae73964cfe4876";
      string actual;
      actual = GenericHash.Hash(Encoding.ASCII.GetBytes("Adam Caudill"), null, 32);
      Assert.AreEqual(expected, actual);
    }

    /// <summary>
    /// BLAKE2b, 32 bytes, with key
    /// </summary>
    [TestMethod()]
    public void GenericHashWithKey()
    {
      var expected = "8866267f985204ae511980704ac85ec4936ee535c37541f342976b2cb3ac62fd";
      string actual;
      actual = GenericHash.Hash("Adam Caudill", "This is a test key", 32);
      Assert.AreEqual(expected, actual);
    }
  }
}
