using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Sodium;

namespace Tests
{
  /// <summary>
  /// Tests for the PublicKeyAuth class
  /// </summary>
  [TestClass()]
  public class PublicKeyAuthTest
  {
    /// <summary>
    /// Does PublicKeyAuth.GenerateKeyPair() return... something.
    /// </summary>
    [TestMethod()]
    public void GenerateKeyTest()
    {
      var actual = PublicKeyAuth.GenerateKeyPair();

      //need a better test
      Assert.IsNotNull(actual.PrivateKey);
      Assert.IsNotNull(actual.PublicKey);
    }
    
    /// <summary>
    /// Does PublicKeyAuth.Sign() return the expected value?
    /// </summary>
    [TestMethod()]
    public void SimpleAuthTest()
    {
      var expected = Utilities.HexToBinary("8d5436accbe258a6b252c1140f38d7b8dc6196619945818b72512b6a8019d86dfeeb56f40c4d4b983d97dfeed37948527256c3567d6b253757fcfb32bef56f0b4164616d2043617564696c6c");
      var actual = PublicKeyAuth.Sign(Encoding.UTF8.GetBytes("Adam Caudill"),
        Utilities.HexToBinary("89dff97c131434c11809c3341510ce63c85e851d3ba62e2f810016bbc67d35144ffda13c11d61d2b9568e54bec06ea59368e84874883087645e64e5e9653422e"));
      CollectionAssert.AreEqual(expected, actual);
    }

    /// <summary>
    /// Does SecretKeyAuth.Verify() return the expected value?
    /// </summary>
    [TestMethod()]
    public void SimpleVerifyTest()
    {
      var expected = Encoding.UTF8.GetBytes("Adam Caudill");
      var actual = PublicKeyAuth.Verify(Utilities.HexToBinary("8d5436accbe258a6b252c1140f38d7b8dc6196619945818b72512b6a8019d86dfeeb56f40c4d4b983d97dfeed37948527256c3567d6b253757fcfb32bef56f0b4164616d2043617564696c6c"),
        Utilities.HexToBinary("4ffda13c11d61d2b9568e54bec06ea59368e84874883087645e64e5e9653422e"));
      CollectionAssert.AreEqual(expected, actual);
    }
  }
}
