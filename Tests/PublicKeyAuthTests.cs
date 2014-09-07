using System.Text;
using Sodium;
using NUnit.Framework;

namespace Tests
{
  /// <summary>Tests for the PublicKeyAuth class</summary>
  [TestFixture]
  public class PublicKeyAuthTest
  {
    /// <summary>Does PublicKeyAuth.GenerateKeyPair() return... something.</summary>
    [Test]
    public void GenerateKeyTest()
    {
      var actual = PublicKeyAuth.GenerateKeyPair();

      //need a better test
      Assert.IsNotNull(actual.PrivateKey);
      Assert.IsNotNull(actual.PublicKey);
    }

    /// <summary>Does PublicKeyAuth.GenerateKeyPair(seed) return the expected value?</summary>
    [Test]
    public void GenerateKeySeedTest()
    {
      var expected = new KeyPair(Utilities.HexToBinary("76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5"),
        Utilities.HexToBinary("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5"));
      var actual = PublicKeyAuth.GenerateKeyPair(Utilities.HexToBinary("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

      CollectionAssert.AreEqual(expected.PublicKey, actual.PublicKey);
      CollectionAssert.AreEqual(expected.PrivateKey, actual.PrivateKey);
    }
    
    /// <summary>Does PublicKeyAuth.Sign() return the expected value?</summary>
    [Test]
    public void SimpleAuthTest()
    {
      var expected = Utilities.HexToBinary("8d5436accbe258a6b252c1140f38d7b8dc6196619945818b72512b6a8019d86dfeeb56f40c4d4b983d97dfeed37948527256c3567d6b253757fcfb32bef56f0b4164616d2043617564696c6c");
      var actual = PublicKeyAuth.Sign(Encoding.UTF8.GetBytes("Adam Caudill"),
        Utilities.HexToBinary("89dff97c131434c11809c3341510ce63c85e851d3ba62e2f810016bbc67d35144ffda13c11d61d2b9568e54bec06ea59368e84874883087645e64e5e9653422e"));
      CollectionAssert.AreEqual(expected, actual);
    }

    /// <summary>Does SecretKeyAuth.Verify() return the expected value?</summary>
    [Test]
    public void SimpleVerifyTest()
    {
      var expected = Encoding.UTF8.GetBytes("Adam Caudill");
      var actual = PublicKeyAuth.Verify(Utilities.HexToBinary("8d5436accbe258a6b252c1140f38d7b8dc6196619945818b72512b6a8019d86dfeeb56f40c4d4b983d97dfeed37948527256c3567d6b253757fcfb32bef56f0b4164616d2043617564696c6c"),
        Utilities.HexToBinary("4ffda13c11d61d2b9568e54bec06ea59368e84874883087645e64e5e9653422e"));
      CollectionAssert.AreEqual(expected, actual);
    }
  }
}
