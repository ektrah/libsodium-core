using System.Text;

using Sodium;
using NUnit.Framework;

namespace Tests
{
  /// <summary>
  /// Tests for the CryptoHash class
  /// </summary>
  [TestFixture]
  public class CryptoHashTest
  {
    //hashes of "Adam Caudill"
    private const string SHA512_HASH = "be4102c89b6d8af4be54ef72d66a19f49d86e245adb83019118fff716eabd3f27cfc2fa98285d239eb56e70249cffe814e385180caf6b3f7a31a133a34b2aa7e";

    private const string SHA256_HASH = "00b7d1c5871ebc343c24114f87434a9af321405606fbde47d33278ed21f2e068";

    /// <summary>
    /// Does CryptoHash.Hash(string) return the expected value?
    /// </summary>
    [Test]
    public void CryptoHashStringTest()
    {
      var actual = CryptoHash.Hash("Adam Caudill");
      CollectionAssert.AreEqual(Utilities.HexToBinary(SHA512_HASH), actual);
    }

    /// <summary>
    /// Does CryptoHash.Hash(byte[]) return the expected value?
    /// </summary>
    [Test]
    public void CryptoHashArrayTest()
    {
      var actual = CryptoHash.Hash(Encoding.UTF8.GetBytes("Adam Caudill"));
      CollectionAssert.AreEqual(Utilities.HexToBinary(SHA512_HASH), actual);
    }

    /// <summary>
    /// Does CryptoHash.SHA512(string) return the expected value?
    /// </summary>
    [Test]
    public void CryptoHashSHA512StringTest()
    {
      var actual = CryptoHash.SHA512("Adam Caudill");
      CollectionAssert.AreEqual(Utilities.HexToBinary(SHA512_HASH), actual);
    }

    /// <summary>
    /// Does CryptoHash.SHA512(byte[]) return the expected value?
    /// </summary>
    [Test]
    public void CryptoHashSHA512ArrayTest()
    {
      var actual = CryptoHash.SHA512(Encoding.UTF8.GetBytes("Adam Caudill"));
      CollectionAssert.AreEqual(Utilities.HexToBinary(SHA512_HASH), actual);
    }

    /// <summary>
    /// Does CryptoHash.SHA256(string) return the expected value?
    /// </summary>
    [Test]
    public void CryptoHashSHA256StringTest()
    {
      var actual = CryptoHash.SHA256("Adam Caudill");
      CollectionAssert.AreEqual(Utilities.HexToBinary(SHA256_HASH), actual);
    }

    /// <summary>
    /// Does CryptoHash.SHA256(byte[]) return the expected value?
    /// </summary>
    [Test]
    public void CryptoHashSHA256ArrayTest()
    {
      var actual = CryptoHash.SHA256(Encoding.UTF8.GetBytes("Adam Caudill"));
      CollectionAssert.AreEqual(Utilities.HexToBinary(SHA256_HASH), actual);
    }
  }
}
