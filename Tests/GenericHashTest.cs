using System.Text;
using Sodium;
using NUnit.Framework;

namespace Tests
{
  /// <summary>
  /// Tests for the GenericHash class
  /// </summary>
  [TestFixture]
  public class GenericHashTest
  {
    /// <summary>
    /// Verify that the length of the returned key is correct.
    /// </summary>
    [Test]
    public void TestGenerateKey()
    {
      Assert.AreEqual(64, GenericHash.GenerateKey().Length);
    }
    
    /// <summary>
    /// BLAKE2b, 32 bytes, no key
    /// </summary>
    [Test]
    public void GenericHashNoKey()
    {
      var expected = Utilities.HexToBinary("53e27925e5786abe74e6bb7004980a6a38a8da2478efa1b6b2ae73964cfe4876");
      var actual = GenericHash.Hash(Encoding.UTF8.GetBytes("Adam Caudill"), null, 32);
      CollectionAssert.AreEqual(expected, actual);
    }

    /// <summary>
    /// BLAKE2b, 32 bytes, with key
    /// </summary>
    [Test]
    public void GenericHashWithKey()
    {
      var expected = Utilities.HexToBinary("8866267f985204ae511980704ac85ec4936ee535c37541f342976b2cb3ac62fd");
      var actual = GenericHash.Hash("Adam Caudill", "This is a test key", 32);
      CollectionAssert.AreEqual(expected, actual);
    }

    /// <summary>
    /// Generics the hash salt personal.
    /// </summary>
    [Test]
    public void GenericHashSaltPersonal()
    {
      string salt, personal, key;

      salt = "5b6b41ed9b343fe0";
      personal = "5126fb2a37400d2a";
      key = "1234567891123456";

      //Changed BinaryToHex from upper to lower
      //string expected = "2A4ED94ED58EB8D099F52A5EBED051648CC34F29DCCD0F25B215E28672B28DE8F86A4666D60456EA93E25C5F1FBEC1387D861E2B9AB498169A2AD2DA3649F84B";
      string expected = "2a4ed94ed58eb8d099f52a5ebed051648cc34f29dccd0f25b215e28672b28de8f86a4666d60456ea93e25c5f1fbec1387d861e2b9ab498169a2ad2da3649f84b";
      string actual = Utilities.BinaryToHex(GenericHash.HashSaltPersonal ("message", key, salt, personal));

      Assert.AreEqual(expected, actual);
    }
  }
}
