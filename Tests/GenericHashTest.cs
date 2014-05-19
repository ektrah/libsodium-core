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
      var actual = GenericHash.Hash(Encoding.ASCII.GetBytes("Adam Caudill"), null, 32);
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
      key = "123456789112345";

      string expected = "62d2997fd7787b8114154dc79e76e53f9f9e3a705aa83f2477555887cc9ba9a3a460674d7e2b999d75e9cc243c105362afd22920aa6c22d7e64cb16c939ea9cb";
      string actual = Utilities.BinaryToHex(GenericHash.HashSaltPersonal ("message", key, salt, personal));

      Assert.AreEqual(expected, actual);
    }
  }
}
