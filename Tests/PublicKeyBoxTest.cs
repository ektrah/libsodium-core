using System.Text;
using Sodium;
using NUnit.Framework;

namespace Tests
{
  /// <summary>
  /// Tests for the PublicKeyBox class
  /// </summary>
  [TestFixture]
  public class PublicKeyBoxTest
  {
    // Test Key 1:
    //  Public Key: 753cb95919b15b76654b1969c554a4aaf8334402ef1468cb40a602b9c9fd2c13
    //  Private Key: 2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975
    //
    // Test Key 2:
    //  Public Key: 83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645
    //  Private Key: d4c8438482d5d103a2315251a5eed7c46017864a02ddc4c8b03f0ede8cb3ef9b
    
    /// <summary>
    /// Does PublicKeyBox.GenerateKeyPair() return... something.
    /// </summary>
    [Test]
    public void GenerateKeyTest()
    {
      var actual = PublicKeyBox.GenerateKeyPair();

      //need a better test
      Assert.IsNotNull(actual.PrivateKey);
      Assert.IsNotNull(actual.PublicKey);
    }

    /// <summary>
    /// Does PublicKeyBox.Sign() return the expected value?
    /// </summary>
    [Test]
    public void SimpleAuthTest()
    {
      var expected = Utilities.HexToBinary("00000000000000000000000000000000aed04284c55860ad0f6379f235cc2cb8c32aba7a811b35cfac94f64d");
      var actual = PublicKeyBox.Create(
        Encoding.UTF8.GetBytes("Adam Caudill"),
        Encoding.ASCII.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
        Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975"),
        Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645"));
      CollectionAssert.AreEqual(expected, actual);
    }

    /// <summary>
    /// Does PublicKeyBox.Verify() return the expected value?
    /// </summary>
    [Test]
    public void SimpleVerifyTest()
    {
      var expected = Encoding.UTF8.GetBytes("Adam Caudill");
      var actual = PublicKeyBox.Open(
        Utilities.HexToBinary("00000000000000000000000000000000aed04284c55860ad0f6379f235cc2cb8c32aba7a811b35cfac94f64d"),
        Encoding.ASCII.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
        Utilities.HexToBinary("d4c8438482d5d103a2315251a5eed7c46017864a02ddc4c8b03f0ede8cb3ef9b"),
        Utilities.HexToBinary("753cb95919b15b76654b1969c554a4aaf8334402ef1468cb40a602b9c9fd2c13"));
      CollectionAssert.AreEqual(expected, actual);
    }
  }
}
