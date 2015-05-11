using System.Text;
using NUnit.Framework;
using Sodium;

namespace Tests
{
    [TestFixture]
    public class SealedBoxTest
    {
        [Test]
        public void CreateAndOpenSealedBoxTest()
        {
            const string message = "Adam Caudill";
            var recipientKeypair = PublicKeyBox.GenerateKeyPair();

            var encrypted = SealedBox.Create(
              Encoding.UTF8.GetBytes(message), recipientKeypair.PublicKey);
            var decrypted = SealedBox.Open(encrypted, recipientKeypair.PrivateKey, recipientKeypair.PublicKey);

            Assert.AreEqual(message, Encoding.UTF8.GetString(decrypted));
        }

        [Test]
        public void CreateAndOpenSealedBoxWithKeyPairTest()
        {
            const string message = "Adam Caudill";
            var recipientKeypair = PublicKeyBox.GenerateKeyPair();

            var encrypted = SealedBox.Create(message, recipientKeypair);
            var decrypted = SealedBox.Open(encrypted, recipientKeypair);

            Assert.AreEqual(message, Encoding.UTF8.GetString(decrypted));
        }
    }
}
