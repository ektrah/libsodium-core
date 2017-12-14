using System.Text;
using NUnit.Framework;

namespace Sodium.Tests
{
    /// <summary>Tests for the SecretAeadXChaCha20Poly1305 class</summary>
    [TestFixture]
    public class SecretAeadXChaCha20Poly1305Test
    {
        /// <summary>Test Authenticated Encryption with Additional Data</summary>
        /// <remarks>Binary source from: https://github.com/jedisct1/libsodium/blob/master/test/default/aead_xchacha20poly1305.c</remarks>
        [Test]
        public void AeadWithAdditionalDataTest()
        {
            var key = new byte[]
            {
                0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
                0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91,
                0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a,
                0x9b, 0x9c, 0x9d, 0x9e, 0x9f
            };

            var nonce = new byte[]
            {
                0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                0x48, 0x49, 0x4a, 0x4b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };

            var ad = new byte[]
            {
                0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7
            };

            var m = Encoding.UTF8.GetBytes("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");

            var encrypted = SecretAeadXChaCha20Poly1305.Encrypt(m, nonce, key, ad);
            var decrypted = SecretAeadXChaCha20Poly1305.Decrypt(encrypted, nonce, key, ad);

            CollectionAssert.AreEqual(m, decrypted);
        }

        [Test]
        public void AeadWithoutAdditionalDataTest()
        {
            var key = new byte[]
            {
                0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
                0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91,
                0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a,
                0x9b, 0x9c, 0x9d, 0x9e, 0x9f
            };

            var nonce = new byte[]
            {
                0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                0x48, 0x49, 0x4a, 0x4b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };

            var m = Encoding.UTF8.GetBytes("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");

            var encrypted = SecretAeadXChaCha20Poly1305.Encrypt(m, nonce, key);
            var decrypted = SecretAeadXChaCha20Poly1305.Decrypt(encrypted, nonce, key);

            CollectionAssert.AreEqual(m, decrypted);
        }
    }
}
