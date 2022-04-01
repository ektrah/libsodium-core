using System.Security.Cryptography;
using System.Text;
using NUnit.Framework;
using Sodium;
using Sodium.Exceptions;

namespace Tests
{
    /// <summary>Exception tests for the PublicKeyAuth class</summary>
    [TestFixture]
    public class PublicKeyAuthExceptionTest
    {
        [Test]
        public void GenerateKeyPairWithBadSeed()
        {
            //Don`t copy bobSk for other tests (bad key)!
            //30 byte
            var bobSk = new byte[] {
        0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
        0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
        0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
        0x1c,0x2f,0x8b,0x27,0xff,0x88
      };

            Assert.Throws<SeedOutOfRangeException>(
              () => PublicKeyAuth.GenerateKeyPair(bobSk));
        }

        [Test]
        public void SignAuthBadKey()
        {
            //Don`t copy bobSk for other tests (bad key)!
            //30 byte
            var bobSk = new byte[] {
        0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
        0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
        0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
        0x1c,0x2f,0x8b,0x27,0xff,0x88
      };
            var message = Encoding.UTF8.GetBytes("Adam Caudill");

            Assert.Throws<KeyOutOfRangeException>(
              () => PublicKeyAuth.Sign(message, bobSk));
        }

        [Test]
        public void VerifyAuthBadKey()
        {
            //Don`t copy bobSk for other tests (bad key)!
            //30 byte
            var bobSk = new byte[] {
        0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
        0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
        0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
        0x1c,0x2f,0x8b,0x27,0xff,0x88
      };
            var message = Encoding.UTF8.GetBytes("Adam Caudill");

            Assert.Throws<KeyOutOfRangeException>(
              () => PublicKeyAuth.Verify(message, bobSk));
        }

        [Test]
        public void VerifyAuthWrongKey()
        {
            //Don`t copy bobSk for other tests (bad key)!
            //30 byte
            var bobSk = new byte[] {
        0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
        0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
        0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
        0x1c,0x2f,0x8b,0x27,0xff,0x88,0x88,0x88
      };
            var message = Encoding.UTF8.GetBytes("Adam Caudill");

            //It`s not really signed ...
            Assert.Throws<CryptographicException>(
              () => PublicKeyAuth.Verify(message, bobSk));
        }

        [Test]
        public void SignAuthDetachedBadKey()
        {
            //Don`t copy bobSk for other tests (bad key)!
            //30 byte
            var bobSk = new byte[] {
        0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
        0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
        0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
        0x1c,0x2f,0x8b,0x27,0xff,0x88
      };
            var message = Encoding.UTF8.GetBytes("Adam Caudill");

            Assert.Throws<KeyOutOfRangeException>(
              () => PublicKeyAuth.SignDetached(message, bobSk));
        }

        [Test]
        public void VerifyAuthDetachedBadKey()
        {
            //Don`t copy bobSk for other tests (bad key)!
            //30 byte
            var bobSk = new byte[] {
        0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
        0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
        0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
        0x1c,0x2f,0x8b,0x27,0xff,0x88
      };
            var signature = Utilities.HexToBinary("8d5436accbe258a6b252c1140f38d7b8dc6196619945818b72512b6a8019d86dfeeb56f40c4d4b983d97dfeed37948527256c3567d6b253757fcfb32bef56f0b");
            var message = Encoding.UTF8.GetBytes("Adam Caudill");

            Assert.Throws<KeyOutOfRangeException>(
              () => PublicKeyAuth.VerifyDetached(signature, message, bobSk));
        }

        [Test]
        public void VerifyAuthDetachedBadSignature()
        {
            var signature = Utilities.HexToBinary("5436accbe258a6b252c1140f38d7b8dc6196619945818b72512b6a8019d86dfeeb56f40c4d4b983d97dfeed37948527256c3567d6b253757fcfb32bef56f0b");
            var message = Encoding.UTF8.GetBytes("Adam Caudill");
            var key = Utilities.HexToBinary("4ffda13c11d61d2b9568e54bec06ea59368e84874883087645e64e5e9653422e");
            Assert.Throws<SignatureOutOfRangeException>(
              () => PublicKeyAuth.VerifyDetached(signature, message, key));
        }

        [Test]
        public void ConvertEd25519PublicKeyToCurve25519PublicKeyBadKey()
        {
            //Don`t copy keypairSeed for other tests (bad key)!
            //30 byte
            var keypairSeed = new byte[]{
        0x42, 0x11, 0x51, 0xa4, 0x59, 0xfa, 0xea, 0xde,
        0x3d, 0x24, 0x71, 0x15, 0xf9, 0x4a, 0xed, 0xae,
        0x42, 0x31, 0x81, 0x24, 0x09, 0x5a, 0xfa, 0xbe,
        0x4d, 0x14, 0x51, 0xa5, 0x59, 0xfa
      };

            Assert.Throws<KeyOutOfRangeException>(
              () => PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(keypairSeed));
        }

        [Test, Ignore("not implemented")]
        public void ConvertEd25519PublicKeyToCurve25519PublicKeyWrongKey()
        {
            //TODO: implement
            Assert.Throws<CryptographicException>(() =>
            {

            });
        }

        [Test]
        public void ConvertEd25519SecretKeyToCurve25519SecretKeyBadKey()
        {
            //Don`t copy keypairSeed for other tests (bad key)!
            //62 byte
            var keypairSeed = new byte[]{
        0x42, 0x11, 0x51, 0xa4, 0x59, 0xfa, 0xea, 0xde,
        0x3d, 0x24, 0x71, 0x15, 0xf9, 0x4a, 0xed, 0xae,
        0x42, 0x31, 0x81, 0x24, 0x09, 0x5a, 0xfa, 0xbe,
        0x4d, 0x14, 0x51, 0xa5, 0x59, 0xfa, 0xea, 0xde,
        0x42, 0x11, 0x51, 0xa4, 0x59, 0xfa, 0xea, 0xde,
        0x3d, 0x24, 0x71, 0x15, 0xf9, 0x4a, 0xed, 0xae,
        0x42, 0x31, 0x81, 0x24, 0x09, 0x5a, 0xfa, 0xbe,
        0x4d, 0x14, 0x51, 0xa5, 0x59, 0xfa
      };

            Assert.Throws<KeyOutOfRangeException>(
              () => PublicKeyAuth.ConvertEd25519SecretKeyToCurve25519SecretKey(keypairSeed));
        }

        [Test, Ignore("not implemented")]
        public void ConvertEd25519SecretKeyToCurve25519SecretKeyWrongKey()
        {
            //TODO: implement
            Assert.Throws<CryptographicException>(() =>
            {

            });
        }
    }
}
