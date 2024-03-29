using System;
using System.Security.Cryptography;
using System.Text;
using Sodium.Exceptions;
using static Interop.Libsodium;

namespace Sodium
{
    /// <summary>Create and Open Boxes.</summary>
    public static class PublicKeyBox
    {
        private const int PUBLIC_KEY_BYTES = crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES;
        private const int SECRET_KEY_BYTES = crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES;

        private const int NONCE_BYTES = crypto_box_curve25519xsalsa20poly1305_NONCEBYTES;
        private const int MAC_BYTES = crypto_box_curve25519xsalsa20poly1305_MACBYTES;
        private const int SEED_BYTES = crypto_box_curve25519xsalsa20poly1305_SEEDBYTES;

        public static int PublicKeyBytes { get; } = PUBLIC_KEY_BYTES;
        public static int SecretKeyBytes { get; } = SECRET_KEY_BYTES;

        /// <summary>Creates a new key pair based on a random seed.</summary>
        /// <returns>A KeyPair.</returns>
        public static KeyPair GenerateKeyPair()
        {
            var publicKey = new byte[PUBLIC_KEY_BYTES];
            var privateKey = new byte[SECRET_KEY_BYTES];

            SodiumCore.Initialize();
            crypto_box_curve25519xsalsa20poly1305_keypair(publicKey, privateKey);

            return new KeyPair(publicKey, privateKey);
        }

        /// <summary>Creates a new key pair based on the provided private key.</summary>
        /// <param name="privateKey">The private key.</param>
        /// <returns>A KeyPair.</returns>
        /// <exception cref="SeedOutOfRangeException"></exception>
        public static KeyPair GenerateKeyPair(byte[] privateKey)
        {
            if (privateKey == null || privateKey.Length != SECRET_KEY_BYTES)
                throw new SeedOutOfRangeException(nameof(privateKey), privateKey?.Length ?? 0, $"privateKey must be {SECRET_KEY_BYTES} bytes in length.");

            var publicKey = ScalarMult.Base(privateKey);

            return new KeyPair(publicKey, privateKey);
        }

        /// <summary>Creates a new key pair based on the provided seed.</summary>
        /// <param name="seed">Seed data.</param>
        /// <returns>A KeyPair.</returns>
        /// <exception cref="SeedOutOfRangeException"></exception>
        public static KeyPair GenerateSeededKeyPair(byte[] seed)
        {
            if (seed == null || (nuint)seed.Length != SEED_BYTES)
                throw new SeedOutOfRangeException(nameof(seed), seed?.Length ?? 0, $"Key seed must be {SECRET_KEY_BYTES} bytes in length.");

            var publicKey = new byte[PUBLIC_KEY_BYTES];
            var privateKey = new byte[SECRET_KEY_BYTES];

            SodiumCore.Initialize();
            crypto_box_curve25519xsalsa20poly1305_seed_keypair(publicKey, privateKey, seed);

            return new KeyPair(publicKey, privateKey);
        }

        /// <summary>Generates a random 24 byte nonce.</summary>
        /// <returns>Returns a byte array with 24 random bytes</returns>
        public static byte[] GenerateNonce()
        {
            return SodiumCore.GetRandomBytes(NONCE_BYTES);
        }

        /// <summary>Creates a Box</summary>
        /// <param name="message">The message.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="secretKey">The secret key to sign message with.</param>
        /// <param name="publicKey">The recipient's public key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Create(string message, byte[] nonce, byte[] secretKey, byte[] publicKey)
        {
            return Create(Encoding.UTF8.GetBytes(message), nonce, secretKey, publicKey);
        }

        /// <summary>Creates a Box</summary>
        /// <param name="message">The message.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="secretKey">The secret key to sign message with.</param>
        /// <param name="publicKey">The recipient's public key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Create(byte[] message, byte[] nonce, byte[] secretKey, byte[] publicKey)
        {
            if (secretKey == null || secretKey.Length != SECRET_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(secretKey), secretKey?.Length ?? 0, $"key must be {SECRET_KEY_BYTES} bytes in length.");
            if (publicKey == null || publicKey.Length != PUBLIC_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(publicKey), publicKey?.Length ?? 0, $"key must be {PUBLIC_KEY_BYTES} bytes in length.");
            if (nonce == null || nonce.Length != NONCE_BYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {NONCE_BYTES} bytes in length.");

            var buffer = new byte[message.Length + MAC_BYTES];

            SodiumCore.Initialize();
            var ret = crypto_box_easy(buffer, message, (ulong)message.Length, nonce, publicKey, secretKey);

            if (ret != 0)
                throw new CryptographicException("Failed to create PublicKeyBox");

            return buffer;
        }

        /// <summary>Creates detached a Box</summary>
        /// <param name="message">The message.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="secretKey">The secret key to sign message with.</param>
        /// <param name="publicKey">The recipient's public key.</param>
        /// <returns>A detached object with a cipher and a mac.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static DetachedBox CreateDetached(string message, byte[] nonce, byte[] secretKey, byte[] publicKey)
        {
            return CreateDetached(Encoding.UTF8.GetBytes(message), nonce, secretKey, publicKey);
        }

        /// <summary>Creates a detached Box</summary>
        /// <param name="message">The message.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="secretKey">The secret key to sign message with.</param>
        /// <param name="publicKey">The recipient's public key.</param>
        /// <returns>A detached object with a cipher and a mac.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static DetachedBox CreateDetached(byte[] message, byte[] nonce, byte[] secretKey, byte[] publicKey)
        {
            if (secretKey == null || secretKey.Length != SECRET_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(secretKey), secretKey?.Length ?? 0, $"key must be {SECRET_KEY_BYTES} bytes in length.");
            if (publicKey == null || publicKey.Length != PUBLIC_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(publicKey), publicKey?.Length ?? 0, $"key must be {PUBLIC_KEY_BYTES} bytes in length.");
            if (nonce == null || nonce.Length != NONCE_BYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {NONCE_BYTES} bytes in length.");

            var cipher = new byte[message.Length];
            var mac = new byte[MAC_BYTES];

            SodiumCore.Initialize();
            var ret = crypto_box_detached(cipher, mac, message, (ulong)message.Length, nonce, secretKey, publicKey);

            if (ret != 0)
                throw new CryptographicException("Failed to create public detached Box");

            return new DetachedBox(cipher, mac);
        }

        /// <summary>Opens a Box</summary>
        /// <param name="cipherText"></param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="secretKey">The recipient's secret key.</param>
        /// <param name="publicKey">The sender's public key.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Open(byte[] cipherText, byte[] nonce, byte[] secretKey, byte[] publicKey)
        {
            if (secretKey == null || secretKey.Length != SECRET_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(secretKey), secretKey?.Length ?? 0, $"key must be {SECRET_KEY_BYTES} bytes in length.");
            if (publicKey == null || publicKey.Length != PUBLIC_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(publicKey), publicKey?.Length ?? 0, $"key must be {PUBLIC_KEY_BYTES} bytes in length.");
            if (nonce == null || nonce.Length != NONCE_BYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {NONCE_BYTES} bytes in length.");

            if (cipherText.Length < MAC_BYTES)
                throw new CryptographicException("Failed to open PublicKeyBox");

            //check to see if there are MAC_BYTES of leading nulls, if so, trim.
            //this is required due to an error in older versions.
            if (cipherText[0] == 0)
            {
                //check to see if trim is needed
                var trim = true;
                for (var i = 0; i < MAC_BYTES - 1; i++)
                {
                    if (cipherText[i] != 0)
                    {
                        trim = false;
                        break;
                    }
                }

                //if the leading MAC_BYTES are null, trim it off before going on.
                if (trim)
                {
                    var temp = new byte[cipherText.Length - MAC_BYTES];
                    Array.Copy(cipherText, MAC_BYTES, temp, 0, cipherText.Length - MAC_BYTES);

                    cipherText = temp;
                }
            }

            var buffer = new byte[cipherText.Length - MAC_BYTES];

            SodiumCore.Initialize();
            var ret = crypto_box_open_easy(buffer, cipherText, (ulong)cipherText.Length, nonce, publicKey, secretKey);

            if (ret != 0)
                throw new CryptographicException("Failed to open PublicKeyBox");

            return buffer;
        }

        /// <summary>Opens a detached Box</summary>
        /// <param name="cipherText">Hex-encoded string to be opened.</param>
        /// <param name="mac">The 16 byte mac.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="secretKey">The recipient's secret key.</param>
        /// <param name="publicKey">The sender's public key.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="MacOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] OpenDetached(string cipherText, byte[] mac, byte[] nonce, byte[] secretKey, byte[] publicKey)
        {
            return OpenDetached(Utilities.HexToBinary(cipherText), mac, nonce, secretKey, publicKey);
        }

        /// <summary>Opens a detached Box</summary>
        /// <param name="detached">A detached object.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="secretKey">The recipient's secret key.</param>
        /// <param name="publicKey">The sender's public key.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="MacOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] OpenDetached(DetachedBox detached, byte[] nonce, byte[] secretKey, byte[] publicKey)
        {
            return OpenDetached(detached.CipherText, detached.Mac, nonce, secretKey, publicKey);
        }

        /// <summary>Opens a detached Box</summary>
        /// <param name="cipherText">The cipherText.</param>
        /// <param name="mac">The 16 byte mac.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="secretKey">The recipient's secret key.</param>
        /// <param name="publicKey">The sender's public key.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="MacOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] OpenDetached(byte[] cipherText, byte[] mac, byte[] nonce, byte[] secretKey, byte[] publicKey)
        {
            if (secretKey == null || secretKey.Length != SECRET_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(secretKey), secretKey?.Length ?? 0, $"key must be {SECRET_KEY_BYTES} bytes in length.");
            if (publicKey == null || publicKey.Length != PUBLIC_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(publicKey), publicKey?.Length ?? 0, $"key must be {PUBLIC_KEY_BYTES} bytes in length.");
            if (mac == null || mac.Length != MAC_BYTES)
                throw new MacOutOfRangeException(nameof(mac), mac?.Length ?? 0, $"mac must be {MAC_BYTES} bytes in length.");
            if (nonce == null || nonce.Length != NONCE_BYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {NONCE_BYTES} bytes in length.");

            var buffer = new byte[cipherText.Length];

            SodiumCore.Initialize();
            var ret = crypto_box_open_detached(buffer, cipherText, mac, (ulong)cipherText.Length, nonce, secretKey, publicKey);

            if (ret != 0)
                throw new CryptographicException("Failed to open public detached Box");

            return buffer;
        }
    }
}
