using System;
using System.Security.Cryptography;
using Sodium.Exceptions;
using static Interop.Libsodium;

namespace Sodium
{
    /// <summary>Authenticated Encryption with Additional Data.</summary>
    public static class SecretAeadChaCha20Poly1305
    {
        private const int KEYBYTES = crypto_aead_chacha20poly1305_KEYBYTES;
        private const int NPUBBYTES = crypto_aead_chacha20poly1305_NPUBBYTES;
        private const int ABYTES = crypto_aead_chacha20poly1305_ABYTES;

        /// <summary>Generates a random 8 byte nonce.</summary>
        /// <returns>Returns a byte array with 8 random bytes.</returns>
        public static byte[] GenerateNonce()
        {
            return SodiumCore.GetRandomBytes(NPUBBYTES);
        }

        /// <summary>
        /// Encrypts a message with an authentication tag and additional data.
        /// </summary>
        /// <param name="message">The message to be encrypted.</param>
        /// <param name="nonce">The 8 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <param name="additionalData">The additional data; may be null, otherwise between 0 and 16 bytes.</param>
        /// <returns>The encrypted message with additional data.</returns>
        /// <remarks>The nonce should never ever be reused with the same key.</remarks>
        /// <remarks>The recommended way to generate it is to use GenerateNonce() for the first message, and increment it for each subsequent message using the same key.</remarks>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="AdditionalDataOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Encrypt(byte[] message, byte[] nonce, byte[] key, byte[]? additionalData = null)
        {
            //additionalData can be null
            if (additionalData == null)
                additionalData = Array.Empty<byte>();

            //validate the length of the key
            if (key == null || key.Length != KEYBYTES)
                throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
                  string.Format("key must be {0} bytes in length.", KEYBYTES));

            //validate the length of the nonce
            if (nonce == null || nonce.Length != NPUBBYTES)
                throw new NonceOutOfRangeException("nonce", (nonce == null) ? 0 : nonce.Length,
                  string.Format("nonce must be {0} bytes in length.", NPUBBYTES));

            //validate the length of the additionalData
            if (additionalData.Length > ABYTES || additionalData.Length < 0)
                throw new AdditionalDataOutOfRangeException(
                  string.Format("additionalData must be between {0} and {1} bytes in length.", 0, ABYTES));

            var cipher = new byte[message.Length + ABYTES];
            ulong cipherLength = 0;

            var ret = crypto_aead_chacha20poly1305_encrypt(cipher, ref cipherLength, message, (ulong)message.Length, additionalData, (ulong)additionalData.Length, IntPtr.Zero,
              nonce, key);

            if (ret != 0)
                throw new CryptographicException("Error encrypting message.");

            return cipher;
        }

        /// <summary>
        /// Decrypts a cipher with an authentication tag and additional data.
        /// </summary>
        /// <param name="cipher">The cipher to be decrypted.</param>
        /// <param name="nonce">The 8 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <param name="additionalData">The additional data; may be null, otherwise between 0 and 16 bytes.</param>
        /// <returns>The decrypted cipher.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="AdditionalDataOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Decrypt(byte[] cipher, byte[] nonce, byte[] key, byte[]? additionalData = null)
        {
            //additionalData can be null
            if (additionalData == null)
                additionalData = Array.Empty<byte>();

            //validate the length of the key
            if (key == null || key.Length != KEYBYTES)
                throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
                  string.Format("key must be {0} bytes in length.", KEYBYTES));

            //validate the length of the nonce
            if (nonce == null || nonce.Length != NPUBBYTES)
                throw new NonceOutOfRangeException("nonce", (nonce == null) ? 0 : nonce.Length,
                  string.Format("nonce must be {0} bytes in length.", NPUBBYTES));

            //validate the length of the additionalData
            if (additionalData.Length > ABYTES || additionalData.Length < 0)
                throw new AdditionalDataOutOfRangeException(
                  string.Format("additionalData must be between {0} and {1} bytes in length.", 0, ABYTES));

            var message = new byte[cipher.Length - ABYTES];
            ulong messageLength = 0;

            var ret = crypto_aead_chacha20poly1305_decrypt(message, ref messageLength, IntPtr.Zero, cipher, (ulong)cipher.Length,
              additionalData, (ulong)additionalData.Length, nonce, key);

            if (ret != 0)
                throw new CryptographicException("Error decrypting message.");

            return message;
        }
    }
}
