using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Sodium.Exceptions;

namespace Sodium
{
    /// <summary>Authenticated Encryption with Additional Data.</summary>
    public static class SecretAeadChaCha20Poly1305IETF
    {
        private const int KEYBYTES = 32;
        private const int NPUBBYTES = 8;
        private const int ABYTES = 16;

        //TODO: we could implement a method which increments the nonce.

        /// <summary>Generates a random 8 byte nonce.</summary>
        /// <returns>Returns a byte array with 8 random bytes.</returns>
        public static byte[] GenerateNonce() => SodiumCore.GetRandomBytes(NPUBBYTES);

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
        public static byte[] Encrypt(byte[] message, byte[] nonce, byte[] key, byte[] additionalData = null)
        {
            //additionalData can be null
            if (additionalData == null)
                additionalData = new byte[0x00];

            //validate the length of the key
            if (key == null || key.Length != KEYBYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {KEYBYTES} bytes in length.");

            //validate the length of the nonce
            if (nonce == null || nonce.Length != NPUBBYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {NPUBBYTES} bytes in length.");

            //validate the length of the additionalData
            if (additionalData.Length > ABYTES || additionalData.Length < 0)
                throw new AdditionalDataOutOfRangeException($"additionalData must be between {0} and {ABYTES} bytes in length.");

            var cipher = ByteBuffer.Create(message.Length + ABYTES);
            var bin = Marshal.AllocHGlobal(cipher.Length);

            var ret = SodiumLibrary.crypto_aead_chacha20poly1305_ietf_encrypt(bin, out var cipherLength, message, message.Length, additionalData, additionalData.Length, null, nonce, key);

            Marshal.Copy(bin, cipher, 0, (int)cipherLength);
            Marshal.FreeHGlobal(bin);

            if (ret != 0)
                throw new CryptographicException("Error encrypting message.");

            return cipher.Length == cipherLength ? cipher : ByteBuffer.Slice(cipher, 0, cipherLength);
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
        public static byte[] Decrypt(byte[] cipher, byte[] nonce, byte[] key, byte[] additionalData = null)
        {
            //additionalData can be null
            if (additionalData == null)
                additionalData = new byte[0x00];

            //validate the length of the key
            if (key == null || key.Length != KEYBYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {KEYBYTES} bytes in length.");

            //validate the length of the nonce
            if (nonce == null || nonce.Length != NPUBBYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {NPUBBYTES} bytes in length.");

            //validate the length of the additionalData
            if (additionalData.Length > ABYTES || additionalData.Length < 0)
                throw new AdditionalDataOutOfRangeException($"additionalData must be between {0} and {ABYTES} bytes in length.");

            var message = ByteBuffer.Create(cipher.Length - ABYTES);
            var bin = Marshal.AllocHGlobal(message.Length);

            var ret = SodiumLibrary.crypto_aead_chacha20poly1305_ietf_decrypt(bin, out var messageLength, null, cipher, cipher.Length, additionalData, additionalData.Length, nonce, key);

            Marshal.Copy(bin, message, 0, (int)messageLength);
            Marshal.FreeHGlobal(bin);

            if (ret != 0)
                throw new CryptographicException("Error decrypting message.");

            return message.Length == messageLength ? message : ByteBuffer.Slice(message, 0, messageLength);
        }
    }
}
