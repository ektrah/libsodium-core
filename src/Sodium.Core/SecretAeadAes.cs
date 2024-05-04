using System;
using System.Security.Cryptography;
using System.Threading;
using Sodium.Exceptions;
using static Interop.Libsodium;

namespace Sodium
{
    /// <summary>Authenticated Encryption with Additional Data using AES-GCM.</summary>
    /// <remarks>Only supported on modern x86/x64 processors.</remarks>
    public static class SecretAeadAes
    {
        private const int KEYBYTES = crypto_aead_aes256gcm_KEYBYTES;
        private const int NPUBBYTES = crypto_aead_aes256gcm_NPUBBYTES;
        private const int ABYTES = crypto_aead_aes256gcm_ABYTES;

        private static int s_isAvailable;

        /// <summary>Detect if the current CPU supports the required instructions (SSSE3, aesni, pcmul).</summary>
        /// <returns><c>true</c> if the CPU supports the necessary instructions, otherwise <c>false</c></returns>
        /// <remarks>Use <see cref="SecretAeadChaCha20Poly1305"/> if portability is required.</remarks>
        public static bool IsAvailable
        {
            get
            {
                if (s_isAvailable == 0)
                {
                    SodiumCore.Initialize();
                    Interlocked.Exchange(ref s_isAvailable, crypto_aead_aes256gcm_is_available() != 0 ? 1 : -1);
                }
                return s_isAvailable > 0;
            }
        }

        /// <summary>Generates a random 12 byte nonce.</summary>
        /// <returns>Returns a byte array with 12 random bytes.</returns>
        public static byte[] GenerateNonce()
        {
            return SodiumCore.GetRandomBytes(NPUBBYTES);
        }

        /// <summary>
        /// Encrypts a message with an authentication tag and additional data using AES-GCM.
        /// </summary>
        /// <param name="message">The message to be encrypted.</param>
        /// <param name="nonce">The 12 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <param name="additionalData">The additional data; may be null.</param>
        /// <returns>The encrypted message with additional data.</returns>
        /// <remarks>The nonce should never ever be reused with the same key.</remarks>
        /// <remarks>The recommended way to generate it is to use GenerateNonce() for the first message, and increment it for each subsequent message using the same key.</remarks>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="AdditionalDataOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Encrypt(byte[] message, byte[] nonce, byte[] key, byte[]? additionalData = null)
        {
            if (key == null || key.Length != KEYBYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {KEYBYTES} bytes in length.");
            if (nonce == null || nonce.Length != NPUBBYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {NPUBBYTES} bytes in length.");
            if (!IsAvailable)
                throw new PlatformNotSupportedException("AES-GCM is not supported on this platform. See https://github.com/ektrah/libsodium-core/blob/master/INSTALL.md for more information.");

            additionalData ??= [];

            var cipher = new byte[message.Length + ABYTES];
            ulong cipherLength = 0;

            SodiumCore.Initialize();
            var ret = crypto_aead_aes256gcm_encrypt(cipher, ref cipherLength, message, (ulong)message.Length,
              additionalData, (ulong)additionalData.Length, IntPtr.Zero,
              nonce, key);

            if (ret != 0)
                throw new CryptographicException("Error encrypting message.");

            return cipher;
        }

        /// <summary>
        /// Decrypts a cipher with an authentication tag and additional data using AES-GCM.
        /// </summary>
        /// <param name="cipher">The cipher to be decrypted.</param>
        /// <param name="nonce">The 12 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <param name="additionalData">The additional data; may be null.</param>
        /// <returns>The decrypted cipher.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="AdditionalDataOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Decrypt(byte[] cipher, byte[] nonce, byte[] key, byte[]? additionalData = null)
        {
            if (key == null || key.Length != KEYBYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {KEYBYTES} bytes in length.");
            if (nonce == null || nonce.Length != NPUBBYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {NPUBBYTES} bytes in length.");
            if (!IsAvailable)
                throw new PlatformNotSupportedException("AES-GCM is not supported on this platform. See https://github.com/ektrah/libsodium-core/blob/master/INSTALL.md for more information.");

            if (cipher.Length < ABYTES)
                throw new CryptographicException("Error decrypting message.");

            additionalData ??= [];

            var message = new byte[cipher.Length - ABYTES];
            ulong messageLength = 0;

            SodiumCore.Initialize();
            var ret = crypto_aead_aes256gcm_decrypt(message, ref messageLength, IntPtr.Zero, cipher, (ulong)cipher.Length,
              additionalData, (ulong)additionalData.Length, nonce, key);

            if (ret != 0)
                throw new CryptographicException("Error decrypting message.");

            return message;
        }
    }
}
