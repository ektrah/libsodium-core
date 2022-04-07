using System.Text;
using Sodium.Exceptions;
using static Interop.Libsodium;

namespace Sodium
{
    /// <summary>One Time Message Authentication</summary>
    public static class SecretKeyAuth
    {
        private const int KEY_BYTES = crypto_auth_hmacsha512256_KEYBYTES;
        private const int BYTES = crypto_auth_hmacsha512256_BYTES;

        private const int CRYPTO_AUTH_HMACSHA256_KEY_BYTES = crypto_auth_hmacsha256_KEYBYTES;
        private const int CRYPTO_AUTH_HMACSHA256_BYTES = crypto_auth_hmacsha256_BYTES;

        private const int CRYPTO_AUTH_HMACSHA512_KEY_BYTES = crypto_auth_hmacsha512_KEYBYTES;
        private const int CRYPTO_AUTH_HMACSHA512_BYTES = crypto_auth_hmacsha512_BYTES;

        /// <summary>Generates a random 32 byte key.</summary>
        /// <returns>Returns a byte array with 32 random bytes</returns>
        public static byte[] GenerateKey()
        {
            return SodiumCore.GetRandomBytes(KEY_BYTES);
        }

        /// <summary>Signs a message with HMAC-SHA512-256.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>32 byte authentication code.</returns>
        public static byte[] Sign(string message, byte[] key)
        {
            return Sign(Encoding.UTF8.GetBytes(message), key);
        }

        /// <summary>Signs a message with HMAC-SHA512-256.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>32 byte authentication code.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Sign(byte[] message, byte[] key)
        {
            if (key == null || key.Length != KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {KEY_BYTES} bytes in length.");

            var buffer = new byte[BYTES];

            SodiumCore.Initialize();
            crypto_auth_hmacsha512256(buffer, message, (ulong)message.Length, key);

            return buffer;
        }

        /// <summary>Verifies a message signed with the Sign method.</summary>
        /// <param name="message">The message.</param>
        /// <param name="signature">The 32 byte signature.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>True if verified.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        public static bool Verify(string message, byte[] signature, byte[] key)
        {
            return Verify(Encoding.UTF8.GetBytes(message), signature, key);
        }

        /// <summary>Verifies a message signed with the Sign method.</summary>
        /// <param name="message">The message.</param>
        /// <param name="signature">The 32 byte signature.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>True if verified.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        public static bool Verify(byte[] message, byte[] signature, byte[] key)
        {
            if (key == null || key.Length != KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {KEY_BYTES} bytes in length.");
            if (signature == null || signature.Length != BYTES)
                throw new SignatureOutOfRangeException(nameof(signature), signature?.Length ?? 0, $"signature must be {BYTES} bytes in length.");

            SodiumCore.Initialize();
            var ret = crypto_auth_hmacsha512256_verify(signature, message, (ulong)message.Length, key);

            return ret == 0;
        }

        /// <summary>Signs a message with HMAC-SHA-256.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>32 byte authentication code.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] SignHmacSha256(byte[] message, byte[] key)
        {
            if (key == null || key.Length != CRYPTO_AUTH_HMACSHA256_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {CRYPTO_AUTH_HMACSHA256_KEY_BYTES} bytes in length.");

            var buffer = new byte[CRYPTO_AUTH_HMACSHA256_BYTES];

            SodiumCore.Initialize();
            crypto_auth_hmacsha256(buffer, message, (ulong)message.Length, key);

            return buffer;
        }

        /// <summary>Signs a message with HMAC-SHA-256.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>32 byte authentication code.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] SignHmacSha256(string message, byte[] key)
        {
            return SignHmacSha256(Encoding.UTF8.GetBytes(message), key);
        }

        /// <summary>Signs a message with HMAC-SHA-512.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>64 byte authentication code.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] SignHmacSha512(byte[] message, byte[] key)
        {
            if (key == null || key.Length != CRYPTO_AUTH_HMACSHA512_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {CRYPTO_AUTH_HMACSHA512_KEY_BYTES} bytes in length.");

            var buffer = new byte[CRYPTO_AUTH_HMACSHA512_BYTES];

            SodiumCore.Initialize();
            crypto_auth_hmacsha512(buffer, message, (ulong)message.Length, key);

            return buffer;
        }

        /// <summary>Signs a message with HMAC-SHA-512.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>64 byte authentication code.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] SignHmacSha512(string message, byte[] key)
        {
            return SignHmacSha512(Encoding.UTF8.GetBytes(message), key);
        }

        /// <summary>Verifies a message signed with the SignHmacSha256 method.</summary>
        /// <param name="message">The message.</param>
        /// <param name="signature">The 32 byte signature.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>True if verified.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        public static bool VerifyHmacSha256(string message, byte[] signature, byte[] key)
        {
            return VerifyHmacSha256(Encoding.UTF8.GetBytes(message), signature, key);
        }

        /// <summary>Verifies a message signed with the SignHmacSha256 method.</summary>
        /// <param name="message">The message.</param>
        /// <param name="signature">The 32 byte signature.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>True if verified.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        public static bool VerifyHmacSha256(byte[] message, byte[] signature, byte[] key)
        {
            if (key == null || key.Length != CRYPTO_AUTH_HMACSHA256_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {CRYPTO_AUTH_HMACSHA256_KEY_BYTES} bytes in length.");
            if (signature == null || signature.Length != CRYPTO_AUTH_HMACSHA256_BYTES)
                throw new SignatureOutOfRangeException(nameof(signature), signature?.Length ?? 0, $"signature must be {CRYPTO_AUTH_HMACSHA256_BYTES} bytes in length.");

            SodiumCore.Initialize();
            var ret = crypto_auth_hmacsha256_verify(signature, message, (ulong)message.Length, key);

            return ret == 0;
        }

        /// <summary>Verifies a message signed with the SignHmacSha512 method.</summary>
        /// <param name="message">The message.</param>
        /// <param name="signature">The 64 byte signature.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>True if verified.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        public static bool VerifyHmacSha512(string message, byte[] signature, byte[] key)
        {
            return VerifyHmacSha512(Encoding.UTF8.GetBytes(message), signature, key);
        }

        /// <summary>Verifies a message signed with the SignHmacSha512 method.</summary>
        /// <param name="message">The message.</param>
        /// <param name="signature">The 64 byte signature.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>True if verified.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        public static bool VerifyHmacSha512(byte[] message, byte[] signature, byte[] key)
        {
            if (key == null || key.Length != CRYPTO_AUTH_HMACSHA512_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {CRYPTO_AUTH_HMACSHA512_KEY_BYTES} bytes in length.");
            if (signature == null || signature.Length != CRYPTO_AUTH_HMACSHA512_BYTES)
                throw new SignatureOutOfRangeException(nameof(signature), signature?.Length ?? 0, $"signature must be {CRYPTO_AUTH_HMACSHA512_BYTES} bytes in length.");

            SodiumCore.Initialize();
            var ret = crypto_auth_hmacsha512_verify(signature, message, (ulong)message.Length, key);

            return ret == 0;
        }
    }
}
