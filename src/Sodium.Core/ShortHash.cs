using System.Text;
using Sodium.Exceptions;
using static Interop.Libsodium;

namespace Sodium
{
    /// <summary>Short hash function.</summary>
    public static class ShortHash
    {
        //this was pulled from the headers; should be more dynamic
        private const int BYTES = crypto_shorthash_siphash24_BYTES;
        private const int KEY_BYTES = crypto_shorthash_siphash24_KEYBYTES;

        /// <summary>Generates a random 16 byte key.</summary>
        /// <returns>Returns a byte array with 16 random bytes</returns>
        public static byte[] GenerateKey()
        {
            return SodiumCore.GetRandomBytes(KEY_BYTES);
        }

        /// <summary>Hashes a message, with a key, using the SipHash-2-4 primitive.</summary>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="key">The key; must be 16 bytes.</param>
        /// <returns>Returns 8 byte array.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Hash(string message, string key)
        {
            return Hash(message, Encoding.UTF8.GetBytes(key));
        }

        /// <summary>Hashes a message, with a key, using the SipHash-2-4 primitive.</summary>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="key">The key; must be 16 bytes.</param>
        /// <returns>Returns 8 byte array.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Hash(string message, byte[] key)
        {
            return Hash(Encoding.UTF8.GetBytes(message), key);
        }

        /// <summary>Hashes a message, with a key, using the SipHash-2-4 primitive.</summary>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="key">The key; must be 16 bytes.</param>
        /// <returns>Returns 8 byte array.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Hash(byte[] message, byte[] key)
        {
            if (key == null || key.Length != KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {KEY_BYTES} bytes in length.");

            var buffer = new byte[BYTES];

            SodiumCore.Initialize();
            crypto_shorthash_siphash24(buffer, message, (ulong)message.Length, key);

            return buffer;
        }
    }
}
