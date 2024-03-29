using System.Text;
using static Interop.Libsodium;

namespace Sodium
{
    /// <summary>Provides hashing via selected primitive.</summary>
    public static class CryptoHash
    {
        private const int SHA512_BYTES = crypto_hash_sha512_BYTES;
        private const int SHA256_BYTES = crypto_hash_sha256_BYTES;

        /// <summary>Hashes a string using the default algorithm (This is what you want to use)</summary>
        /// <param name="message">The message.</param>
        /// <returns>Hex-encoded hash.</returns>
        public static byte[] Hash(string message)
        {
            return Hash(Encoding.UTF8.GetBytes(message));
        }

        /// <summary>Hashes a byte array using the default algorithm (This is what you want to use)</summary>
        /// <param name="message">The message.</param>
        /// <returns></returns>
        public static byte[] Hash(byte[] message)
        {
            var buffer = new byte[SHA512_BYTES];

            SodiumCore.Initialize();
            crypto_hash_sha512(buffer, message, (ulong)message.Length);

            return buffer;
        }

        /// <summary>Hashes a string using the SHA512 algorithm</summary>
        /// <param name="message">The message.</param>
        /// <returns>Hex-encoded hash.</returns>
        public static byte[] Sha512(string message)
        {
            return Sha512(Encoding.UTF8.GetBytes(message));
        }

        /// <summary>Hashes a byte array using the SHA512 algorithm</summary>
        /// <param name="message">The message.</param>
        /// <returns></returns>
        public static byte[] Sha512(byte[] message)
        {
            var buffer = new byte[SHA512_BYTES];

            SodiumCore.Initialize();
            crypto_hash_sha512(buffer, message, (ulong)message.Length);

            return buffer;
        }

        /// <summary>Hashes a string using the SHA256 algorithm</summary>
        /// <param name="message">The message.</param>
        /// <returns>Hex-encoded hash.</returns>
        public static byte[] Sha256(string message)
        {
            return Sha256(Encoding.UTF8.GetBytes(message));
        }

        /// <summary>Hashes a byte array using the SHA256 algorithm</summary>
        /// <param name="message">The message.</param>
        /// <returns></returns>
        public static byte[] Sha256(byte[] message)
        {
            var buffer = new byte[SHA256_BYTES];

            SodiumCore.Initialize();
            crypto_hash_sha256(buffer, message, (ulong)message.Length);

            return buffer;
        }
    }
}
