using System.Text;

namespace Sodium
{
    /// <summary>Provides hashing via selected primitive.</summary>
    public class CryptoHash
    {
        //pulled from various #define statements; may break with new versions
        private const int SHA512_BYTES = 64;
        private const int SHA256_BYTES = 32;

        /// <summary>Hashes a string using the default algorithm (This is what you want to use)</summary>
        /// <param name="message">The message.</param>
        /// <returns>Hex-encoded hash.</returns>
        public static byte[] Hash(string message) => Hash(Encoding.UTF8.GetBytes(message));

        /// <summary>Hashes a byte array using the default algorithm (This is what you want to use)</summary>
        /// <param name="message">The message.</param>
        /// <returns></returns>
        public static byte[] Hash(byte[] message) =>
            ByteBuffer.Use(SHA512_BYTES, buffer => SodiumLibrary.crypto_hash(buffer, message, message.Length));

        /// <summary>Hashes a string using the SHA512 algorithm</summary>
        /// <param name="message">The message.</param>
        /// <returns>Hex-encoded hash.</returns>
        public static byte[] Sha512(string message) => Sha512(Encoding.UTF8.GetBytes(message));

        /// <summary>Hashes a byte array using the SHA512 algorithm</summary>
        /// <param name="message">The message.</param>
        /// <returns></returns>
        public static byte[] Sha512(byte[] message) =>
            ByteBuffer.Use(SHA512_BYTES, buffer => SodiumLibrary.crypto_hash_sha512(buffer, message, message.Length));

        /// <summary>Hashes a string using the SHA256 algorithm</summary>
        /// <param name="message">The message.</param>
        /// <returns>Hex-encoded hash.</returns>
        public static byte[] Sha256(string message) => Sha256(Encoding.UTF8.GetBytes(message));

        /// <summary>Hashes a byte array using the SHA256 algorithm</summary>
        /// <param name="message">The message.</param>
        /// <returns></returns>
        public static byte[] Sha256(byte[] message) =>
            ByteBuffer.Use(SHA256_BYTES, buffer => SodiumLibrary.crypto_hash_sha256(buffer, message, message.Length));
    }
}
