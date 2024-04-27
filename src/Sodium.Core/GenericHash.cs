using System;
using System.Text;
using Sodium.Exceptions;
using static Interop.Libsodium;

namespace Sodium
{
    /// <summary>
    /// Multipurpose hash function.
    /// </summary>
    public static partial class GenericHash
    {
        private const int BYTES_MIN = crypto_generichash_blake2b_BYTES_MIN;
        private const int BYTES_MAX = crypto_generichash_blake2b_BYTES_MAX;
        private const int KEY_BYTES_MIN = crypto_generichash_blake2b_KEYBYTES_MIN;
        private const int KEY_BYTES_MAX = crypto_generichash_blake2b_KEYBYTES_MAX;
        private const int SALT_BYTES = crypto_generichash_blake2b_SALTBYTES;
        private const int PERSONAL_BYTES = crypto_generichash_blake2b_PERSONALBYTES;

        /// <summary>Generates a random 64 byte key.</summary>
        /// <returns>Returns a byte array with 64 random bytes</returns>
        public static byte[] GenerateKey()
        {
            return SodiumCore.GetRandomBytes(KEY_BYTES_MAX);
        }

        /// <summary>Hashes a message, with an optional key, using the BLAKE2b primitive.</summary>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="key">The key; may be null, otherwise between 16 and 64 bytes.</param>
        /// <param name="bytes">The size (in bytes) of the desired result.</param>
        /// <returns>Returns a byte array.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="BytesOutOfRangeException"></exception>
        public static byte[] Hash(string message, string? key, int bytes)
        {
            return Hash(message, key != null ? Encoding.UTF8.GetBytes(key) : null, bytes);
        }

        /// <summary>Hashes a message, with an optional key, using the BLAKE2b primitive.</summary>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="key">The key; may be null, otherwise between 16 and 64 bytes.</param>
        /// <param name="bytes">The size (in bytes) of the desired result.</param>
        /// <returns>Returns a byte array.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="BytesOutOfRangeException"></exception>
        public static byte[] Hash(string message, byte[]? key, int bytes)
        {
            return Hash(Encoding.UTF8.GetBytes(message), key, bytes);
        }

        /// <summary>Hashes a message, with an optional key, using the BLAKE2b primitive.</summary>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="key">The key; may be null, otherwise between 16 and 64 bytes.</param>
        /// <param name="bytes">The size (in bytes) of the desired result.</param>
        /// <returns>Returns a byte array.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="BytesOutOfRangeException"></exception>
        public static byte[] Hash(byte[] message, byte[]? key, int bytes)
        {
            if (key == null)
                key = Array.Empty<byte>();
            else if (key.Length > KEY_BYTES_MAX || key.Length < KEY_BYTES_MIN)
                throw new KeyOutOfRangeException(nameof(key), key.Length, $"key must be between {KEY_BYTES_MIN} and {KEY_BYTES_MAX} bytes in length.");
            if (bytes > BYTES_MAX || bytes < BYTES_MIN)
                throw new BytesOutOfRangeException(nameof(bytes), bytes, $"bytes must be between {BYTES_MIN} and {BYTES_MAX} bytes in length.");

            var buffer = new byte[bytes];

            SodiumCore.Initialize();
            crypto_generichash_blake2b(buffer, (nuint)buffer.Length, message, (nuint)message.Length, key, (nuint)key.Length);

            return buffer;
        }

        /// <summary>Generates a hash based on a key, salt and personal strings</summary>
        /// <returns><c>byte</c> hashed message</returns>
        /// <param name="message">Message.</param>
        /// <param name="key">Key.</param>
        /// <param name="salt">Salt.</param>
        /// <param name="personal">Personal.</param>
        /// <param name="bytes">The size (in bytes) of the desired result.</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="PersonalOutOfRangeException"></exception>
        public static byte[] HashSaltPersonal(string message, string? key, string salt, string personal, int bytes = 64)
        {
            return HashSaltPersonal(Encoding.UTF8.GetBytes(message), key != null ? Encoding.UTF8.GetBytes(key) : null, Encoding.UTF8.GetBytes(salt), Encoding.UTF8.GetBytes(personal), bytes);
        }

        /// <summary>Generates a hash based on a key, salt and personal bytes</summary>
        /// <returns><c>byte</c> hashed message</returns>
        /// <param name="message">Message.</param>
        /// <param name="key">Key.</param>
        /// <param name="salt">Salt.</param>
        /// <param name="personal">Personal string.</param>
        /// <param name="bytes">The size (in bytes) of the desired result.</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="PersonalOutOfRangeException"></exception>
        public static byte[] HashSaltPersonal(byte[] message, byte[]? key, byte[] salt, byte[] personal, int bytes = 64)
        {
            if (message == null)
                throw new ArgumentNullException(nameof(message), "Message cannot be null");
            if (salt == null)
                throw new ArgumentNullException(nameof(salt), "Salt cannot be null");
            if (personal == null)
                throw new ArgumentNullException(nameof(personal), "Personal string cannot be null");
            if (key == null)
                key = Array.Empty<byte>();
            else if (key.Length > KEY_BYTES_MAX || key.Length < KEY_BYTES_MIN)
                throw new KeyOutOfRangeException(nameof(key), key.Length, $"key must be between {KEY_BYTES_MIN} and {KEY_BYTES_MAX} bytes in length.");
            if (salt.Length != SALT_BYTES)
                throw new SaltOutOfRangeException(nameof(salt), salt.Length, $"Salt must be {SALT_BYTES} bytes in length.");
            if (personal.Length != PERSONAL_BYTES)
                throw new PersonalOutOfRangeException(nameof(personal), personal.Length, $"Personal bytes must be {PERSONAL_BYTES} bytes in length.");
            if (bytes > BYTES_MAX || bytes < BYTES_MIN)
                throw new BytesOutOfRangeException(nameof(bytes), bytes, $"bytes must be between {BYTES_MIN} and {BYTES_MAX} bytes in length.");

            var buffer = new byte[bytes];

            SodiumCore.Initialize();
            crypto_generichash_blake2b_salt_personal(buffer, (nuint)buffer.Length, message, (nuint)message.Length, key, (nuint)key.Length, salt, personal);

            return buffer;
        }
    }
}
