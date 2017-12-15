using System;
using System.Text;
using Sodium.Exceptions;

namespace Sodium
{
    /// <summary>
    /// Multipurpose hash function.
    /// </summary>
    public partial class GenericHash
    {
        //this was pulled from the headers; should be more dynamic
        private const int BYTES_MIN = 16;
        private const int BYTES_MAX = 64;
        private const int KEY_BYTES_MIN = 16;
        private const int KEY_BYTES_MAX = 64;
        private const int OUT_BYTES = 64;
        private const int SALT_BYTES = 16;
        private const int PERSONAL_BYTES = 16;

        /// <summary>Generates a random 64 byte key.</summary>
        /// <returns>Returns a byte array with 64 random bytes</returns>
        public static byte[] GenerateKey() => SodiumCore.GetRandomBytes(KEY_BYTES_MAX);

        /// <summary>Hashes a message, with an optional key, using the BLAKE2b primitive.</summary>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="key">The key; may be null, otherwise between 16 and 64 bytes.</param>
        /// <param name="bytes">The size (in bytes) of the desired result.</param>
        /// <returns>Returns a byte array.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="BytesOutOfRangeException"></exception>
        public static byte[] Hash(string message, string key, int bytes) => Hash(message, Encoding.UTF8.GetBytes(key), bytes);

        /// <summary>Hashes a message, with an optional key, using the BLAKE2b primitive.</summary>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="key">The key; may be null, otherwise between 16 and 64 bytes.</param>
        /// <param name="bytes">The size (in bytes) of the desired result.</param>
        /// <returns>Returns a byte array.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="BytesOutOfRangeException"></exception>
        public static byte[] Hash(string message, byte[] key, int bytes) => Hash(Encoding.UTF8.GetBytes(message), key, bytes);

        /// <summary>Hashes a message, with an optional key, using the BLAKE2b primitive.</summary>
        /// <param name="message">The message to be hashed.</param>
        /// <param name="key">The key; may be null, otherwise between 16 and 64 bytes.</param>
        /// <param name="bytes">The size (in bytes) of the desired result.</param>
        /// <returns>Returns a byte array.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="BytesOutOfRangeException"></exception>
        public static byte[] Hash(byte[] message, byte[] key, int bytes)
        {
            //validate the length of the key
            int keyLength;
            if (key != null)
            {
                if (key.Length > KEY_BYTES_MAX || key.Length < KEY_BYTES_MIN)
                    throw new KeyOutOfRangeException($"key must be between {KEY_BYTES_MIN} and {KEY_BYTES_MAX} bytes in length.");

                keyLength = key.Length;
            }
            else
            {
                key = new byte[0];
                keyLength = 0;
            }

            //validate output length
            if (bytes > BYTES_MAX || bytes < BYTES_MIN)
                throw new BytesOutOfRangeException(nameof(bytes), bytes, $"bytes must be between {BYTES_MIN} and {BYTES_MAX} bytes in length.");

            var buffer = new byte[bytes];
            SodiumLibrary.crypto_generichash(buffer, buffer.Length, message, message.Length, key, keyLength);

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
        public static byte[] HashSaltPersonal(string message, string key, string salt, string personal, int bytes = OUT_BYTES) =>
            HashSaltPersonal(Encoding.UTF8.GetBytes(message), Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(salt), Encoding.UTF8.GetBytes(personal), bytes);

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
        public static byte[] HashSaltPersonal(byte[] message, byte[] key, byte[] salt, byte[] personal, int bytes = OUT_BYTES)
        {
            if (message == null)
                throw new ArgumentNullException(nameof(message), "Message cannot be null");

            if (salt == null)
                throw new ArgumentNullException(nameof(salt), "Salt cannot be null");

            if (personal == null)
                throw new ArgumentNullException(nameof(personal), "Personal string cannot be null");

            if (key != null && (key.Length > KEY_BYTES_MAX || key.Length < KEY_BYTES_MIN))
                throw new KeyOutOfRangeException($"key must be between {KEY_BYTES_MIN} and {KEY_BYTES_MAX} bytes in length.");

            if (key == null)
                key = new byte[0];

            if (salt.Length != SALT_BYTES)
                throw new SaltOutOfRangeException($"Salt must be {SALT_BYTES} bytes in length.");

            if (personal.Length != PERSONAL_BYTES)
                throw new PersonalOutOfRangeException($"Personal bytes must be {PERSONAL_BYTES} bytes in length.");

            //validate output length
            if (bytes > BYTES_MAX || bytes < BYTES_MIN)
                throw new BytesOutOfRangeException(nameof(bytes), bytes, $"bytes must be between {BYTES_MIN} and {BYTES_MAX} bytes in length.");

            var buffer = new byte[bytes];
            SodiumLibrary.crypto_generichash_blake2b_salt_personal(buffer, buffer.Length, message, message.Length, key, key.Length, salt, personal);

            return buffer;
        }
    }
}
