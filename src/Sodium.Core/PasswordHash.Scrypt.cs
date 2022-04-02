using System;
using System.Text;
using Sodium.Exceptions;

namespace Sodium
{
    public static partial class PasswordHash
    {
        private const uint SCRYPT_SALSA208_SHA256_STRBYTES = 102U;
        private const uint SCRYPT_SALSA208_SHA256_SALTBYTES = 32U;

        private const long SCRYPT_OPSLIMIT_INTERACTIVE = 524288;
        private const long SCRYPT_OPSLIMIT_MODERATE = 8388608;
        private const long SCRYPT_OPSLIMIT_MEDIUM = 8388608;
        private const long SCRYPT_OPSLIMIT_SENSITIVE = 33554432;

        private const int SCRYPT_MEMLIMIT_INTERACTIVE = 16777216;
        private const int SCRYPT_MEMLIMIT_MODERATE = 100000000;
        private const int SCRYPT_MEMLIMIT_MEDIUM = 134217728;
        private const int SCRYPT_MEMLIMIT_SENSITIVE = 1073741824;

        /// <summary>Represents predefined and useful limits for ScryptHashBinary() and ScryptHashString().</summary>
        public enum Strength
        {
            /// <summary>For interactive sessions (fast: uses 16MB of RAM).</summary>
            Interactive,
            /// <summary>For normal use (moderate: uses 100MB of RAM).</summary>
            [Obsolete("Use Strength.Medium instead.")]
            Moderate,
            /// <summary>For normal use (moderate: uses 128MB of RAM).</summary>
            Medium,
            /// <summary>For more sensitive use (moderate: uses 128MB of RAM).</summary>
            MediumSlow,
            /// <summary>For highly sensitive data (slow: uses more than 1GB of RAM).</summary>
            Sensitive
        }

        /// <summary>Generates a random 32 byte salt for the Scrypt algorithm.</summary>
        /// <returns>Returns a byte array with 32 random bytes</returns>
        public static byte[] ScryptGenerateSalt()
        {
            return SodiumCore.GetRandomBytes((int)SCRYPT_SALSA208_SHA256_SALTBYTES);
        }

        /// <summary>Derives a secret key of any size from a password and a salt.</summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="limit">The limit for computation.</param>
        /// <param name="outputLength">The length of the computed output array.</param>
        /// <returns>Returns a byte array of the given size.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static byte[] ScryptHashBinary(string password, string salt, Strength limit = Strength.Interactive, long outputLength = SCRYPT_SALSA208_SHA256_SALTBYTES)
        {
            return ScryptHashBinary(Encoding.UTF8.GetBytes(password), Encoding.UTF8.GetBytes(salt), limit, outputLength);
        }

        /// <summary>
        /// Derives a secret key of any size from a password and a salt.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="opsLimit">Represents a maximum amount of computations to perform.</param>
        /// <param name="memLimit">Is the maximum amount of RAM that the function will use, in bytes.</param>
        /// <param name="outputLength">The length of the computed output array.</param>
        /// <returns>Returns a byte array of the given size.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static byte[] ScryptHashBinary(string password, string salt, long opsLimit, int memLimit, long outputLength = SCRYPT_SALSA208_SHA256_SALTBYTES)
        {
            var pass = Encoding.UTF8.GetBytes(password);
            var saltAsBytes = Encoding.UTF8.GetBytes(salt);

            return ScryptHashBinary(pass, saltAsBytes, opsLimit, memLimit, outputLength);
        }

        /// <summary>Derives a secret key of any size from a password and a salt.</summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="limit">The limit for computation.</param>
        /// <param name="outputLength">The length of the computed output array.</param>
        /// <returns>Returns a byte array of the given size.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static byte[] ScryptHashBinary(byte[] password, byte[] salt, Strength limit = Strength.Interactive, long outputLength = SCRYPT_SALSA208_SHA256_SALTBYTES)
        {
            var (opsLimit, memLimit) = GetScryptOpsAndMemoryLimit(limit);

            return ScryptHashBinary(password, salt, opsLimit, memLimit, outputLength);
        }

        /// <summary>
        /// Derives a secret key of any size from a password and a salt.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="opsLimit">Represents a maximum amount of computations to perform.</param>
        /// <param name="memLimit">Is the maximum amount of RAM that the function will use, in bytes.</param>
        /// <param name="outputLength">The length of the computed output array.</param>
        /// <returns>Returns a byte array of the given size.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static byte[] ScryptHashBinary(byte[] password, byte[] salt, long opsLimit, int memLimit, long outputLength = SCRYPT_SALSA208_SHA256_SALTBYTES)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password), "Password cannot be null");

            if (salt == null)
                throw new ArgumentNullException(nameof(salt), "Salt cannot be null");

            if (salt.Length != SCRYPT_SALSA208_SHA256_SALTBYTES)
                throw new SaltOutOfRangeException($"Salt must be {SCRYPT_SALSA208_SHA256_SALTBYTES} bytes in length.");

            if (opsLimit <= 0)
                throw new ArgumentOutOfRangeException(nameof(opsLimit), "opsLimit cannot be zero or negative");

            if (memLimit <= 0)
                throw new ArgumentOutOfRangeException(nameof(memLimit), "memLimit cannot be zero or negative");

            if (outputLength < 16)
                throw new ArgumentOutOfRangeException(nameof(outputLength), "OutputLength cannot be less than 16 bytes");

            var buffer = new byte[outputLength];

            SodiumCore.Init();

            var ret = SodiumLibrary.crypto_pwhash_scryptsalsa208sha256(buffer, buffer.Length, password, password.Length, salt, opsLimit, memLimit);

            if (ret != 0)
                throw new OutOfMemoryException("Internal error, hash failed (usually because the operating system refused to allocate the amount of requested memory).");

            return buffer;
        }

        /// <summary>Returns the hash in a string format, which includes the generated salt.</summary>
        /// <param name="password">The password.</param>
        /// <param name="limit">The limit for computation.</param>
        /// <returns>Returns an zero-terminated ASCII encoded string of the computed password and hash.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static string ScryptHashString(string password, Strength limit = Strength.Interactive)
        {
            var (opsLimit, memLimit) = GetScryptOpsAndMemoryLimit(limit);

            return ScryptHashString(password, opsLimit, memLimit);
        }

        /// <summary>Returns the hash in a string format, which includes the generated salt.</summary>
        /// <param name="password">The password.</param>
        /// <param name="opsLimit">Represents a maximum amount of computations to perform.</param>
        /// <param name="memLimit">Is the maximum amount of RAM that the function will use, in bytes.</param>
        /// <returns>Returns an zero-terminated ASCII encoded string of the computed password and hash.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static string ScryptHashString(string password, long opsLimit, int memLimit)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password), "Password cannot be null");

            if (opsLimit <= 0)
                throw new ArgumentOutOfRangeException(nameof(opsLimit), "opsLimit cannot be zero or negative");

            if (memLimit <= 0)
                throw new ArgumentOutOfRangeException(nameof(memLimit), "memLimit cannot be zero or negative");

            var buffer = new byte[SCRYPT_SALSA208_SHA256_STRBYTES];
            var pass = Encoding.UTF8.GetBytes(password);

            SodiumCore.Init();

            var ret = SodiumLibrary.crypto_pwhash_scryptsalsa208sha256_str(buffer, pass, pass.Length, opsLimit, memLimit);

            if (ret != 0)
            {
                throw new OutOfMemoryException("Internal error, hash failed (usually because the operating system refused to allocate the amount of requested memory).");
            }

            return Utilities.UnsafeAsciiBytesToString(buffer);
        }

        /// <summary>Verifies that a hash generated with ScryptHashString matches the supplied password.</summary>
        /// <param name="hash">The hash.</param>
        /// <param name="password">The password.</param>
        /// <returns><c>true</c> on success; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static bool ScryptHashStringVerify(string hash, string password)
        {
            return ScryptHashStringVerify(Encoding.UTF8.GetBytes(hash), Encoding.UTF8.GetBytes(password));
        }

        /// <summary>Verifies that a hash generated with ScryptHashString matches the supplied password.</summary>
        /// <param name="hash">The hash.</param>
        /// <param name="password">The password.</param>
        /// <returns><c>true</c> on success; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static bool ScryptHashStringVerify(byte[] hash, byte[] password)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password), "Password cannot be null");
            if (hash == null)
                throw new ArgumentNullException(nameof(hash), "Hash cannot be null");

            SodiumCore.Init();

            var ret = SodiumLibrary.crypto_pwhash_scryptsalsa208sha256_str_verify(hash, password, password.Length);

            return ret == 0;
        }

        private static (long opsLimit, int memLimit) GetScryptOpsAndMemoryLimit(Strength limit = Strength.Interactive)
        {
            int memLimit;
            long opsLimit;

            switch (limit)
            {
                case Strength.Interactive:
                    opsLimit = SCRYPT_OPSLIMIT_INTERACTIVE;
                    memLimit = SCRYPT_MEMLIMIT_INTERACTIVE;
                    break;
#pragma warning disable CS0618
                case Strength.Moderate:
#pragma warning restore CS0618
                    opsLimit = SCRYPT_OPSLIMIT_MODERATE;
                    memLimit = SCRYPT_MEMLIMIT_MODERATE;
                    break;
                case Strength.Medium:
                    opsLimit = SCRYPT_OPSLIMIT_MEDIUM;
                    memLimit = SCRYPT_MEMLIMIT_MEDIUM;
                    break;
                case Strength.MediumSlow:
                    //to slow the process down, use the sensitive ops limit
                    opsLimit = SCRYPT_OPSLIMIT_SENSITIVE;
                    memLimit = SCRYPT_MEMLIMIT_MEDIUM;
                    break;
                case Strength.Sensitive:
                    opsLimit = SCRYPT_OPSLIMIT_SENSITIVE;
                    memLimit = SCRYPT_MEMLIMIT_SENSITIVE;
                    break;
                default:
                    opsLimit = SCRYPT_OPSLIMIT_INTERACTIVE;
                    memLimit = SCRYPT_MEMLIMIT_INTERACTIVE;
                    break;
            }

            return (opsLimit, memLimit);
        }
    }
}
