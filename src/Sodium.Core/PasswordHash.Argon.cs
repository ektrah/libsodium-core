using System;
using System.Text;
using Sodium.Exceptions;
using static Interop.Libsodium;

namespace Sodium
{
    public static partial class PasswordHash
    {
        private const int ARGON_STRBYTES = crypto_pwhash_argon2id_STRBYTES;
        private const int ARGON_SALTBYTES = crypto_pwhash_argon2id_SALTBYTES;

        private const long ARGON_OPSLIMIT_INTERACTIVE = 4;
        private const long ARGON_OPSLIMIT_MEDIUM = 4;
        private const long ARGON_OPSLIMIT_MODERATE = 6;
        private const long ARGON_OPSLIMIT_SENSITIVE = 8;

        private const int ARGON_MEMLIMIT_INTERACTIVE = 33554432;
        private const int ARGON_MEMLIMIT_MEDIUM = 67108864;
        private const int ARGON_MEMLIMIT_MODERATE = 134217728;
        private const int ARGON_MEMLIMIT_SENSITIVE = 536870912;

        /// <summary>Represents available Argon algorithms</summary>
        public enum ArgonAlgorithm
        {
            /// <summary>2I13, default Argon algorithm</summary>
            Argon_2I13 = crypto_pwhash_argon2i_ALG_ARGON2I13,
            /// <summary>2ID13 Argon algorithm</summary>
            Argon_2ID13 = crypto_pwhash_argon2id_ALG_ARGON2ID13,
        }

        /// <summary>Represents predefined and useful limits for ArgonHashBinary() and ArgonHashString().</summary>
        public enum StrengthArgon
        {
            /// <summary>For interactive sessions (fast: uses 32MB of RAM).</summary>
            Interactive,
            /// <summary>For medium use (medium: uses 64MB of RAM)</summary>
            Medium,
            /// <summary>For normal use (moderate: uses 128MB of RAM).</summary>
            Moderate,
            /// <summary>For highly sensitive data (slow: uses 512MB of RAM).</summary>
            Sensitive
        }

        /// <summary>Generates a random 16 byte salt for the Argon2i algorithm.</summary>
        /// <returns>Returns a byte array with 16 random bytes</returns>
        public static byte[] ArgonGenerateSalt()
        {
            return SodiumCore.GetRandomBytes(ARGON_SALTBYTES);
        }

        /// <summary>Derives a secret key of any size from a password and a salt.</summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="limit">The limit for computation.</param>
        /// <param name="outputLength">The length of the computed output array.</param>
        /// <param name="alg">Argon Algorithm</param>
        /// <returns>Returns a byte array of the given size.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static byte[] ArgonHashBinary(string password, string salt, StrengthArgon limit = StrengthArgon.Interactive, long outputLength = ARGON_SALTBYTES,
          ArgonAlgorithm alg = ArgonAlgorithm.Argon_2I13)
        {
            return ArgonHashBinary(Encoding.UTF8.GetBytes(password), Encoding.UTF8.GetBytes(salt), limit, outputLength, alg);
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
        public static byte[] ArgonHashBinary(string password, string salt, long opsLimit, int memLimit, long outputLength = ARGON_SALTBYTES,
          ArgonAlgorithm alg = ArgonAlgorithm.Argon_2I13)
        {
            return ArgonHashBinary(Encoding.UTF8.GetBytes(password), Encoding.UTF8.GetBytes(salt), opsLimit, memLimit, outputLength, alg);
        }

        /// <summary>Derives a secret key of any size from a password and a salt.</summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="limit">The limit for computation.</param>
        /// <param name="outputLength">The length of the computed output array.</param>
        /// <param name="alg">Argon Algorithm</param>
        /// <returns>Returns a byte array of the given size.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static byte[] ArgonHashBinary(byte[] password, byte[] salt, StrengthArgon limit = StrengthArgon.Interactive, long outputLength = ARGON_SALTBYTES,
          ArgonAlgorithm alg = ArgonAlgorithm.Argon_2I13)
        {
            var (opsLimit, memLimit) = GetArgonOpsAndMemoryLimit(limit);

            return ArgonHashBinary(password, salt, opsLimit, memLimit, outputLength, alg);
        }

        /// <summary>
        /// Derives a secret key of any size from a password and a salt.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="opsLimit">Represents a maximum amount of computations to perform.</param>
        /// <param name="memLimit">Is the maximum amount of RAM that the function will use, in bytes.</param>
        /// <param name="outputLength">The length of the computed output array.</param>
        /// <param name="alg">Argon Algorithm</param>
        /// <returns>Returns a byte array of the given size.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static byte[] ArgonHashBinary(byte[] password, byte[] salt, long opsLimit, int memLimit, long outputLength = ARGON_SALTBYTES,
          ArgonAlgorithm alg = ArgonAlgorithm.Argon_2I13)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password), "Password cannot be null");

            if (salt == null)
                throw new ArgumentNullException(nameof(salt), "Salt cannot be null");

            if (salt.Length != ARGON_SALTBYTES)
                throw new SaltOutOfRangeException($"Salt must be {ARGON_SALTBYTES} bytes in length.");

            if (opsLimit < 3)
                throw new ArgumentOutOfRangeException(nameof(opsLimit), "opsLimit the number of passes, has to be at least 3");

            if (memLimit <= 0)
                throw new ArgumentOutOfRangeException(nameof(memLimit), "memLimit cannot be zero or negative");

            if (outputLength <= 0)
                throw new ArgumentOutOfRangeException(nameof(outputLength), "OutputLength cannot be zero or negative");

            var buffer = new byte[outputLength];

            SodiumCore.Initialize();
            var ret = crypto_pwhash(buffer, (ulong)buffer.Length, password, (ulong)password.Length, salt, (ulong)opsLimit, (nuint)memLimit, (int)alg);

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
        public static string ArgonHashString(string password, StrengthArgon limit = StrengthArgon.Interactive)
        {
            var (opsLimit, memLimit) = GetArgonOpsAndMemoryLimit(limit);

            return ArgonHashString(password, opsLimit, memLimit);
        }

        /// <summary>Returns the hash in a string format, which includes the generated salt.</summary>
        /// <param name="password">The password.</param>
        /// <param name="opsLimit">Represents a maximum amount of computations to perform.</param>
        /// <param name="memLimit">Is the maximum amount of RAM that the function will use, in bytes.</param>
        /// <returns>Returns an zero-terminated ASCII encoded string of the computed password and hash.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static string ArgonHashString(string password, long opsLimit, int memLimit)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password), "Password cannot be null");

            if (opsLimit < 3)
                throw new ArgumentOutOfRangeException(nameof(opsLimit), "opsLimit the number of passes, has to be at least 3");

            if (memLimit <= 0)
                throw new ArgumentOutOfRangeException(nameof(memLimit), "memLimit cannot be zero or negative");

            var buffer = new byte[ARGON_STRBYTES];
            var pass = Encoding.UTF8.GetBytes(password);

            SodiumCore.Initialize();
            var ret = crypto_pwhash_str(buffer, pass, (ulong)pass.Length, (ulong)opsLimit, (nuint)memLimit);

            if (ret != 0)
            {
                throw new OutOfMemoryException("Internal error, hash failed (usually because the operating system refused to allocate the amount of requested memory).");
            }

            return Encoding.UTF8.GetString(buffer, 0, Array.IndexOf<byte>(buffer, 0));
        }

        /// <summary>Verifies that a hash generated with ArgonHashString matches the supplied password.</summary>
        /// <param name="hash">The hash.</param>
        /// <param name="password">The password.</param>
        /// <returns><c>true</c> on success; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static bool ArgonHashStringVerify(string hash, string password)
        {
            return ArgonHashStringVerify(Encoding.UTF8.GetBytes(hash), Encoding.UTF8.GetBytes(password));
        }

        /// <summary>Verifies that a hash generated with ArgonHashString matches the supplied password.</summary>
        /// <param name="hash">The hash.</param>
        /// <param name="password">The password.</param>
        /// <returns><c>true</c> on success; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static bool ArgonHashStringVerify(byte[] hash, byte[] password)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password), "Password cannot be null");
            if (hash == null)
                throw new ArgumentNullException(nameof(hash), "Hash cannot be null");
            if (hash.Length >= ARGON_STRBYTES)
                throw new ArgumentOutOfRangeException(nameof(hash), "Hash is invalid");

            var buffer = new byte[ARGON_STRBYTES];
            Array.Copy(hash, buffer, hash.Length);

            SodiumCore.Initialize();
            var ret = crypto_pwhash_str_verify(buffer, password, (ulong)password.Length);

            return ret == 0;
        }

        public static bool ArgonPasswordNeedsRehash(string hash, StrengthArgon limit = StrengthArgon.Interactive)
        {
            return ArgonPasswordNeedsRehash(Encoding.UTF8.GetBytes(hash), limit);
        }

        public static bool ArgonPasswordNeedsRehash(string hash, long opsLimit, int memLimit)
        {
            return ArgonPasswordNeedsRehash(Encoding.UTF8.GetBytes(hash), opsLimit, memLimit);
        }

        public static bool ArgonPasswordNeedsRehash(byte[] hash, StrengthArgon limit = StrengthArgon.Interactive)
        {
            var (opsLimit, memLimit) = GetArgonOpsAndMemoryLimit(limit);

            return ArgonPasswordNeedsRehash(hash, opsLimit, memLimit);
        }

        /// <summary>
        /// Checks if the current password hash needs rehashing
        /// </summary>
        /// <param name="password">Password that needs rehashing</param>
        /// <param name="opsLimit"></param>
        /// <param name="memLimit"></param>
        /// <returns></returns>
        public static bool ArgonPasswordNeedsRehash(byte[] hash, long opsLimit, int memLimit)
        {
            if (hash == null)
                throw new ArgumentNullException(nameof(hash), "Hash cannot be null");
            if (hash.Length >= ARGON_STRBYTES)
                throw new ArgumentOutOfRangeException(nameof(hash), "Hash is invalid");

            var buffer = new byte[ARGON_STRBYTES];
            Array.Copy(hash, buffer, hash.Length);

            SodiumCore.Initialize();
            int status = crypto_pwhash_str_needs_rehash(buffer, (ulong)opsLimit, (nuint)memLimit);

            if (status == -1)
            {
                throw new InvalidPasswordStringException("Invalid Password string for Argon 2");
            }

            return status == 1;
        }

        private static (long opsLimit, int memLimit) GetArgonOpsAndMemoryLimit(StrengthArgon limit = StrengthArgon.Interactive)
        {
            int memLimit;
            long opsLimit;

            switch (limit)
            {
                case StrengthArgon.Interactive:
                    opsLimit = ARGON_OPSLIMIT_INTERACTIVE;
                    memLimit = ARGON_MEMLIMIT_INTERACTIVE;
                    break;
                case StrengthArgon.Medium:
                    opsLimit = ARGON_OPSLIMIT_MEDIUM;
                    memLimit = ARGON_MEMLIMIT_MEDIUM;
                    break;
                case StrengthArgon.Moderate:
                    opsLimit = ARGON_OPSLIMIT_MODERATE;
                    memLimit = ARGON_MEMLIMIT_MODERATE;
                    break;
                case StrengthArgon.Sensitive:
                    opsLimit = ARGON_OPSLIMIT_SENSITIVE;
                    memLimit = ARGON_MEMLIMIT_SENSITIVE;
                    break;
                default:
                    opsLimit = ARGON_OPSLIMIT_INTERACTIVE;
                    memLimit = ARGON_MEMLIMIT_INTERACTIVE;
                    break;
            }
            return (opsLimit, memLimit);
        }
    }
}
