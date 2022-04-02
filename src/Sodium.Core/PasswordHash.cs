using System;

namespace Sodium
{
    /// <summary>Hashes passwords using the argon2i and scrypt algorithm</summary>
    public static partial class PasswordHash
    {
        public enum HashType
        {
            /// <summary></summary>
            Argon,
            /// <summary></summary>
            Scrypt
        }

        /// <summary>Generates a random byte salt.</summary>
        /// <param name="hashType"></param>
        /// <returns>Returns a byte array with 16 or 32 random bytes</returns>
        [Obsolete("Use ScryptGenerateSalt() or ArgonGenerateSalt() instead.")]
        public static byte[] GenerateSalt(HashType hashType = HashType.Scrypt)
        {
            //Note: the default hash type is Scrypt for now: to keep backward compatibility
            return hashType == HashType.Argon ? ArgonGenerateSalt() : ScryptGenerateSalt();
        }
    }
}
