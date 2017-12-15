using Sodium.Exceptions;

namespace Sodium
{
    /// <summary>Scalar Multiplication</summary>
    public static class ScalarMult
    {
        private const int BYTES = 32;
        private const int SCALAR_BYTES = 32;

        //TODO: Add documentation header
        public static int Bytes() => SodiumLibrary.crypto_scalarmult_bytes();

        //TODO: Add documentation header
        public static int ScalarBytes() => SodiumLibrary.crypto_scalarmult_scalarbytes();

        //TODO: Add documentation header
        //TODO: Unit test(s)
        static byte Primitive() => SodiumLibrary.crypto_scalarmult_primitive();

        /// <summary>
        /// Diffie-Hellman (function computes the public key)
        /// </summary>
        /// <param name="secretKey">A secret key.</param>
        /// <returns>A computed public key.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Base(byte[] secretKey)
        {
            //validate the length of the scalar
            if (secretKey == null || secretKey.Length != SCALAR_BYTES)
                throw new KeyOutOfRangeException(nameof(secretKey), secretKey?.Length ?? 0, $"secretKey must be {SCALAR_BYTES} bytes in length.");

            var publicKey = new byte[SCALAR_BYTES];

            SodiumLibrary.crypto_scalarmult_base(publicKey, secretKey);

            return publicKey;
        }

        /// <summary>
        /// Diffie-Hellman (function computes a secret shared by the two keys) 
        /// </summary>
        /// <param name="secretKey">A secret key.</param>
        /// <param name="publicKey">A public key.</param>
        /// <returns>A computed secret shared.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Mult(byte[] secretKey, byte[] publicKey)
        {
            //validate the length of the scalar
            if (secretKey == null || secretKey.Length != SCALAR_BYTES)
                throw new KeyOutOfRangeException(nameof(secretKey), secretKey?.Length ?? 0, $"secretKey must be {SCALAR_BYTES} bytes in length.");

            //validate the length of the group element
            if (publicKey == null || publicKey.Length != BYTES)
                throw new KeyOutOfRangeException(nameof(publicKey), publicKey?.Length ?? 0, $"publicKey must be {BYTES} bytes in length.");

            var secretShared = new byte[BYTES];

            SodiumLibrary.crypto_scalarmult(secretShared, secretKey, publicKey);

            return secretShared;
        }
    }
}
