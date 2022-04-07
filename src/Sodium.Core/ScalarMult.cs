using Sodium.Exceptions;
using static Interop.Libsodium;

namespace Sodium
{
    /// <summary>Scalar Multiplication</summary>
    public static class ScalarMult
    {
        private const int BYTES = crypto_scalarmult_curve25519_BYTES;
        private const int SCALAR_BYTES = crypto_scalarmult_curve25519_SCALARBYTES;

        //TODO: Add documentation header
        public static int Bytes()
        {
            return crypto_scalarmult_curve25519_BYTES;
        }

        //TODO: Add documentation header
        public static int ScalarBytes()
        {
            return crypto_scalarmult_curve25519_SCALARBYTES;
        }

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
                throw new KeyOutOfRangeException("secretKey", (secretKey == null) ? 0 : secretKey.Length,
                  string.Format("secretKey must be {0} bytes in length.", SCALAR_BYTES));

            var publicKey = new byte[BYTES];

            SodiumCore.Initialize();
            crypto_scalarmult_curve25519_base(publicKey, secretKey);

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
                throw new KeyOutOfRangeException("secretKey", (secretKey == null) ? 0 : secretKey.Length,
                  string.Format("secretKey must be {0} bytes in length.", SCALAR_BYTES));

            //validate the length of the group element
            if (publicKey == null || publicKey.Length != BYTES)
                throw new KeyOutOfRangeException("publicKey", (publicKey == null) ? 0 : publicKey.Length,
                  string.Format("publicKey must be {0} bytes in length.", BYTES));

            var secretShared = new byte[BYTES];

            SodiumCore.Initialize();
            crypto_scalarmult_curve25519(secretShared, secretKey, publicKey);

            return secretShared;
        }
    }
}
