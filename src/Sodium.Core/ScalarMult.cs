using Sodium.Exceptions;
using static Interop.Libsodium;

namespace Sodium
{
    /// <summary>Scalar Multiplication</summary>
    public static class ScalarMult
    {
        private const int BYTES = crypto_scalarmult_curve25519_BYTES;
        private const int SCALAR_BYTES = crypto_scalarmult_curve25519_SCALARBYTES;

        public static int Bytes { get; } = crypto_scalarmult_curve25519_BYTES;
        public static int ScalarBytes { get; } = crypto_scalarmult_curve25519_SCALARBYTES;

        /// <summary>
        /// Diffie-Hellman (function computes the public key)
        /// </summary>
        /// <param name="secretKey">A secret key.</param>
        /// <returns>A computed public key.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Base(byte[] secretKey)
        {
            if (secretKey == null || secretKey.Length != SCALAR_BYTES)
                throw new KeyOutOfRangeException(nameof(secretKey), secretKey?.Length ?? 0, $"secretKey must be {SCALAR_BYTES} bytes in length.");

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
            if (secretKey == null || secretKey.Length != SCALAR_BYTES)
                throw new KeyOutOfRangeException(nameof(secretKey), secretKey?.Length ?? 0, $"secretKey must be {SCALAR_BYTES} bytes in length.");
            if (publicKey == null || publicKey.Length != BYTES)
                throw new KeyOutOfRangeException(nameof(publicKey), publicKey?.Length ?? 0, $"publicKey must be {BYTES} bytes in length.");

            var secretShared = new byte[BYTES];

            SodiumCore.Initialize();
            crypto_scalarmult_curve25519(secretShared, secretKey, publicKey);

            return secretShared;
        }
    }
}
