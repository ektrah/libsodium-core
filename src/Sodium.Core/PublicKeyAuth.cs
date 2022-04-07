using System;
using System.Security.Cryptography;
using System.Text;
using Sodium.Exceptions;
using static Interop.Libsodium;

namespace Sodium
{
    /// <summary>Public-key signatures</summary>
    public static class PublicKeyAuth
    {
        private const int SECRET_KEY_BYTES = crypto_sign_ed25519_SECRETKEYBYTES;
        private const int PUBLIC_KEY_BYTES = crypto_sign_ed25519_PUBLICKEYBYTES;
        private const int BYTES = crypto_sign_ed25519_BYTES;
        private const int SEED_BYTES = crypto_sign_ed25519_SEEDBYTES;

        public static int SecretKeyBytes { get; } = SECRET_KEY_BYTES;
        public static int PublicKeyBytes { get; } = PUBLIC_KEY_BYTES;
        public static int SignatureBytes { get; } = BYTES;
        public static int SeedBytes { get; } = SEED_BYTES;

        /// <summary>Creates a new key pair based on a random seed.</summary>
        /// <returns>A KeyPair.</returns>
        public static KeyPair GenerateKeyPair()
        {
            var publicKey = new byte[PUBLIC_KEY_BYTES];
            var privateKey = new byte[SECRET_KEY_BYTES];

            SodiumCore.Initialize();
            crypto_sign_ed25519_keypair(publicKey, privateKey);

            return new KeyPair(publicKey, privateKey);
        }

        /// <summary>Creates a new key pair based on the provided seed.</summary>
        /// <param name="seed">The seed.</param>
        /// <returns>A KeyPair.</returns>
        /// <exception cref="SeedOutOfRangeException"></exception>
        public static KeyPair GenerateKeyPair(byte[] seed)
        {
            if (seed == null || seed.Length != SEED_BYTES)
                throw new SeedOutOfRangeException(nameof(seed), seed?.Length ?? 0, $"seed must be {SEED_BYTES} bytes in length.");

            var publicKey = new byte[PUBLIC_KEY_BYTES];
            var privateKey = new byte[SECRET_KEY_BYTES];

            SodiumCore.Initialize();
            crypto_sign_ed25519_seed_keypair(publicKey, privateKey, seed);

            return new KeyPair(publicKey, privateKey);
        }

        /// <summary>Signs a message with Ed25519.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 64 byte private key.</param>
        /// <returns>Signed message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Sign(string message, byte[] key)
        {
            return Sign(Encoding.UTF8.GetBytes(message), key);
        }

        /// <summary>Signs a message with Ed25519.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 64 byte private key.</param>
        /// <returns>Signed message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] Sign(byte[] message, byte[] key)
        {
            if (key == null || key.Length != SECRET_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {SECRET_KEY_BYTES} bytes in length.");

            var buffer = new byte[message.Length + BYTES];
            ulong bufferLength = 0;

            SodiumCore.Initialize();
            crypto_sign_ed25519(buffer, ref bufferLength, message, (ulong)message.Length, key);

            Array.Resize(ref buffer, (int)bufferLength);
            return buffer;
        }

        /// <summary>Verifies a message signed with the Sign method.</summary>
        /// <param name="signedMessage">The signed message.</param>
        /// <param name="key">The 32 byte public key.</param>
        /// <returns>Message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Verify(byte[] signedMessage, byte[] key)
        {
            if (key == null || key.Length != PUBLIC_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {PUBLIC_KEY_BYTES} bytes in length.");

            if (signedMessage.Length < BYTES)
                throw new CryptographicException("Failed to verify signature.");

            var buffer = new byte[signedMessage.Length - BYTES];
            ulong bufferLength = 0;

            SodiumCore.Initialize();
            var ret = crypto_sign_ed25519_open(buffer, ref bufferLength, signedMessage, (ulong)signedMessage.Length, key);

            if (ret != 0)
                throw new CryptographicException("Failed to verify signature.");

            Array.Resize(ref buffer, (int)bufferLength);
            return buffer;
        }

        /// <summary>Signs a message with Ed25519.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 64 byte private key.</param>
        /// <returns>The signature.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] SignDetached(string message, byte[] key)
        {
            return SignDetached(Encoding.UTF8.GetBytes(message), key);
        }

        /// <summary>Signs a message with Ed25519.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The 64 byte private key.</param>
        /// <returns>The signature.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static byte[] SignDetached(byte[] message, byte[] key)
        {
            if (key == null || key.Length != SECRET_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {SECRET_KEY_BYTES} bytes in length.");

            var signature = new byte[BYTES];
            ulong signatureLength = 0;

            SodiumCore.Initialize();
            crypto_sign_ed25519_detached(signature, ref signatureLength, message, (ulong)message.Length, key);

            return signature;
        }

        /// <summary>Verifies a message signed with the SignDetached method.</summary>
        /// <param name="signature">The signature.</param>
        /// <param name="message">The message.</param>
        /// <param name="key">The 32 byte public key.</param>
        /// <returns><c>true</c> on success; otherwise, <c>false</c>.</returns>
        /// <exception cref="SignatureOutOfRangeException"></exception>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public static bool VerifyDetached(byte[] signature, byte[] message, byte[] key)
        {
            if (signature == null || signature.Length != BYTES)
                throw new SignatureOutOfRangeException(nameof(signature), signature?.Length ?? 0, $"signature must be {BYTES} bytes in length.");
            if (key == null || key.Length != PUBLIC_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {PUBLIC_KEY_BYTES} bytes in length.");

            SodiumCore.Initialize();
            var ret = crypto_sign_ed25519_verify_detached(signature, message, (ulong)message.Length, key);

            return ret == 0;
        }

        /// <summary>Converts the ed25519 public key to curve25519 public key.</summary>
        /// <param name="ed25519PublicKey">Ed25519 public key.</param>
        /// <returns>The curve25519 public key.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] ConvertEd25519PublicKeyToCurve25519PublicKey(byte[] ed25519PublicKey)
        {
            if (ed25519PublicKey == null || ed25519PublicKey.Length != PUBLIC_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(ed25519PublicKey), ed25519PublicKey?.Length ?? 0, $"ed25519PublicKey must be {PUBLIC_KEY_BYTES} bytes in length.");

            var buffer = new byte[crypto_scalarmult_curve25519_BYTES];

            SodiumCore.Initialize();
            var ret = crypto_sign_ed25519_pk_to_curve25519(buffer, ed25519PublicKey);

            if (ret != 0)
                throw new CryptographicException("Failed to convert public key.");

            return buffer;
        }

        /// <summary>Converts the ed25519 secret key to curve25519 secret key.</summary>
        /// <param name="ed25519SecretKey">Ed25519 secret key.</param>
        /// <returns>The curve25519 secret key.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] ConvertEd25519SecretKeyToCurve25519SecretKey(byte[] ed25519SecretKey)
        {
            // key can be appended with the public key or not (both are allowed)
            if (ed25519SecretKey == null || (ed25519SecretKey.Length != PUBLIC_KEY_BYTES && ed25519SecretKey.Length != SECRET_KEY_BYTES))
                throw new KeyOutOfRangeException(nameof(ed25519SecretKey), ed25519SecretKey?.Length ?? 0, $"ed25519SecretKey must be either {PUBLIC_KEY_BYTES} or {SECRET_KEY_BYTES} bytes in length.");

            var buffer = new byte[crypto_scalarmult_curve25519_SCALARBYTES];

            SodiumCore.Initialize();
            var ret = crypto_sign_ed25519_sk_to_curve25519(buffer, ed25519SecretKey);

            if (ret != 0)
                throw new CryptographicException("Failed to convert secret key.");

            return buffer;
        }

        /// <summary>
        /// Extracts the seed from the Ed25519 secret key.
        /// </summary>
        /// <param name="ed25519SecretKey">The 64 byte Ed25519 secret key.</param>
        /// <returns>The associated seed.</returns>
        public static byte[] ExtractEd25519SeedFromEd25519SecretKey(byte[] ed25519SecretKey)
        {
            if (ed25519SecretKey == null || ed25519SecretKey.Length != SECRET_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(ed25519SecretKey), ed25519SecretKey?.Length ?? 0, $"ed25519SecretKey must be {SECRET_KEY_BYTES} bytes in length.");

            var buffer = new byte[SEED_BYTES];

            SodiumCore.Initialize();
            var ret = crypto_sign_ed25519_sk_to_seed(buffer, ed25519SecretKey);

            if (ret != 0)
                throw new CryptographicException("Failed to extract seed from secret key.");

            return buffer;
        }

        /// <summary>
        /// Extracts the Ed25519 public key from the Ed25519 secret key.
        /// </summary>
        /// <param name="ed25519SecretKey">The 64 byte Ed25519 secret key.</param>
        /// <returns>The associated ed25519PublicKey.</returns>
        public static byte[] ExtractEd25519PublicKeyFromEd25519SecretKey(byte[] ed25519SecretKey)
        {
            if (ed25519SecretKey == null || ed25519SecretKey.Length != SECRET_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(ed25519SecretKey), ed25519SecretKey?.Length ?? 0, $"ed25519SecretKey must be {SECRET_KEY_BYTES} bytes in length.");

            var buffer = new byte[PUBLIC_KEY_BYTES];

            SodiumCore.Initialize();
            var ret = crypto_sign_ed25519_sk_to_pk(buffer, ed25519SecretKey);

            if (ret != 0)
                throw new CryptographicException("Failed to extract public key from secret key.");

            return buffer;
        }
    }
}
