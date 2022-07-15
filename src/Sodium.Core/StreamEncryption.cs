using System.Security.Cryptography;
using System.Text;
using Sodium.Exceptions;
using static Interop.Libsodium;

namespace Sodium
{
    /// <summary>Encrypt and decrypt messages via XSalsa20 or ChaCha20</summary>
    public static class StreamEncryption
    {
        private const int XSALSA20_KEY_BYTES = crypto_stream_xsalsa20_KEYBYTES;
        private const int XSALSA20_NONCE_BYTES = crypto_stream_xsalsa20_NONCEBYTES;
        private const int CHACHA20_KEY_BYTES = crypto_stream_chacha20_KEYBYTES;
        private const int CHACHA20_NONCEBYTES = crypto_stream_chacha20_NONCEBYTES;
        private const int CHACHA20_IETF_KEY_BYTES = crypto_stream_chacha20_ietf_KEYBYTES;
        private const int CHACHA20_IETF_NONCEBYTES = crypto_stream_chacha20_ietf_NONCEBYTES;
        private const int XCHACHA20_KEY_BYTES = crypto_stream_xchacha20_KEYBYTES;
        private const int XCHACHA20_NONCEBYTES = crypto_stream_xchacha20_NONCEBYTES;

        /// <summary>Generates a random 32 byte key.</summary>
        /// <returns>Returns a byte array with 32 random bytes</returns>
        public static byte[] GenerateKey()
        {
            return SodiumCore.GetRandomBytes(XSALSA20_KEY_BYTES);
        }

        /// <summary>Generates a random 24 byte nonce.</summary>
        /// <returns>Returns a byte array with 24 random bytes</returns>
        public static byte[] GenerateNonce()
        {
            return SodiumCore.GetRandomBytes(XSALSA20_NONCE_BYTES);
        }

        /// <summary>Generates a random 8 byte nonce.</summary>
        /// <returns>Returns a byte array with 8 random bytes</returns>
        public static byte[] GenerateNonceChaCha20()
        {
            return SodiumCore.GetRandomBytes(CHACHA20_NONCEBYTES);
        }

        /// <summary>Generates a random 12 byte nonce.</summary>
        /// <returns>Returns a byte array with 12 random bytes</returns>
        public static byte[] GenerateNonceChaCha20Ietf()
        {
            return SodiumCore.GetRandomBytes(CHACHA20_IETF_NONCEBYTES);
        }

        /// <summary>Generates a random 24 byte nonce.</summary>
        /// <returns>Returns a byte array with 24 random bytes</returns>
        public static byte[] GenerateNonceXChaCha20()
        {
            return SodiumCore.GetRandomBytes(XCHACHA20_NONCEBYTES);
        }

        /// <summary>Encrypts messages via XSalsa20</summary>
        /// <param name="message">The message to be encrypted.</param>
        /// <param name="nonce">The nonce.</param>
        /// <param name="key">The key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Encrypt(string message, byte[] nonce, byte[] key)
        {
            return Encrypt(Encoding.UTF8.GetBytes(message), nonce, key);
        }

        /// <summary>Encrypts messages via XSalsa20</summary>
        /// <param name="message">The message to be encrypted.</param>
        /// <param name="nonce">The nonce.</param>
        /// <param name="key">The key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Encrypt(byte[] message, byte[] nonce, byte[] key)
        {
            if (key == null || key.Length != XSALSA20_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {XSALSA20_KEY_BYTES} bytes in length.");
            if (nonce == null || nonce.Length != XSALSA20_NONCE_BYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {XSALSA20_NONCE_BYTES} bytes in length.");

            var buffer = new byte[message.Length];

            SodiumCore.Initialize();
            var ret = crypto_stream_xsalsa20_xor(buffer, message, (ulong)message.Length, nonce, key);

            if (ret != 0)
                throw new CryptographicException("Error encrypting message.");

            return buffer;
        }

        /// <summary>Encrypts messages via ChaCha20</summary>
        /// <param name="message">The message to be encrypted.</param>
        /// <param name="nonce">The 8 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] EncryptChaCha20(string message, byte[] nonce, byte[] key)
        {
            return EncryptChaCha20(Encoding.UTF8.GetBytes(message), nonce, key);
        }

        /// <summary>Encrypts messages via ChaCha20</summary>
        /// <param name="message">The message to be encrypted.</param>
        /// <param name="nonce">The 8 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] EncryptChaCha20(byte[] message, byte[] nonce, byte[] key)
        {
            if (key == null || key.Length != CHACHA20_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {CHACHA20_KEY_BYTES} bytes in length.");
            if (nonce == null || nonce.Length != CHACHA20_NONCEBYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {CHACHA20_NONCEBYTES} bytes in length.");

            var buffer = new byte[message.Length];

            SodiumCore.Initialize();
            var ret = crypto_stream_chacha20_xor(buffer, message, (ulong)message.Length, nonce, key);

            if (ret != 0)
                throw new CryptographicException("Error encrypting message.");

            return buffer;
        }

        /// <summary>Encrypts messages via ChaCha20 IETF</summary>
        /// <param name="message">The message to be encrypted.</param>
        /// <param name="nonce">The 12 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] EncryptChaCha20Ietf(string message, byte[] nonce, byte[] key)
        {
            return EncryptChaCha20Ietf(Encoding.UTF8.GetBytes(message), nonce, key);
        }

        /// <summary>Encrypts messages via ChaCha20 IETF</summary>
        /// <param name="message">The message to be encrypted.</param>
        /// <param name="nonce">The 12 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] EncryptChaCha20Ietf(byte[] message, byte[] nonce, byte[] key)
        {
            if (key == null || key.Length != CHACHA20_IETF_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {CHACHA20_IETF_KEY_BYTES} bytes in length.");
            if (nonce == null || nonce.Length != CHACHA20_IETF_NONCEBYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {CHACHA20_IETF_NONCEBYTES} bytes in length.");

            var buffer = new byte[message.Length];

            SodiumCore.Initialize();
            var ret = crypto_stream_chacha20_ietf_xor(buffer, message, (ulong)message.Length, nonce, key);

            if (ret != 0)
                throw new CryptographicException("Error encrypting message.");

            return buffer;
        }

        /// <summary>Encrypts messages via XChaCha20</summary>
        /// <param name="message">The message to be encrypted.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] EncryptXChaCha20(string message, byte[] nonce, byte[] key)
        {
            return EncryptXChaCha20(Encoding.UTF8.GetBytes(message), nonce, key);
        }

        /// <summary>Encrypts messages via XChaCha20</summary>
        /// <param name="message">The message to be encrypted.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] EncryptXChaCha20(byte[] message, byte[] nonce, byte[] key)
        {
            if (key == null || key.Length != XCHACHA20_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {XCHACHA20_KEY_BYTES} bytes in length.");
            if (nonce == null || nonce.Length != XCHACHA20_NONCEBYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {XCHACHA20_NONCEBYTES} bytes in length.");

            var buffer = new byte[message.Length];

            SodiumCore.Initialize();
            var ret = crypto_stream_xchacha20_xor(buffer, message, (ulong)message.Length, nonce, key);

            if (ret != 0)
                throw new CryptographicException("Error encrypting message.");

            return buffer;
        }

        /// <summary>Decrypts messages via XSalsa20</summary>
        /// <param name="cipherText">The ciphertext as hex-encoded string.</param>
        /// <param name="nonce">The nonce.</param>
        /// <param name="key">The key.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Decrypt(string cipherText, byte[] nonce, byte[] key)
        {
            return Decrypt(Utilities.HexToBinary(cipherText), nonce, key);
        }

        /// <summary>Decrypts messages via XSalsa20</summary>
        /// <param name="cipherText">The ciphertext to be opened.</param>
        /// <param name="nonce">The nonce.</param>
        /// <param name="key">The key.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Decrypt(byte[] cipherText, byte[] nonce, byte[] key)
        {
            if (key == null || key.Length != XSALSA20_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {XSALSA20_KEY_BYTES} bytes in length.");
            if (nonce == null || nonce.Length != XSALSA20_NONCE_BYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {XSALSA20_NONCE_BYTES} bytes in length.");

            var buffer = new byte[cipherText.Length];

            SodiumCore.Initialize();
            var ret = crypto_stream_xsalsa20_xor(buffer, cipherText, (ulong)cipherText.Length, nonce, key);

            if (ret != 0)
                throw new CryptographicException("Error decrypting message.");

            return buffer;
        }

        /// <summary>Decrypts messages via ChaCha20</summary>
        /// <param name="cipherText">The ciphertext as hex-encoded string.</param>
        /// <param name="nonce">The 8 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] DecryptChaCha20(string cipherText, byte[] nonce, byte[] key)
        {
            return DecryptChaCha20(Utilities.HexToBinary(cipherText), nonce, key);
        }

        /// <summary>Decrypts messages via ChaCha20</summary>
        /// <param name="cipherText">The ciphertext to be opened.</param>
        /// <param name="nonce">The 8 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] DecryptChaCha20(byte[] cipherText, byte[] nonce, byte[] key)
        {
            if (key == null || key.Length != CHACHA20_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {CHACHA20_KEY_BYTES} bytes in length.");
            if (nonce == null || nonce.Length != CHACHA20_NONCEBYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {CHACHA20_NONCEBYTES} bytes in length.");

            var buffer = new byte[cipherText.Length];

            SodiumCore.Initialize();
            var ret = crypto_stream_chacha20_xor(buffer, cipherText, (ulong)cipherText.Length, nonce, key);

            if (ret != 0)
                throw new CryptographicException("Error decrypting message.");

            return buffer;
        }

        /// <summary>Decrypts messages via ChaCha20 IETF</summary>
        /// <param name="cipherText">The ciphertext as hex-encoded string.</param>
        /// <param name="nonce">The 12 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] DecryptChaCha20Ietf(string cipherText, byte[] nonce, byte[] key)
        {
            return DecryptChaCha20Ietf(Utilities.HexToBinary(cipherText), nonce, key);
        }

        /// <summary>Decrypts messages via ChaCha20</summary>
        /// <param name="cipherText">The ciphertext to be opened.</param>
        /// <param name="nonce">The 12 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] DecryptChaCha20Ietf(byte[] cipherText, byte[] nonce, byte[] key)
        {
            if (key == null || key.Length != CHACHA20_IETF_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {CHACHA20_IETF_KEY_BYTES} bytes in length.");
            if (nonce == null || nonce.Length != CHACHA20_IETF_NONCEBYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {CHACHA20_IETF_NONCEBYTES} bytes in length.");

            var buffer = new byte[cipherText.Length];

            SodiumCore.Initialize();
            var ret = crypto_stream_chacha20_ietf_xor(buffer, cipherText, (ulong)cipherText.Length, nonce, key);

            if (ret != 0)
                throw new CryptographicException("Error decrypting message.");

            return buffer;
        }

        /// <summary>Decrypts messages via XChaCha20</summary>
        /// <param name="cipherText">The ciphertext as hex-encoded string.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] DecryptXChaCha20(string cipherText, byte[] nonce, byte[] key)
        {
            return DecryptXChaCha20(Utilities.HexToBinary(cipherText), nonce, key);
        }

        /// <summary>Decrypts messages via XChaCha20</summary>
        /// <param name="cipherText">The ciphertext to be opened.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] DecryptXChaCha20(byte[] cipherText, byte[] nonce, byte[] key)
        {
            if (key == null || key.Length != XCHACHA20_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {XCHACHA20_KEY_BYTES} bytes in length.");
            if (nonce == null || nonce.Length != XCHACHA20_NONCEBYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {XCHACHA20_NONCEBYTES} bytes in length.");

            var buffer = new byte[cipherText.Length];

            SodiumCore.Initialize();
            var ret = crypto_stream_xchacha20_xor(buffer, cipherText, (ulong)cipherText.Length, nonce, key);

            if (ret != 0)
                throw new CryptographicException("Error decrypting message.");

            return buffer;
        }
    }
}
