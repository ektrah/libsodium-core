using System.Security.Cryptography;
using System.Text;
using Sodium.Exceptions;

namespace Sodium
{
    /// <summary>Encrypt and decrypt messages via XSalsa20 or ChaCha20</summary>
    public static class StreamEncryption
    {
        private const int XSALSA20_KEY_BYTES = 32;
        private const int XSALSA20_NONCE_BYTES = 24;
        private const int CHACHA20_KEY_BYTES = 32;
        private const int CHACHA20_NONCEBYTES = 8;
        private const int XCHACHA20_KEY_BYTES = 32;
        private const int XCHACHA20_NONCEBYTES = 24;

        /// <summary>Generates a random 32 byte key.</summary>
        /// <returns>Returns a byte array with 32 random bytes</returns>
        public static byte[] GenerateKey() => SodiumCore.GetRandomBytes(XSALSA20_KEY_BYTES);

        /// <summary>Generates a random 24 byte nonce.</summary>
        /// <returns>Returns a byte array with 24 random bytes</returns>
        public static byte[] GenerateNonce() => SodiumCore.GetRandomBytes(XSALSA20_NONCE_BYTES);

        /// <summary>Generates a random 24 byte nonce.</summary>
        /// <returns>Returns a byte array with 24 random bytes</returns>
        public static byte[] GenerateNonceChaCha20() => SodiumCore.GetRandomBytes(CHACHA20_NONCEBYTES);

        /// <summary>Generates a random 8 byte nonce.</summary>
        /// <returns>Returns a byte array with 8 random bytes</returns>
        public static byte[] GenerateNonceXChaCha20() => SodiumCore.GetRandomBytes(XCHACHA20_NONCEBYTES);

        /// <summary>Encryptes messages via XSalsa20</summary>
        /// <param name="message">The message to be encrypted.</param>
        /// <param name="nonce">The nonce.</param>
        /// <param name="key">The key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Encrypt(string message, byte[] nonce, byte[] key) => Encrypt(Encoding.UTF8.GetBytes(message), nonce, key);

        /// <summary>Encryptes messages via XSalsa20</summary>
        /// <param name="message">The message to be encrypted.</param>
        /// <param name="nonce">The nonce.</param>
        /// <param name="key">The key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Encrypt(byte[] message, byte[] nonce, byte[] key)
        {
            //validate the length of the key
            if (key == null || key.Length != XSALSA20_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {XSALSA20_KEY_BYTES} bytes in length.");

            //validate the length of the nonce
            if (nonce == null || nonce.Length != XSALSA20_NONCE_BYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {XSALSA20_NONCE_BYTES} bytes in length.");

            return ByteBuffer.Use(message.Length, buffer => SodiumLibrary.crypto_stream_xor(buffer, message, message.Length, nonce, key), "Error encrypting message.");
        }

        /// <summary>Encryptes messages via ChaCha20</summary>
        /// <param name="message">The message to be encrypted.</param>
        /// <param name="nonce">The 8 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] EncryptChaCha20(string message, byte[] nonce, byte[] key) => EncryptChaCha20(Encoding.UTF8.GetBytes(message), nonce, key);

        /// <summary>Encryptes messages via ChaCha20</summary>
        /// <param name="message">The message to be encrypted.</param>
        /// <param name="nonce">The 8 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] EncryptChaCha20(byte[] message, byte[] nonce, byte[] key)
        {
            //validate the length of the key
            if (key == null || key.Length != CHACHA20_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {CHACHA20_KEY_BYTES} bytes in length.");

            //validate the length of the nonce
            if (nonce == null || nonce.Length != CHACHA20_NONCEBYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {CHACHA20_NONCEBYTES} bytes in length.");

            return ByteBuffer.Use(message.Length, buffer => SodiumLibrary.crypto_stream_chacha20_xor(buffer, message, message.Length, nonce, key), "Error encrypting message.");
        }

        /// <summary>Encryptes messages via XChaCha20</summary>
        /// <param name="message">The message to be encrypted.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] EncryptXChaCha20(string message, byte[] nonce, byte[] key) => EncryptXChaCha20(Encoding.UTF8.GetBytes(message), nonce, key);

        /// <summary>Encryptes messages via XChaCha20</summary>
        /// <param name="message">The message to be encrypted.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] EncryptXChaCha20(byte[] message, byte[] nonce, byte[] key)
        {
            //validate the length of the key
            if (key == null || key.Length != XCHACHA20_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {XCHACHA20_KEY_BYTES} bytes in length.");

            //validate the length of the nonce
            if (nonce == null || nonce.Length != XCHACHA20_NONCEBYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {XCHACHA20_NONCEBYTES} bytes in length.");

            return ByteBuffer.Use(message.Length, buffer =>  SodiumLibrary.crypto_stream_xchacha20_xor(buffer, message, message.Length, nonce, key), "Error encrypting message.");
        }

        /// <summary>Decryptes messages via XSalsa20</summary>
        /// <param name="cipherText">The chipher as hex-encoded string.</param>
        /// <param name="nonce">The nonce.</param>
        /// <param name="key">The key.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Decrypt(string cipherText, byte[] nonce, byte[] key) => Decrypt(Utilities.HexToBinary(cipherText), nonce, key);

        /// <summary>Decryptes messages via XSalsa20</summary>
        /// <param name="cipherText">The chipher text to be opened.</param>
        /// <param name="nonce">The nonce.</param>
        /// <param name="key">The key.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Decrypt(byte[] cipherText, byte[] nonce, byte[] key)
        {
            //validate the length of the key
            if (key == null || key.Length != XSALSA20_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {XSALSA20_KEY_BYTES} bytes in length.");

            //validate the length of the nonce
            if (nonce == null || nonce.Length != XSALSA20_NONCE_BYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {XSALSA20_NONCE_BYTES} bytes in length.");

            return ByteBuffer.Use(cipherText.Length, buffer => SodiumLibrary.crypto_stream_xor(buffer, cipherText, cipherText.Length, nonce, key), "Error derypting message.");
        }

        /// <summary>Decryptes messages via ChaCha20</summary>
        /// <param name="cipherText">The chipher as hex-encoded string.</param>
        /// <param name="nonce">The 8 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] DecryptChaCha20(string cipherText, byte[] nonce, byte[] key) => DecryptChaCha20(Utilities.HexToBinary(cipherText), nonce, key);

        /// <summary>Decryptes messages via ChaCha20</summary>
        /// <param name="cipherText">The chipher text to be opened.</param>
        /// <param name="nonce">The 8 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] DecryptChaCha20(byte[] cipherText, byte[] nonce, byte[] key)
        {
            //validate the length of the key
            if (key == null || key.Length != CHACHA20_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {CHACHA20_KEY_BYTES} bytes in length.");

            //validate the length of the nonce
            if (nonce == null || nonce.Length != CHACHA20_NONCEBYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {CHACHA20_NONCEBYTES} bytes in length.");

            return ByteBuffer.Use(cipherText.Length, buffer => SodiumLibrary.crypto_stream_chacha20_xor(buffer, cipherText, cipherText.Length, nonce, key), "Error derypting message.");
        }

        /// <summary>Decryptes messages via XChaCha20</summary>
        /// <param name="cipherText">The chipher as hex-encoded string.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] DecryptXChaCha20(string cipherText, byte[] nonce, byte[] key) => DecryptXChaCha20(Utilities.HexToBinary(cipherText), nonce, key);

        /// <summary>Decryptes messages via XChaCha20</summary>
        /// <param name="cipherText">The chipher text to be opened.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] DecryptXChaCha20(byte[] cipherText, byte[] nonce, byte[] key)
        {
            //validate the length of the key
            if (key == null || key.Length != XCHACHA20_KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {XCHACHA20_KEY_BYTES} bytes in length.");

            //validate the length of the nonce
            if (nonce == null || nonce.Length != XCHACHA20_NONCEBYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {XCHACHA20_NONCEBYTES} bytes in length.");

            return ByteBuffer.Use(cipherText.Length, buffer => SodiumLibrary.crypto_stream_xchacha20_xor(buffer, cipherText, cipherText.Length, nonce, key), "Error derypting message.");
        }
    }
}
