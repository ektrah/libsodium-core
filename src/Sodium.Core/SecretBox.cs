using System;
using System.Security.Cryptography;
using System.Text;
using Sodium.Exceptions;

namespace Sodium
{
    /// <summary>Create and Open Secret Boxes.</summary>
    public static class SecretBox
    {
        private const int KEY_BYTES = 32;
        private const int NONCE_BYTES = 24;
        private const int MAC_BYTES = 16;

        /// <summary>Generates a random 32 byte key.</summary>
        /// <returns>Returns a byte array with 32 random bytes</returns>
        public static byte[] GenerateKey() => SodiumCore.GetRandomBytes(KEY_BYTES);

        /// <summary>Generates a random 24 byte nonce.</summary>
        /// <returns>Returns a byte array with 24 random bytes</returns>
        public static byte[] GenerateNonce() => SodiumCore.GetRandomBytes(NONCE_BYTES);

        /// <summary>Creates a Secret Box</summary>
        /// <param name="message">Hex-encoded string to be encrypted.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Create(string message, byte[] nonce, byte[] key) => Create(Encoding.UTF8.GetBytes(message), nonce, key);

        /// <summary>Creates a Secret Box</summary>
        /// <param name="message">The message.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Create(byte[] message, byte[] nonce, byte[] key)
        {
            //validate the length of the key
            if (key == null || key.Length != KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {KEY_BYTES} bytes in length.");

            //validate the length of the nonce
            if (nonce == null || nonce.Length != NONCE_BYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {NONCE_BYTES} bytes in length.");

            var buffer = new byte[MAC_BYTES + message.Length];

            if (SodiumLibrary.crypto_secretbox_easy(buffer, message, message.Length, nonce, key) != 0)
                throw new CryptographicException("Failed to create SecretBox");

            return buffer;
        }

        /// <summary>Creates detached a Secret Box</summary>
        /// <param name="message">Hex-encoded string to be encrypted.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>A detached object with a cipher and a mac.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static DetachedBox CreateDetached(string message, byte[] nonce, byte[] key) => CreateDetached(Encoding.UTF8.GetBytes(message), nonce, key);

        /// <summary>Creates detached a Secret Box</summary>
        /// <param name="message">The message.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>A detached object with a cipher and a mac.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static DetachedBox CreateDetached(byte[] message, byte[] nonce, byte[] key)
        {
            //validate the length of the key
            if (key == null || key.Length != KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {KEY_BYTES} bytes in length.");

            //validate the length of the nonce
            if (nonce == null || nonce.Length != NONCE_BYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {NONCE_BYTES} bytes in length.");

            var cipher = new byte[message.Length];
            var mac = new byte[MAC_BYTES];

            if (SodiumLibrary.crypto_secretbox_detached(cipher, mac, message, message.Length, nonce, key) != 0)
                throw new CryptographicException("Failed to create detached SecretBox");

            return new DetachedBox(cipher, mac);
        }

        /// <summary>Opens a Secret Box</summary>
        /// <param name="cipherText">Hex-encoded string to be opened.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte nonce.</param>
        /// <returns>The decrypted text.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Open(string cipherText, byte[] nonce, byte[] key) => Open(Utilities.HexToBinary(cipherText), nonce, key);

        /// <summary>Opens a Secret Box</summary>
        /// <param name="cipherText">The cipherText.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte nonce.</param>
        /// <returns>The decrypted text.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] Open(byte[] cipherText, byte[] nonce, byte[] key)
        {
            //validate the length of the key
            if (key == null || key.Length != KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {KEY_BYTES} bytes in length.");

            //validate the length of the nonce
            if (nonce == null || nonce.Length != NONCE_BYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {NONCE_BYTES} bytes in length.");

            //check to see if there are MAC_BYTES of leading nulls, if so, trim.
            //this is required due to an error in older versions.
            if (cipherText[0] == 0)
            {
                //check to see if trim is needed
                var trim = true;
                for (var i = 0; i < MAC_BYTES - 1; i++)
                {
                    if (cipherText[i] != 0)
                    {
                        trim = false;
                        break;
                    }
                }

                //if the leading MAC_BYTES are null, trim it off before going on.
                if (trim)
                {
                    var temp = new byte[cipherText.Length - MAC_BYTES];
                    Array.Copy(cipherText, MAC_BYTES, temp, 0, cipherText.Length - MAC_BYTES);

                    cipherText = temp;
                }
            }

            var buffer = new byte[cipherText.Length - MAC_BYTES];

            if (SodiumLibrary.crypto_secretbox_open_easy(buffer, cipherText, cipherText.Length, nonce, key) != 0)
                throw new CryptographicException("Failed to open SecretBox");

            return buffer;
        }

        /// <summary>Opens a detached Secret Box</summary>
        /// <param name="cipherText">Hex-encoded string to be opened</param>
        /// <param name="mac">The 16 byte mac.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte nonce.</param>
        /// <returns>The decrypted text.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="MacOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] OpenDetached(string cipherText, byte[] mac, byte[] nonce, byte[] key) => OpenDetached(Utilities.HexToBinary(cipherText), mac, nonce, key);

        /// <summary>Opens a detached Secret Box</summary>
        /// <param name="detached">A detached object.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte nonce.</param>
        /// <returns>The decrypted text.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="MacOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] OpenDetached(DetachedBox detached, byte[] nonce, byte[] key) => OpenDetached(detached.CipherText, detached.Mac, nonce, key);

        /// <summary>Opens a detached Secret Box</summary>
        /// <param name="cipherText">The cipherText.</param>
        /// <param name="mac">The 16 byte mac.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte nonce.</param>
        /// <returns>The decrypted text.</returns>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <exception cref="NonceOutOfRangeException"></exception>
        /// <exception cref="MacOutOfRangeException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static byte[] OpenDetached(byte[] cipherText, byte[] mac, byte[] nonce, byte[] key)
        {
            //validate the length of the key
            if (key == null || key.Length != KEY_BYTES)
                throw new KeyOutOfRangeException(nameof(key), key?.Length ?? 0, $"key must be {KEY_BYTES} bytes in length.");

            //validate the length of the nonce
            if (nonce == null || nonce.Length != NONCE_BYTES)
                throw new NonceOutOfRangeException(nameof(nonce), nonce?.Length ?? 0, $"nonce must be {NONCE_BYTES} bytes in length.");

            //validate the length of the mac
            if (mac == null || mac.Length != MAC_BYTES)
                throw new MacOutOfRangeException(nameof(mac), mac?.Length ?? 0, $"mac must be {MAC_BYTES} bytes in length.");

            var buffer = new byte[cipherText.Length];

            if (SodiumLibrary.crypto_secretbox_open_detached(buffer, cipherText, mac, cipherText.Length, nonce, key) != 0)
                throw new CryptographicException("Failed to open detached SecretBox");

            return buffer;
        }
    }
}
