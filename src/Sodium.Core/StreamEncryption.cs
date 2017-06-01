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

    /// <summary>Encryptes messages via XSalsa20</summary>
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
        throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", XSALSA20_KEY_BYTES));

      //validate the length of the nonce
      if (nonce == null || nonce.Length != XSALSA20_NONCE_BYTES)
        throw new NonceOutOfRangeException("nonce", (nonce == null) ? 0 : nonce.Length,
          string.Format("nonce must be {0} bytes in length.", XSALSA20_NONCE_BYTES));

      var buffer = new byte[message.Length];
      var ret = SodiumLibrary.crypto_stream_xor(buffer, message, message.Length, nonce, key);

      if (ret != 0)
        throw new CryptographicException("Error encrypting message.");

      return buffer;
    }

    /// <summary>Encryptes messages via ChaCha20</summary>
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
        throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", CHACHA20_KEY_BYTES));

      //validate the length of the nonce
      if (nonce == null || nonce.Length != CHACHA20_NONCEBYTES)
        throw new NonceOutOfRangeException("nonce", (nonce == null) ? 0 : nonce.Length,
          string.Format("nonce must be {0} bytes in length.", CHACHA20_NONCEBYTES));

      var buffer = new byte[message.Length];
      var ret = SodiumLibrary.crypto_stream_chacha20_xor(buffer, message, message.Length, nonce, key);

      if (ret != 0)
        throw new CryptographicException("Error encrypting message.");

      return buffer;
    }

    /// <summary>Decryptes messages via XSalsa20</summary>
    /// <param name="cipherText">The chipher as hex-encoded string.</param>
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
        throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", XSALSA20_KEY_BYTES));

      //validate the length of the nonce
      if (nonce == null || nonce.Length != XSALSA20_NONCE_BYTES)
        throw new NonceOutOfRangeException("nonce", (nonce == null) ? 0 : nonce.Length,
          string.Format("nonce must be {0} bytes in length.", XSALSA20_NONCE_BYTES));

      var buffer = new byte[cipherText.Length];
      var ret = SodiumLibrary.crypto_stream_xor(buffer, cipherText, cipherText.Length, nonce, key);

      if (ret != 0)
        throw new CryptographicException("Error derypting message.");

      return buffer;
    }

    /// <summary>Decryptes messages via ChaCha20</summary>
    /// <param name="cipherText">The chipher as hex-encoded string.</param>
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
        throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", CHACHA20_KEY_BYTES));

      //validate the length of the nonce
      if (nonce == null || nonce.Length != CHACHA20_NONCEBYTES)
        throw new NonceOutOfRangeException("nonce", (nonce == null) ? 0 : nonce.Length,
          string.Format("nonce must be {0} bytes in length.", CHACHA20_NONCEBYTES));

      var buffer = new byte[cipherText.Length];
      var ret = SodiumLibrary.crypto_stream_chacha20_xor(buffer, cipherText, cipherText.Length, nonce, key);

      if (ret != 0)
        throw new CryptographicException("Error derypting message.");

      return buffer;
    }
  }
}
