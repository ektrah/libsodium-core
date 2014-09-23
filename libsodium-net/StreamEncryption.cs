using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Sodium
{
  /// <summary>Encrypt and decrypt messages via XSalsa20</summary>
  public static class StreamEncryption
  {
    private const int KEY_BYTES = 32;
    private const int NONCE_BYTES = 24;

    /// <summary>Generates a random 32 byte key.</summary>
    /// <returns>Returns a byte array with 32 random bytes</returns>
    public static byte[] GenerateKey()
    {
      return SodiumCore.GetRandomBytes(KEY_BYTES);
    }

    /// <summary>Generates a random 24 byte nonce.</summary>
    /// <returns>Returns a byte array with 24 random bytes</returns>
    public static byte[] GenerateNonce()
    {
      return SodiumCore.GetRandomBytes(NONCE_BYTES);
    }

    /// <summary>Encryptes messages via XSalsa20</summary>
    /// <param name="message"></param>
    /// <param name="nonce"></param>
    /// <param name="key"></param>
    /// <returns></returns>
    public static byte[] Encrypt(string message, byte[] nonce, byte[] key)
    {
      return Encrypt(Encoding.UTF8.GetBytes(message), nonce, key);
    }

    /// <summary>Encryptes messages via XSalsa20</summary>
    /// <param name="message"></param>
    /// <param name="nonce"></param>
    /// <param name="key"></param>
    /// <returns></returns>
    public static byte[] Encrypt(byte[] message, byte[] nonce, byte[] key)
    {
      //validate the length of the key
      if (key == null || key.Length != KEY_BYTES)
      {
        throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", KEY_BYTES));
      }

      //validate the length of the nonce
      if (nonce == null || nonce.Length != NONCE_BYTES)
      {
        throw new NonceOutOfRangeException("nonce", (nonce == null) ? 0 : nonce.Length,
          string.Format("nonce must be {0} bytes in length.", NONCE_BYTES));
      }

      var buffer = new byte[message.Length];
      var encrypt = DynamicInvoke.GetDynamicInvoke<_Encrypt>("crypto_stream_xor", SodiumCore.LibraryName());
      var ret = encrypt(buffer, message, message.Length, nonce, key);

      if (ret != 0)
        throw new CryptographicException("Error encrypting message.");

      return buffer;
    }

    /// <summary>Decryptes messages via XSalsa20</summary>
    /// <param name="cipherText">Hex-encoded string to be opened</param>
    /// <param name="nonce"></param>
    /// <param name="key"></param>
    /// <returns></returns>
    public static byte[] Decrypt(string cipherText, byte[] nonce, byte[] key)
    {
      return Decrypt(Utilities.HexToBinary(cipherText), nonce, key);
    }

    /// <summary>Decryptes messages via XSalsa20</summary>
    /// <param name="cipherText"></param>
    /// <param name="nonce"></param>
    /// <param name="key"></param>
    /// <returns></returns>
    public static byte[] Decrypt(byte[] cipherText, byte[] nonce, byte[] key)
    {
      //validate the length of the key
      if (key == null || key.Length != KEY_BYTES)
      {
        throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", KEY_BYTES));
      }

      //validate the length of the nonce
      if (nonce == null || nonce.Length != NONCE_BYTES)
      {
        throw new NonceOutOfRangeException("nonce", (nonce == null) ? 0 : nonce.Length,
          string.Format("nonce must be {0} bytes in length.", NONCE_BYTES));
      }

      var buffer = new byte[cipherText.Length];
      var decrypt = DynamicInvoke.GetDynamicInvoke<_Encrypt>("crypto_stream_xor", SodiumCore.LibraryName());
      var ret = decrypt(buffer, cipherText, cipherText.Length, nonce, key);

      if (ret != 0)
        throw new CryptographicException("Error derypting message.");

      return buffer;
    }

    //crypto_stream_xor
    private delegate int _Encrypt(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] key);
  }
}
