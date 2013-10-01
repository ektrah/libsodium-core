using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Sodium
{
  /// <summary>
  /// Create and Open Secret Boxes.
  /// </summary>
  public static class SecretBox
  {
    private const int KEY_BYTES = 32;
    private const int NONCE_BYTES = 24;
    private const int ZERO_BYTES = 32;

    /// <summary>
    /// Creates a Secret Box
    /// </summary>
    /// <param name="message"></param>
    /// <param name="nonce"></param>
    /// <param name="key"></param>
    /// <returns></returns>
    public static byte[] Create(string message, byte[] nonce, byte[] key)
    {
      return Create(Encoding.UTF8.GetBytes(message), nonce, key);
    }

    /// <summary>
    /// Creates a Secret Box
    /// </summary>
    /// <param name="message"></param>
    /// <param name="nonce"></param>
    /// <param name="key"></param>
    /// <returns></returns>
    public static byte[] Create(byte[] message, byte[] nonce, byte[] key)
    {
      //validate the length of the key
      if (key == null || key.Length != KEY_BYTES)
      {
        throw new ArgumentOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", KEY_BYTES));
      }

      //validate the length of the nonce
      if (nonce == null || nonce.Length != NONCE_BYTES)
      {
        throw new ArgumentOutOfRangeException("nonce", (nonce == null) ? 0 : nonce.Length,
          string.Format("nonce must be {0} bytes in length.", NONCE_BYTES));
      }

      //pad the message, to start with ZERO_BYTES null bytes
      var paddedMessage = new byte[message.Length + ZERO_BYTES];
      Array.Copy(message, 0, paddedMessage, ZERO_BYTES, message.Length);

      var buffer = new byte[paddedMessage.Length];
      var ret = _Create(buffer, paddedMessage, paddedMessage.Length, nonce, key);

      if (ret != 0)
      {
        throw new CryptographicException("Failed to create SecretBox");
      }

      return buffer;
    }

    /// <summary>
    /// Opens a Secret Box
    /// </summary>
    /// <param name="cipherText">Hex-encoded string to be opened</param>
    /// <param name="nonce"></param>
    /// <param name="key"></param>
    /// <returns></returns>
    public static byte[] Open(string cipherText, byte[] nonce, byte[] key)
    {
      return Open(Helper.HexToBinary(cipherText), nonce, key);
    }

    /// <summary>
    /// Opens a Secret Box
    /// </summary>
    /// <param name="cipherText"></param>
    /// <param name="nonce"></param>
    /// <param name="key"></param>
    /// <returns></returns>
    public static byte[] Open(byte[] cipherText, byte[] nonce, byte[] key)
    {
      //validate the length of the key
      if (key == null || key.Length != KEY_BYTES)
      {
        throw new ArgumentOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", KEY_BYTES));
      }

      //validate the length of the nonce
      if (nonce == null || nonce.Length != NONCE_BYTES)
      {
        throw new ArgumentOutOfRangeException("nonce", (nonce == null) ? 0 : nonce.Length,
          string.Format("nonce must be {0} bytes in length.", NONCE_BYTES));
      }
      
      var buffer = new byte[cipherText.Length];
      var ret = _Open(buffer, cipherText, cipherText.Length, nonce, key);

      if (ret != 0)
      {
        throw new CryptographicException("Failed to open SecretBox");
      }

      var final = new byte[buffer.Length - ZERO_BYTES];
      Array.Copy(buffer, ZERO_BYTES, final, 0, buffer.Length - ZERO_BYTES);

      return final;
    }

    [DllImport("libsodium-4.dll", EntryPoint = "crypto_secretbox", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Create(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] key);

    [DllImport("libsodium-4.dll", EntryPoint = "crypto_secretbox_open", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Open(byte[] buffer, byte[] cipherText, long cipherTextLength, byte[] nonce, byte[] key);
  }
}
