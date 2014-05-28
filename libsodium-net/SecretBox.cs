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
      var ret = SodiumCore.Is64
                  ? _Create64(buffer, paddedMessage, paddedMessage.Length, nonce, key)
                  : _Create86(buffer, paddedMessage, paddedMessage.Length, nonce, key);

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
      return Open(Utilities.HexToBinary(cipherText), nonce, key);
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
      var ret = SodiumCore.Is64
                  ? _Open64(buffer, cipherText, cipherText.Length, nonce, key)
                  : _Open86(buffer, cipherText, cipherText.Length, nonce, key);

      if (ret != 0)
      {
        throw new CryptographicException("Failed to open SecretBox");
      }

      var final = new byte[buffer.Length - ZERO_BYTES];
      Array.Copy(buffer, ZERO_BYTES, final, 0, buffer.Length - ZERO_BYTES);

      return final;
    }

    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_secretbox", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Create64(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] key);

    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_secretbox_open", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Open64(byte[] buffer, byte[] cipherText, long cipherTextLength, byte[] nonce, byte[] key);

    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_secretbox", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Create86(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] key);

    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_secretbox_open", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Open86(byte[] buffer, byte[] cipherText, long cipherTextLength, byte[] nonce, byte[] key);
  }
}
