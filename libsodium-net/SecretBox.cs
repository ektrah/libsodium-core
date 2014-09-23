using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Sodium
{
  /// <summary>Create and Open Secret Boxes.</summary>
  public static class SecretBox
  {
    private const int KEY_BYTES = 32;
    private const int NONCE_BYTES = 24;
    private const int ZERO_BYTES = 32;
    private const int MAC_BYTES = 16;

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

    /// <summary>Creates a Secret Box</summary>
    /// <param name="message"></param>
    /// <param name="nonce"></param>
    /// <param name="key"></param>
    /// <returns></returns>
    /// <exception cref="KeyOutOfRangeException"></exception>
    /// <exception cref="NonceOutOfRangeException"></exception>
    /// <exception cref="CryptographicException"></exception>
    public static byte[] Create(string message, byte[] nonce, byte[] key)
    {
      return Create(Encoding.UTF8.GetBytes(message), nonce, key);
    }

    /// <summary>Creates a Secret Box</summary>
    /// <param name="message"></param>
    /// <param name="nonce"></param>
    /// <param name="key"></param>
    /// <returns></returns>
    /// <exception cref="KeyOutOfRangeException"></exception>
    /// <exception cref="NonceOutOfRangeException"></exception>
    /// <exception cref="CryptographicException"></exception>
    public static byte[] Create(byte[] message, byte[] nonce, byte[] key)
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

      //pad the message, to start with ZERO_BYTES null bytes
      var paddedMessage = new byte[message.Length + ZERO_BYTES];
      Array.Copy(message, 0, paddedMessage, ZERO_BYTES, message.Length);

      var buffer = new byte[paddedMessage.Length];
      var create = DynamicInvoke.GetDynamicInvoke<_Create>("crypto_secretbox", SodiumCore.LibraryName());
      var ret = create(buffer, paddedMessage, paddedMessage.Length, nonce, key);

      if (ret != 0)
        throw new CryptographicException("Failed to create SecretBox");

      return buffer;
    }

    /// <summary>Creates detached a Secret Box</summary>
    /// <param name="message">The message.</param>
    /// <param name="nonce">The 24 byte nonce.</param>
    /// <param name="key">The 32 byte key.</param>
    /// <returns>A detached object with a cipher and a mac.</returns>
    /// <exception cref="KeyOutOfRangeException"></exception>
    /// <exception cref="NonceOutOfRangeException"></exception>
    /// <exception cref="CryptographicException"></exception>
    public static DetachedBox CreateDetached(string message, byte[] nonce, byte[] key)
    {
      return CreateDetached(Encoding.UTF8.GetBytes(message), nonce, key);
    }

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

      var cipher = new byte[message.Length];
      var mac = new byte[MAC_BYTES];
      var create = DynamicInvoke.GetDynamicInvoke<_CreateDetached>("crypto_secretbox_detached", SodiumCore.LibraryName());
      var ret = create(cipher, mac, message, message.Length, nonce, key);

      if (ret != 0)
        throw new CryptographicException("Failed to create detached SecretBox");

      return new DetachedBox(cipher, mac);
    }

    /// <summary>Opens a Secret Box</summary>
    /// <param name="cipherText">Hex-encoded string to be opened</param>
    /// <param name="nonce"></param>
    /// <param name="key"></param>
    /// <returns></returns>
    /// <exception cref="KeyOutOfRangeException"></exception>
    /// <exception cref="NonceOutOfRangeException"></exception>
    /// <exception cref="CryptographicException"></exception>
    public static byte[] Open(string cipherText, byte[] nonce, byte[] key)
    {
      return Open(Utilities.HexToBinary(cipherText), nonce, key);
    }

    /// <summary>Opens a Secret Box</summary>
    /// <param name="cipherText"></param>
    /// <param name="nonce"></param>
    /// <param name="key"></param>
    /// <returns></returns>
    /// <exception cref="KeyOutOfRangeException"></exception>
    /// <exception cref="NonceOutOfRangeException"></exception>
    /// <exception cref="CryptographicException"></exception>
    public static byte[] Open(byte[] cipherText, byte[] nonce, byte[] key)
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
      var open = DynamicInvoke.GetDynamicInvoke<_Open>("crypto_secretbox_open", SodiumCore.LibraryName());
      var ret = open(buffer, cipherText, cipherText.Length, nonce, key);

      if (ret != 0)
        throw new CryptographicException("Failed to open SecretBox");

      var final = new byte[buffer.Length - ZERO_BYTES];
      Array.Copy(buffer, ZERO_BYTES, final, 0, buffer.Length - ZERO_BYTES);

      return final;
    }

    /// <summary>Opens a detached Secret Box</summary>
    /// <param name="cipherText">Hex-encoded string to be opened</param>
    /// <param name="mac">The 16 byte mac.</param>
    /// <param name="nonce">The 24 byte nonce.</param>
    /// <param name="key">The 32 byte nonce.</param>
    /// <returns></returns>
    /// <exception cref="KeyOutOfRangeException"></exception>
    /// <exception cref="NonceOutOfRangeException"></exception>
    /// <exception cref="MacOutOfRangeException"></exception>
    /// <exception cref="CryptographicException"></exception>
    public static byte[] OpenDetached(string cipherText, byte[] mac, byte[] nonce, byte[] key)
    {
      return OpenDetached(Utilities.HexToBinary(cipherText), mac, nonce, key);
    }

    /// <summary>Opens a detached Secret Box</summary>
    /// <param name="detached">A detached object.</param>
    /// <param name="nonce">The 24 byte nonce.</param>
    /// <param name="key">The 32 byte nonce.</param>
    /// <returns></returns>
    /// <exception cref="KeyOutOfRangeException"></exception>
    /// <exception cref="NonceOutOfRangeException"></exception>
    /// <exception cref="MacOutOfRangeException"></exception>
    /// <exception cref="CryptographicException"></exception>
    public static byte[] OpenDetached(DetachedBox detached, byte[] nonce, byte[] key)
    {
      return OpenDetached(detached.CipherText, detached.Mac, nonce, key);
    }

    /// <summary>Opens a detached Secret Box</summary>
    /// <param name="cipherText">The cipherText.</param>
    /// <param name="mac">The 16 byte mac.</param>
    /// <param name="nonce">The 24 byte nonce.</param>
    /// <param name="key">The 32 byte nonce.</param>
    /// <returns></returns>
    /// <exception cref="KeyOutOfRangeException"></exception>
    /// <exception cref="NonceOutOfRangeException"></exception>
    /// <exception cref="MacOutOfRangeException"></exception>
    /// <exception cref="CryptographicException"></exception>
    public static byte[] OpenDetached(byte[] cipherText, byte[] mac, byte[] nonce, byte[] key)
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

      //validate the length of the mac
      if (mac == null || mac.Length != MAC_BYTES)
      {
        throw new MacOutOfRangeException("mac", (mac == null) ? 0 : mac.Length,
          string.Format("mac must be {0} bytes in length.", MAC_BYTES));
      }

      var buffer = new byte[cipherText.Length];
      var open = DynamicInvoke.GetDynamicInvoke<_OpenDetached>("crypto_secretbox_open_detached", SodiumCore.LibraryName());
      var ret = open(buffer, cipherText, mac, cipherText.Length, nonce, key);

      if (ret != 0)
        throw new CryptographicException("Failed to open detached SecretBox");

      return buffer;
    }

    //crypto_secretbox
    private delegate int _Create(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] key);
    //crypto_secretbox_open
    private delegate int _Open(byte[] buffer, byte[] cipherText, long cipherTextLength, byte[] nonce, byte[] key);
    //crypto_secretbox_detached
    private delegate int _CreateDetached(byte[] cipher, byte[] mac, byte[] message, long messageLength, byte[] nonce, byte[] key);
    //crypto_secretbox_open_detached
    private delegate int _OpenDetached(byte[] buffer, byte[] cipherText, byte[] mac, long cipherTextLength, byte[] nonce, byte[] key);
  }
}
