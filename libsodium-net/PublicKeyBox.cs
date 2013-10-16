using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Sodium
{
  /// <summary>
  /// Create and Open Boxes.
  /// </summary>
  public static class PublicKeyBox
  {
    private const int PUBLIC_KEY_BYTES = 32;
    private const int SECRET_KEY_BYTES = 32;
    private const int NONCE_BYTES = 24;
    private const int ZERO_BYTES = 32;

    /// <summary>Creates a new key pair based on a random seed.</summary>
    /// <returns></returns>
    public static KeyPair GenerateKeyPair()
    {
      var publicKey = new byte[PUBLIC_KEY_BYTES];
      var privateKey = new byte[SECRET_KEY_BYTES];

      _GenerateKeyPair(publicKey, privateKey);

      return new KeyPair(publicKey, privateKey);
    }

    /// <summary>Creates a Box</summary>
    /// <param name="message"></param>
    /// <param name="nonce"></param>
    /// <param name="secretKey">The secret key to sign message with.</param>
    /// <param name="publicKey">The recipient's public key.</param>
    /// <returns></returns>
    public static byte[] Create(string message, byte[] nonce, byte[] secretKey, byte[] publicKey)
    {
      return Create(Encoding.UTF8.GetBytes(message), nonce, secretKey, publicKey);
    }

    /// <summary>Creates a Box</summary>
    /// <param name="message"></param>
    /// <param name="nonce"></param>
    /// <param name="secretKey">The secret key to sign message with.</param>
    /// <param name="publicKey">The recipient's public key.</param>
    /// <returns></returns>
    public static byte[] Create(byte[] message, byte[] nonce, byte[] secretKey, byte[] publicKey)
    {
      //validate the length of the secret key
      if (secretKey == null || secretKey.Length != SECRET_KEY_BYTES)
      {
        throw new ArgumentOutOfRangeException("secretKey", (secretKey == null) ? 0 : secretKey.Length,
          string.Format("key must be {0} bytes in length.", SECRET_KEY_BYTES));
      }

      //validate the length of the public key
      if (publicKey == null || publicKey.Length != PUBLIC_KEY_BYTES)
      {
        throw new ArgumentOutOfRangeException("publicKey", (publicKey == null) ? 0 : secretKey.Length,
          string.Format("key must be {0} bytes in length.", PUBLIC_KEY_BYTES));
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
      var ret = _Create(buffer, paddedMessage, paddedMessage.Length, nonce, publicKey, secretKey);

      if (ret != 0)
      {
        throw new CryptographicException("Failed to create SecretBox");
      }

      return buffer;
    }

    /// <summary>Opens a Box</summary>
    /// <param name="cipherText"></param>
    /// <param name="nonce"></param>
    /// <param name="secretKey">The recipient's secret key.</param>
    /// <param name="publicKey">The sender's public key.</param>
    /// <returns></returns>
    public static byte[] Open(byte[] cipherText, byte[] nonce, byte[] secretKey, byte[] publicKey)
    {
      //validate the length of the secret key
      if (secretKey == null || secretKey.Length != SECRET_KEY_BYTES)
      {
        throw new ArgumentOutOfRangeException("secretKey", (secretKey == null) ? 0 : secretKey.Length,
          string.Format("key must be {0} bytes in length.", SECRET_KEY_BYTES));
      }

      //validate the length of the public key
      if (publicKey == null || publicKey.Length != PUBLIC_KEY_BYTES)
      {
        throw new ArgumentOutOfRangeException("publicKey", (publicKey == null) ? 0 : secretKey.Length,
          string.Format("key must be {0} bytes in length.", PUBLIC_KEY_BYTES));
      }

      //validate the length of the nonce
      if (nonce == null || nonce.Length != NONCE_BYTES)
      {
        throw new ArgumentOutOfRangeException("nonce", (nonce == null) ? 0 : nonce.Length,
          string.Format("nonce must be {0} bytes in length.", NONCE_BYTES));
      }

      var buffer = new byte[cipherText.Length];
      var ret = _Open(buffer, cipherText, cipherText.Length, nonce, publicKey, secretKey);

      if (ret != 0)
      {
        throw new CryptographicException("Failed to open SecretBox");
      }

      var final = new byte[buffer.Length - ZERO_BYTES];
      Array.Copy(buffer, ZERO_BYTES, final, 0, buffer.Length - ZERO_BYTES);

      return final;
    }

    [DllImport(SodiumCore.LIBRARY_NAME, EntryPoint = "crypto_box_keypair", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _GenerateKeyPair(byte[] publicKey, byte[] secretKey);

    [DllImport(SodiumCore.LIBRARY_NAME, EntryPoint = "crypto_box", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Create(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] publicKey, byte[] secretKey);

    [DllImport(SodiumCore.LIBRARY_NAME, EntryPoint = "crypto_box_open", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Open(byte[] buffer, byte[] cipherText, long cipherTextLength, byte[] nonce, byte[] publicKey, byte[] secretKey);
  }
}
