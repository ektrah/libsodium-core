using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Sodium
{
  /// <summary>
  /// One Time Message Authentication
  /// </summary>
  public static class PublicKeyAuth
  {
    private const int SECRET_KEY_BYTES = 64;
    private const int PUBLIC_KEY_BYTES = 32;
    private const int BYTES = 64;

    /// <summary>Creates a new key pair based on a random seed.</summary>
    /// <returns></returns>
    public static KeyPair GenerateKeyPair()
    {
      var publicKey = new byte[PUBLIC_KEY_BYTES];
      var privateKey = new byte[SECRET_KEY_BYTES];

      _GenerateKeyPair(publicKey, privateKey);

      return new KeyPair(publicKey, privateKey);
    }

    /// <summary>Signs a message with Ed25519.</summary>
    /// <param name="message">The message.</param>
    /// <param name="key">The 64 byte private key.</param>
    /// <returns>Signed message.</returns>
    public static byte[] Sign(string message, byte[] key)
    {
      return Sign(Encoding.UTF8.GetBytes(message), key);
    }

    /// <summary>Signs a message with Ed25519.</summary>
    /// <param name="message">The message.</param>
    /// <param name="key">The 64 byte private key.</param>
    /// <returns>Signed message.</returns>
    public static byte[] Sign(byte[] message, byte[] key)
    {
      //validate the length of the key
      if (key == null || key.Length != SECRET_KEY_BYTES)
      {
        throw new ArgumentOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", SECRET_KEY_BYTES));
      }

      var buffer = new byte[message.Length + BYTES];
      long bufferLength = 0;
      _Sign(buffer, ref bufferLength, message, message.Length, key);

      var final = new byte[bufferLength];
      Array.Copy(buffer, 0, final, 0, bufferLength);

      return buffer;
    }

    /// <summary>Verifies a message signed with the Sign method.</summary>
    /// <param name="signedMessage">The signed message.</param>
    /// <param name="key">The 32 byte public key.</param>
    /// <returns>Message.</returns>
    public static byte[] Verify(byte[] signedMessage, byte[] key)
    {
      //validate the length of the key
      if (key == null || key.Length != PUBLIC_KEY_BYTES)
      {
        throw new ArgumentOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", PUBLIC_KEY_BYTES));
      }

      var buffer = new byte[signedMessage.Length];
      long bufferLength = 0;

      var ret = _Verify(buffer, ref bufferLength, signedMessage, signedMessage.Length, key);

      if (ret != 0)
      {
        throw new CryptographicException("Failed to verify signature.");
      }

      var final = new byte[bufferLength];
      Array.Copy(buffer, 0, final, 0, bufferLength);

      return final;
    }

    [DllImport("libsodium", EntryPoint = "crypto_sign_keypair", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _GenerateKeyPair(byte[] publicKey, byte[] secretKey);

    [DllImport("libsodium", EntryPoint = "crypto_sign", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Sign(byte[] buffer, ref long bufferLength, byte[] message, long messageLength, byte[] key);

    [DllImport("libsodium", EntryPoint = "crypto_sign_open", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Verify(byte[] buffer, ref long bufferLength, byte[] signedMessage, long signedMessageLength, byte[] key);
  }
}