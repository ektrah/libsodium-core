using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Sodium
{
  /// <summary>
  /// One Time Message Authentication
  /// </summary>
  public static class SecretKeyAuth
  {
    private const int KEY_BYTES = 32;
    private const int BYTES = 32;

    /// <summary>Signs a message with HMAC-SHA512-256.</summary>
    /// <param name="message">The message.</param>
    /// <param name="key">The 32 byte key.</param>
    /// <returns>16 byte authentication code.</returns>
    public static byte[] Sign(string message, byte[] key)
    {
      return Sign(Encoding.UTF8.GetBytes(message), key);
    }

    /// <summary>Signs a message with HMAC-SHA512-256.</summary>
    /// <param name="message">The message.</param>
    /// <param name="key">The 32 byte key.</param>
    /// <returns>16 byte authentication code.</returns>
    public static byte[] Sign(byte[] message, byte[] key)
    {
      //validate the length of the key
      if (key == null || key.Length != KEY_BYTES)
      {
        throw new ArgumentOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", KEY_BYTES));
      }

      var buffer = new byte[BYTES];
      _Sign(buffer, message, message.Length, key);

      return buffer;
    }

    /// <summary>Verifies a message signed with the Sign method.</summary>
    /// <param name="message">The message.</param>
    /// <param name="signature">The 32 byte signature.</param>
    /// <param name="key">The 32 byte key.</param>
    /// <returns>True if verified.</returns>
    public static bool Verify(string message, byte[] signature, byte[] key)
    {
      return Verify(Encoding.UTF8.GetBytes(message), signature, key);
    }

    /// <summary>Verifies a message signed with the Sign method.</summary>
    /// <param name="message">The message.</param>
    /// <param name="signature">The 32 byte signature.</param>
    /// <param name="key">The 32 byte key.</param>
    /// <returns>True if verified.</returns>
    public static bool Verify(byte[] message, byte[] signature, byte[] key)
    {
      //validate the length of the key
      if (key == null || key.Length != KEY_BYTES)
      {
        throw new ArgumentOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", KEY_BYTES));
      }

      //validate the length of the signature
      if (signature == null || signature.Length != BYTES)
      {
        throw new ArgumentOutOfRangeException("signature", (signature == null) ? 0 : signature.Length,
          string.Format("signature must be {0} bytes in length.", BYTES));
      }

      var ret = _Verify(signature, message, message.Length, key);

      return ret == 0;
    }

    [DllImport("libsodium-4.dll", EntryPoint = "crypto_auth", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Sign(byte[] buffer, byte[] message, long messageLength, byte[] key);

    [DllImport("libsodium-4.dll", EntryPoint = "crypto_auth_verify", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Verify(byte[] signature, byte[] message, long messageLength, byte[] key);
  }
}
