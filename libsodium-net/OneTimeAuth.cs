using System.Text;
using Sodium.Exceptions;

namespace Sodium
{
  /// <summary>One Time Message Authentication</summary>
  public static class OneTimeAuth
  {
    private const int KEY_BYTES = 32;
    private const int BYTES = 16;

    /// <summary>Generates a random 32 byte key.</summary>
    /// <returns>Returns a byte array with 32 random bytes</returns>
    public static byte[] GenerateKey()
    {
      return SodiumCore.GetRandomBytes(KEY_BYTES);
    }

    /// <summary>Signs a message using Poly1305</summary>
    /// <param name="message">The message.</param>
    /// <param name="key">The 32 byte key.</param>
    /// <returns>16 byte authentication code.</returns>
    /// <exception cref="KeyOutOfRangeException"></exception>
    public static byte[] Sign(string message, byte[] key)
    {
      return Sign(Encoding.UTF8.GetBytes(message), key);
    }

    /// <summary>Signs a message using Poly1305</summary>
    /// <param name="message">The message.</param>
    /// <param name="key">The 32 byte key.</param>
    /// <returns>16 byte authentication code.</returns>
    /// <exception cref="KeyOutOfRangeException"></exception>
    public static byte[] Sign(byte[] message, byte[] key)
    {
      //validate the length of the key
      if (key == null || key.Length != KEY_BYTES)
        throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", KEY_BYTES));

      var buffer = new byte[BYTES];
      SodiumLibrary.crypto_onetimeauth(buffer, message, message.Length, key);

      return buffer;
    }

    /// <summary>Verifies a message signed with the Sign method.</summary>
    /// <param name="message">The message.</param>
    /// <param name="signature">The 16 byte signature.</param>
    /// <param name="key">The 32 byte key.</param>
    /// <returns>True if verified.</returns>
    /// <exception cref="KeyOutOfRangeException"></exception>
    /// <exception cref="SignatureOutOfRangeException"></exception>
    public static bool Verify(string message, byte[] signature, byte[] key)
    {
      return Verify(Encoding.UTF8.GetBytes(message), signature, key);
    }

    /// <summary>Verifies a message signed with the Sign method.</summary>
    /// <param name="message">The message.</param>
    /// <param name="signature">The 16 byte signature.</param>
    /// <param name="key">The 32 byte key.</param>
    /// <returns>True if verified.</returns>
    /// <exception cref="KeyOutOfRangeException"></exception>
    /// <exception cref="SignatureOutOfRangeException"></exception>
    public static bool Verify(byte[] message, byte[] signature, byte[] key)
    {
      //validate the length of the key
      if (key == null || key.Length != KEY_BYTES)
        throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", KEY_BYTES));

      //validate the length of the signature
      if (signature == null || signature.Length != BYTES)
        throw new SignatureOutOfRangeException("signature", (signature == null) ? 0 : signature.Length,
          string.Format("signature must be {0} bytes in length.", BYTES));

      var ret = SodiumLibrary.crypto_onetimeauth_verify(signature, message, message.Length, key);

      return ret == 0;
    }
  }
}
