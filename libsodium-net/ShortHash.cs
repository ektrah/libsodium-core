using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Sodium
{
  /// <summary>
  /// Short hash function.
  /// </summary>
  public static class ShortHash
  {
    //this was pulled from the headers; should be more dynamic
    private const int BYTES = 8;
    private const int KEY_BYTES = 16;

    /// <summary>
    /// Hashes a message, with a key, using the SipHash-2-4 primitive.
    /// </summary>
    /// <param name="message">The message to be hashed.</param>
    /// <param name="key">The key; must be 16 bytes.</param>
    /// <returns>
    /// Returns a hex-encoded string.
    /// </returns>
    public static string Hash(string message, string key)
    {
      return Hash(message, Encoding.UTF8.GetBytes(key));
    }

    /// <summary>
    /// Hashes a message, with a key, using the SipHash-2-4 primitive.
    /// </summary>
    /// <param name="message">The message to be hashed.</param>
    /// <param name="key">The key; must be 16 bytes.</param>
    /// <returns>
    /// Returns a hex-encoded string.
    /// </returns>
    public static string Hash(string message, byte[] key)
    {
      return Hash(Encoding.UTF8.GetBytes(message), key);
    }

    /// <summary>
    /// Hashes a message, with a key, using the SipHash-2-4 primitive.
    /// </summary>
    /// <param name="message">The message to be hashed.</param>
    /// <param name="key">The key; must be 16 bytes.</param>
    /// <returns>
    /// Returns a hex-encoded string.
    /// </returns>
    public static string Hash(byte[] message, byte[] key)
    {
      //validate the length of the key
      if (key == null || key.Length != KEY_BYTES)
      {
        throw new ArgumentOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", KEY_BYTES));
      }

      var buffer = new byte[BYTES];
      _ShortHash(buffer, message, message.Length, key);

      return Helper.BinaryToHex(buffer);
    }

    [DllImport("libsodium-4.dll", EntryPoint = "crypto_shorthash", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _ShortHash(byte[] buffer, byte[] message, long messageLength, byte[] key);
  }
}
