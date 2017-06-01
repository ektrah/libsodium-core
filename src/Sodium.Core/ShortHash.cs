using System.Text;
using Sodium.Exceptions;

namespace Sodium
{
  /// <summary>Short hash function.</summary>
  public static class ShortHash
  {
    //this was pulled from the headers; should be more dynamic
    private const int BYTES = 8;
    private const int KEY_BYTES = 16;

    /// <summary>Generates a random 16 byte key.</summary>
    /// <returns>Returns a byte array with 16 random bytes</returns>
    public static byte[] GenerateKey()
    {
      return SodiumCore.GetRandomBytes(KEY_BYTES);
    }

    /// <summary>Hashes a message, with a key, using the SipHash-2-4 primitive.</summary>
    /// <param name="message">The message to be hashed.</param>
    /// <param name="key">The key; must be 16 bytes.</param>
    /// <returns>Returns 8 byte array.</returns>
    /// <exception cref="KeyOutOfRangeException"></exception>
    public static byte[] Hash(string message, string key)
    {
      return Hash(message, Encoding.UTF8.GetBytes(key));
    }

    /// <summary>Hashes a message, with a key, using the SipHash-2-4 primitive.</summary>
    /// <param name="message">The message to be hashed.</param>
    /// <param name="key">The key; must be 16 bytes.</param>
    /// <returns>Returns 8 byte array.</returns>
    /// <exception cref="KeyOutOfRangeException"></exception>
    public static byte[] Hash(string message, byte[] key)
    {
      return Hash(Encoding.UTF8.GetBytes(message), key);
    }

    /// <summary>Hashes a message, with a key, using the SipHash-2-4 primitive.</summary>
    /// <param name="message">The message to be hashed.</param>
    /// <param name="key">The key; must be 16 bytes.</param>
    /// <returns>Returns 8 byte array.</returns>
    /// <exception cref="KeyOutOfRangeException"></exception>
    public static byte[] Hash(byte[] message, byte[] key)
    {
      //validate the length of the key
      if (key == null || key.Length != KEY_BYTES)
        throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", KEY_BYTES));

      var buffer = new byte[BYTES];
      SodiumLibrary.crypto_shorthash(buffer, message, message.Length, key);

      return buffer;
    }
  }
}
