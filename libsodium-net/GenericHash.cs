using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Sodium
{
  /// <summary>
  /// Multipurpose hash function.
  /// </summary>
  public static class GenericHash
  {
    //this was pulled from the headers; should be more dynamic
    private const int BYTES_MIN = 16;
    private const int BYTES_MAX = 64;
    private const int KEY_BYTES_MIN = 16;
    private const int KEY_BYTES_MAX = 64;

    /// <summary>Generates a random 64 byte key.</summary>
    /// <returns>Returns a byte array with 64 random bytes</returns>
    public static byte[] GenerateKey()
    {
      return SodiumCore.GetRandomBytes(KEY_BYTES_MAX);
    }

    /// <summary>
    /// Hashes a message, with an optional key, using the BLAKE2b primitive.
    /// </summary>
    /// <param name="message">The message to be hashed.</param>
    /// <param name="key">The key; may be null, otherwise between 16 and 64 bytes.</param>
    /// <param name="bytes">The size (in bytes) of the desired result.</param>
    /// <returns>Returns a byte array.</returns>
    public static byte[] Hash(string message, string key, int bytes)
    {
      return Hash(message, Encoding.UTF8.GetBytes(key), bytes);
    }

    /// <summary>
    /// Hashes a message, with an optional key, using the BLAKE2b primitive.
    /// </summary>
    /// <param name="message">The message to be hashed.</param>
    /// <param name="key">The key; may be null, otherwise between 16 and 64 bytes.</param>
    /// <param name="bytes">The size (in bytes) of the desired result.</param>
    /// <returns>Returns a byte array.</returns>
    public static byte[] Hash(string message, byte[] key, int bytes)
    {
      return Hash(Encoding.UTF8.GetBytes(message), key, bytes);
    }

    /// <summary>
    /// Hashes a message, with an optional key, using the BLAKE2b primitive.
    /// </summary>
    /// <param name="message">The message to be hashed.</param>
    /// <param name="key">The key; may be null, otherwise between 16 and 64 bytes.</param>
    /// <param name="bytes">The size (in bytes) of the desired result.</param>
    /// <returns>Returns a byte array.</returns>
    public static byte[] Hash(byte[] message, byte[] key, int bytes)
    {
      //validate the length of the key
      int keyLength;
      if (key != null)
      {
        if (key.Length > KEY_BYTES_MAX || key.Length < KEY_BYTES_MIN)
        {
          throw new ArgumentOutOfRangeException("key", key.Length, 
            string.Format("key must be between {0} and {1} bytes in length.", KEY_BYTES_MIN, KEY_BYTES_MAX));
        }

        keyLength = key.Length;
      }
      else
      {
        key = new byte[0];
        keyLength = 0;
      }

      //validate output length
      if (bytes > BYTES_MAX || bytes < BYTES_MIN)
      {
        throw new ArgumentOutOfRangeException("bytes", bytes,
          string.Format("bytes must be between {0} and {1} bytes in length.", BYTES_MIN, BYTES_MAX));
      }

      var buffer = new byte[bytes];
      _GenericHash(buffer, buffer.Length, message, message.Length, key, keyLength);

      return buffer;
    }

    [DllImport("libsodium-4.dll", EntryPoint = "crypto_generichash", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _GenericHash(byte[] buffer, int bufferLength, byte[] message, long messageLength, byte[] key, int keyLength);
  }
}
