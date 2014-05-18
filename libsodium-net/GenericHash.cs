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

    /// <summary>
    /// Determines the result based on hashing a message with a key, a salt and a personal parameter.
    /// </summary>
    /// <returns><c>1</c> if the hash was generated correctly.</returns>
    /// <param name="result">Result.</param>
    /// <param name="message">Message.</param>
    /// <param name="key">Key.</param>
    /// <param name="salt">Salt.</param>
    /// <param name="personal">Personal.</param>
    public static int HashSaltPersonal(out byte[] output, byte[] message, byte[] key, byte[] salt, byte[] personal)
    {
      output = new byte[BYTES_MAX];

      return _GenericHashSaltPersonal(out output, output.GetLongLength(0), message, message.GetLongLength(0), key, BYTES_MAX, salt, personal);
    }

    [DllImport(SodiumCore.LIBRARY_NAME, EntryPoint = "crypto_generichash", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _GenericHash(byte[] buffer, int bufferLength, byte[] message, long messageLength, byte[] key, int keyLength);

    [DllImport(SodiumCore.LIBRARY_NAME, EntryPoint = "crypto_generichash_blake2b_salt_personal", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _GenericHashSaltPersonal(out byte[] output, long outputLength, byte[] message, long messageLen, byte[] key, long keyLength, byte[] salt, byte[] personal);

  }
}
