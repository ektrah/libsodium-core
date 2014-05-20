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
    private const int BLAKE2B_OUTBYTES = 64;
    private const int BLAKE2B_SALTBYTES = 16;
    private const int BLAKE2B_PERSONALBYTES = 16;

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
    /// Generates a hash based on a key, salt and personal strings
    /// </summary>
    /// <returns><c>byte</c> hashed message</returns>
    /// <param name="message">Message.</param>
    /// <param name="key">Key.</param>
    /// <param name="salt">Salt.</param>
    /// <param name="personal">Personal.</param>
    public static byte[] HashSaltPersonal(string message, string key, string salt, string personal)
    {
      return HashSaltPersonal(Encoding.UTF8.GetBytes(message), Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(salt), Encoding.UTF8.GetBytes(personal));
    }

    /// <summary>
    /// Generates a hash based on a key, salt and personal bytes
    /// </summary>
    /// <returns><c>byte</c> hashed message</returns>
    /// <param name="message">Message.</param>
    /// <param name="key">Key.</param>
    /// <param name="salt">Salt.</param>
    /// <param name="personal">Personal.</param>
    public static byte[] HashSaltPersonal(byte[] message, byte[] key, byte[] salt, byte[] personal)
    {
      if (message == null || key == null || salt == null || personal == null)
        throw new ArgumentNullException("Message, key, salt or personal cannot be null");

      if (key.Length == 0 || key.Length > KEY_BYTES_MAX)
        throw new ArgumentOutOfRangeException (string.Format ("Key must be {0} bytes in length.", KEY_BYTES_MAX));

      if (salt.Length == 0 || salt.Length > BLAKE2B_SALTBYTES)
        throw new ArgumentOutOfRangeException (string.Format ("Salt must be {0} bytes in length.", BLAKE2B_SALTBYTES));

      if (personal.Length == 0 || personal.Length > BLAKE2B_PERSONALBYTES)
        throw new ArgumentOutOfRangeException (string.Format ("Personal bytes must be {0} bytes in length.", BLAKE2B_PERSONALBYTES));

      byte[] buffer = new byte[BLAKE2B_OUTBYTES];

      _GenericHashSaltPersonal(buffer, buffer.Length, message, message.LongLength, key, key.Length, salt, personal);

      return buffer;
    }

    [DllImport(SodiumCore.LIBRARY_NAME, EntryPoint = "crypto_generichash", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _GenericHash(byte[] buffer, int bufferLength, byte[] message, long messageLength, byte[] key, int keyLength);

    [DllImport(SodiumCore.LIBRARY_NAME, EntryPoint = "crypto_generichash_blake2b_salt_personal", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _GenericHashSaltPersonal(byte[] buffer, int bufferLength, byte[] message, long messageLen, byte[] key, int keyLength, byte[] salt, byte[] personal);

  }
}
