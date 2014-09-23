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
    private const int OUT_BYTES = 64;
    private const int SALT_BYTES = 16;
    private const int PERSONAL_BYTES = 16;

    /// <summary>Generates a random 64 byte key.</summary>
    /// <returns>Returns a byte array with 64 random bytes</returns>
    public static byte[] GenerateKey()
    {
      return SodiumCore.GetRandomBytes(KEY_BYTES_MAX);
    }

    /// <summary>Hashes a message, with an optional key, using the BLAKE2b primitive.</summary>
    /// <param name="message">The message to be hashed.</param>
    /// <param name="key">The key; may be null, otherwise between 16 and 64 bytes.</param>
    /// <param name="bytes">The size (in bytes) of the desired result.</param>
    /// <returns>Returns a byte array.</returns>
    public static byte[] Hash(string message, string key, int bytes)
    {
      return Hash(message, Encoding.UTF8.GetBytes(key), bytes);
    }

    /// <summary>Hashes a message, with an optional key, using the BLAKE2b primitive.</summary>
    /// <param name="message">The message to be hashed.</param>
    /// <param name="key">The key; may be null, otherwise between 16 and 64 bytes.</param>
    /// <param name="bytes">The size (in bytes) of the desired result.</param>
    /// <returns>Returns a byte array.</returns>
    public static byte[] Hash(string message, byte[] key, int bytes)
    {
      return Hash(Encoding.UTF8.GetBytes(message), key, bytes);
    }

    /// <summary>Hashes a message, with an optional key, using the BLAKE2b primitive.</summary>
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
            throw new KeyOutOfRangeException(string.Format("key must be between {0} and {1} bytes in length.", KEY_BYTES_MIN, KEY_BYTES_MAX));
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
        throw new BytesOutOfRangeException("bytes", bytes,
          string.Format("bytes must be between {0} and {1} bytes in length.", BYTES_MIN, BYTES_MAX));
      }

      var buffer = new byte[bytes];
      var hash = DynamicInvoke.GetDynamicInvoke<_GenericHash>("crypto_generichash", SodiumCore.LibraryName());
      hash(buffer, buffer.Length, message, message.Length, key, keyLength);

      return buffer;
    }

    /// <summary>Generates a hash based on a key, salt and personal strings</summary>
    /// <returns><c>byte</c> hashed message</returns>
    /// <param name="message">Message.</param>
    /// <param name="key">Key.</param>
    /// <param name="salt">Salt.</param>
    /// <param name="personal">Personal.</param>
    public static byte[] HashSaltPersonal(string message, string key, string salt, string personal)
    {
      return HashSaltPersonal(Encoding.UTF8.GetBytes(message), Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(salt), Encoding.UTF8.GetBytes(personal));
    }

    /// <summary>Generates a hash based on a key, salt and personal bytes</summary>
    /// <returns><c>byte</c> hashed message</returns>
    /// <param name="message">Message.</param>
    /// <param name="key">Key.</param>
    /// <param name="salt">Salt.</param>
    /// <param name="personal">Personal string.</param>
    public static byte[] HashSaltPersonal(byte[] message, byte[] key, byte[] salt, byte[] personal)
    {
      if (message == null)
        throw new ArgumentNullException("message", "Message cannot be null");

      if (salt == null)
        throw new ArgumentNullException("salt", "Salt cannot be null");

      if (personal == null)
        throw new ArgumentNullException("personal", "Personal string cannot be null");

      if (key != null && (key.Length > KEY_BYTES_MAX || key.Length < KEY_BYTES_MIN))
        throw new KeyOutOfRangeException(string.Format("key must be between {0} and {1} bytes in length.", KEY_BYTES_MIN, KEY_BYTES_MAX));

      if (key == null)
        key = new byte[0];

      if (salt.Length != SALT_BYTES)
        throw new SaltOutOfRangeException(string.Format("Salt must be {0} bytes in length.", SALT_BYTES));

      if (personal.Length != PERSONAL_BYTES)
        throw new PersonalOutOfRangeException(string.Format("Personal bytes must be {0} bytes in length.", PERSONAL_BYTES));

      var buffer = new byte[OUT_BYTES];

      var hash = DynamicInvoke.GetDynamicInvoke<_GenericHashSaltPersonal>("crypto_generichash_blake2b_salt_personal", SodiumCore.LibraryName());
      hash(buffer, buffer.Length, message, message.LongLength, key, key.Length, salt, personal);

      return buffer;
    }

    //crypto_generichash
    private delegate int _GenericHash(byte[] buffer, int bufferLength, byte[] message, long messageLength, byte[] key, int keyLength);
    //crypto_generichash_blake2b_salt_personal
    private delegate int _GenericHashSaltPersonal(byte[] buffer, int bufferLength, byte[] message, long messageLength, byte[] key, int keyLength, byte[] salt, byte[] personal);
  }
}
