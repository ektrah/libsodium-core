using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Sodium
{
  /// <summary>
  /// Provides hashing via selected primitive.
  /// </summary>
  public class CryptoHash
  {
    //pulled from various #define statements; may break with new versions
    private const int SHA512_BYTES = 64;

    private const int SHA256_BYTES = 32;

    /// <summary>
    /// Hashes a string using the default algorithm (This is what you want to use)
    /// </summary>
    /// <param name="message">
    /// The message.
    /// </param>
    /// <returns>
    /// Hex-encoded hash.
    /// </returns>
    public static byte[] Hash(string message)
    {
      return Hash(Encoding.UTF8.GetBytes(message));
    }

    /// <summary>
    /// Hashes a byte array using the default algorithm (This is what you want to use)
    /// </summary>
    /// <param name="message">
    /// The message.
    /// </param>
    /// <returns>
    /// </returns>
    public static byte[] Hash(byte[] message)
    {
      var buffer = new byte[SHA512_BYTES];

      if (SodiumCore.Is64)
        _CryptoHash64(buffer, message, message.Length);
      else
        _CryptoHash86(buffer, message, message.Length);

      return buffer;
    }

    /// <summary>
    /// Hashes a string using the SHA512 algorithm
    /// </summary>
    /// <param name="message">
    /// The message.
    /// </param>
    /// <returns>
    /// Hex-encoded hash.
    /// </returns>
    public static byte[] SHA512(string message)
    {
      return SHA512(Encoding.UTF8.GetBytes(message));
    }

    /// <summary>
    /// Hashes a byte array using the SHA512 algorithm
    /// </summary>
    /// <param name="message">
    /// The message.
    /// </param>
    /// <returns>
    /// </returns>
    public static byte[] SHA512(byte[] message)
    {
      var buffer = new byte[SHA512_BYTES];

      if (SodiumCore.Is64)
        _SHA51264(buffer, message, message.Length);
      else
        _SHA51286(buffer, message, message.Length);

      return buffer;
    }

    /// <summary>
    /// Hashes a string using the SHA256 algorithm
    /// </summary>
    /// <param name="message">
    /// The message.
    /// </param>
    /// <returns>
    /// Hex-encoded hash.
    /// </returns>
    public static byte[] SHA256(string message)
    {
      return SHA256(Encoding.UTF8.GetBytes(message));
    }

    /// <summary>
    /// Hashes a byte array using the SHA256 algorithm
    /// </summary>
    /// <param name="message">
    /// The message.
    /// </param>
    /// <returns>
    /// </returns>
    public static byte[] SHA256(byte[] message)
    {
      var buffer = new byte[SHA256_BYTES];

      if (SodiumCore.Is64)
        _SHA25664(buffer, message, message.Length);
      else
        _SHA25686(buffer, message, message.Length);

      return buffer;
    }

    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_hash", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _CryptoHash64(byte[] buffer, byte[] message, long length);

    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_hash_sha512", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _SHA51264(byte[] buffer, byte[] message, long length);

    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_hash_sha256", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _SHA25664(byte[] buffer, byte[] message, long length);

    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_hash", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _CryptoHash86(byte[] buffer, byte[] message, long length);

    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_hash_sha512", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _SHA51286(byte[] buffer, byte[] message, long length);

    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_hash_sha256", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _SHA25686(byte[] buffer, byte[] message, long length);
  }
}
