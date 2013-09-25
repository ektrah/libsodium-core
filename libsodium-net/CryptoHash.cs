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
    public static string Hash(string message)
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
    public static string Hash(byte[] message)
    {
      var buffer = new byte[SHA512_BYTES];
      _CryptoHash(buffer, message, message.Length);

      return Helper.BinaryToHex(buffer);
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
    public static string SHA512(string message)
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
    public static string SHA512(byte[] message)
    {
      var buffer = new byte[SHA512_BYTES];
      _SHA512(buffer, message, message.Length);

      return Helper.BinaryToHex(buffer);
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
    public static string SHA256(string message)
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
    public static string SHA256(byte[] message)
    {
      var buffer = new byte[SHA256_BYTES];
      _SHA256(buffer, message, message.Length);

      return Helper.BinaryToHex(buffer);
    }

    [DllImport("libsodium-4.dll", EntryPoint = "crypto_hash", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _CryptoHash(byte[] buffer, byte[] message, long length);

    [DllImport("libsodium-4.dll", EntryPoint = "crypto_hash_sha512", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _SHA512(byte[] buffer, byte[] message, long length);

    [DllImport("libsodium-4.dll", EntryPoint = "crypto_hash_sha256", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _SHA256(byte[] buffer, byte[] message, long length);
  }
}
