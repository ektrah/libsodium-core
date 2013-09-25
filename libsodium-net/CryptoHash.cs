using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Sodium
{
  /// <summary>
  /// TODO: Update summary.
  /// </summary>
  public class CryptoHash
  {
    //pulled from various #define statements; may break with new versions
    private const int BYTES = 64;
    private const string PRIMITIVE = "sha512";

    /// <summary>
    /// Hashes a string using the default algorithm  (currently SHA-2-512)
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
    /// Hashes a byte array using the default algorithm  (currently SHA-2-512)
    /// </summary>
    /// <param name="message">
    /// The message.
    /// </param>
    /// <returns>
    /// </returns>
    public static string Hash(byte[] message)
    {
      var buffer = new byte[BYTES];
      _CryptoHash(buffer, message, message.Length);

      return Helper.BinaryToHex(buffer);
    }

    [DllImport("libsodium-4.dll", EntryPoint = "crypto_hash", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _CryptoHash(byte[] buffer, byte[] message, long length);
  }
}
