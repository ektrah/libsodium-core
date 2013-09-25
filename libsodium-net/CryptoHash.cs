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

    public static string Hash(string message)
    {
      var buffer = new byte[BYTES];
      var msg = Encoding.UTF8.GetBytes(message);
      _CryptoHash(buffer, msg, msg.Length);

      return Helper.BinaryToHex(buffer);
    }

    [DllImport("libsodium-4.dll", EntryPoint = "crypto_hash", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _CryptoHash(byte[] buffer, byte[] message, long length);
  }
}
