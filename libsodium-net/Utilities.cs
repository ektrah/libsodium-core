using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Sodium
{
  /// <summary>
  /// Various utility methods.
  /// </summary>
  public static class Utilities
  {
    /*
    /// <summary>
    /// Takes a byte array and returns a hex-encoded string.
    /// </summary>
    /// <param name="data">Data to be encoded.</param>
    /// <returns>Hex-encoded string, uppercase.</returns>
    /// <remarks>Bit fiddling by CodeInChaos.</remarks>
    public static string BinaryToHex2(byte[] data)
    {
      char[] c = new char[data.Length * 2];
      int b;
      for (int i = 0; i < data.Length; i++) {
          b = data[i] >> 4;
          c[i * 2] = (char)(55 + b + (((b-10)>>31)&-7));
          b = data[i] & 0xF;
          c[i * 2 + 1] = (char)(55 + b + (((b-10)>>31)&-7));
        }
      return new string(c);
    }*/

    /// <summary>
    /// Takes a byte array and returns a hex-encoded string.
    /// </summary>
    /// <param name="data">Data to be encoded.</param>
    /// <returns>Hex-encoded string, lodercase.</returns>
    public static string BinaryToHex(byte[] data)
    {
        byte[] hex = new byte[data.Length * 2 + 1];
        IntPtr ret;

        if (SodiumCore.Is64)
        {
            ret = _SODIUM_BIN2HEX_X64(hex, hex.Length, data, data.Length);
        }
        else
        {
            ret = _SODIUM_BIN2HEX_X86(hex, hex.Length, data, data.Length);
        }
        if (ret == null)
            throw new OverflowException("Internal error, encoding failed.");

        return Marshal.PtrToStringAnsi(ret);
    }

    /// <summary>
    /// Takes a byte array and returns a hex-encoded string.
    /// </summary>
    /// <param name="data">Data to be encoded.</param>
    /// <param name="format">Output format.</param>
    /// <param name="hcase">Lowercase or uppercase.</param>
    /// <returns>Hex-encoded string.</returns>
    /// <remarks>Bit fiddling by CodeInChaos.</remarks>
    /// <remarks>This method don`t use libsodium, but it can be useful for generating human readable fingerprints.</remarks>
    public static string BinaryToHex(byte[] data, HexFormat format = HexFormat.None, HexCase hcase = HexCase.Lower)
    {
        StringBuilder sb = new StringBuilder();
        int b;
        for (int i = 0; i < data.Length; i++)
        {
            if ((i != 0) && (format != HexFormat.None))
            {
                switch (format)
                {
                    case HexFormat.Colon:
                        sb.Append((char)58);
                        break;
                    case HexFormat.Hyphen:
                        sb.Append((char)45);
                        break;
                    case HexFormat.Space:
                        sb.Append((char)32);
                        break;
                    default:
                        //no formatting
                        break;
                }
            }
            b = data[i] >> 4;
            if (hcase == HexCase.Lower)
            {
                sb.Append((char)(87 + b + (((b - 10) >> 31) & -39))); //lower
            }
            else
            {
                sb.Append((char)(55 + b + (((b - 10) >> 31) & -7))); //upper 
            }
            b = data[i] & 0xF;
            if (hcase == HexCase.Lower)
            {
                sb.Append((char)(87 + b + (((b - 10) >> 31) & -39))); //lower
            }
            else
            {
                sb.Append((char)(55 + b + (((b - 10) >> 31) & -7))); //upper 
            }
        }
        return sb.ToString();
    }

    /// <summary>
    /// Converts a hex-encoded string to a byte array
    /// </summary>
    /// <param name="hex">Hex-encoded data</param>
    /// <returns></returns>
    /// <remarks>
    /// Shamelessly pulled from http://stackoverflow.com/questions/321370/convert-hex-string-to-byte-array
    /// </remarks>
    public static byte[] HexToBinary(string hex)
    {
      if (hex.Length % 2 == 1)
      {
        throw new ArgumentException("The binary key cannot have an odd number of digits");
      }
      
      var arr = new byte[hex.Length >> 1];

      for (var i = 0; i < (hex.Length >> 1); ++i)
      {
        arr[i] = (byte)((_GetHexVal(hex[i << 1]) << 4) + (_GetHexVal(hex[(i << 1) + 1])));
      }

      return arr;
    }

    private static int _GetHexVal(char hex)
    {
      int val = hex;
      return val - (val < 58 ? 48 : 87);
    }

    //sodium_bin2hex
    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "sodium_bin2hex", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr _SODIUM_BIN2HEX_X64(byte[] hex, long hex_maxlen, byte[] bin, long bin_len);
    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "sodium_bin2hex", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr _SODIUM_BIN2HEX_X86(byte[] hex, int hex_maxlen, byte[] bin, long bin_len);
  }

  /// <summary>
  /// Represents HEX formats.
  /// </summary>
  public enum HexFormat
  {
      /// <summary>a hex string without seperators.</summary>
      None,
      /// <summary>a hex string with colons (dd:33:dd).</summary>
      Colon,
      /// <summary>a hex string with hyphens (dd-33-dd).</summary>
      Hyphen,
      /// <summary>a hex string with spaces (dd 33 dd).</summary>
      Space
  }

  /// <summary>
  /// Represents HEX cases.
  /// </summary>
  public enum HexCase
  {
      /// <summary>lower-case hex-encoded.</summary>
      Lower,
      /// <summary>upper-case hex-encoded</summary>
      Upper
  }
}
