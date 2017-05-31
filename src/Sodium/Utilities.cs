using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Sodium
{
  /// <summary>Various utility methods.</summary>
  public static class Utilities
  { 
    /// <summary>Represents HEX formats.</summary>
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

    /// <summary>Represents HEX cases.</summary>
    public enum HexCase
    {
      /// <summary>lower-case hex-encoded.</summary>
      Lower,
      /// <summary>upper-case hex-encoded</summary>
      Upper
    }

    /// <summary>Takes a byte array and returns a hex-encoded string.</summary>
    /// <param name="data">Data to be encoded.</param>
    /// <returns>Hex-encoded string, lodercase.</returns>
    /// <exception cref="OverflowException"></exception>
    public static string BinaryToHex(byte[] data)
    {
      var hex = new byte[data.Length * 2 + 1];
      var ret = SodiumLibrary.sodium_bin2hex(hex, hex.Length, data, data.Length);

      if (ret == IntPtr.Zero)
      {
        throw new OverflowException("Internal error, encoding failed.");
      }

      return Marshal.PtrToStringAnsi(ret);
    }

    /// <summary>Takes a byte array and returns a hex-encoded string.</summary>
    /// <param name="data">Data to be encoded.</param>
    /// <param name="format">Output format.</param>
    /// <param name="hcase">Lowercase or uppercase.</param>
    /// <returns>Hex-encoded string.</returns>
    /// <remarks>Bit fiddling by CodeInChaos.</remarks>
    /// <remarks>This method don`t use libsodium, but it can be useful for generating human readable fingerprints.</remarks>
    public static string BinaryToHex(byte[] data, HexFormat format, HexCase hcase = HexCase.Lower)
    {
      var sb = new StringBuilder();

      for (var i = 0; i < data.Length; i++)
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

        var byteValue = data[i] >> 4;

        if (hcase == HexCase.Lower)
        {
          sb.Append((char)(87 + byteValue + (((byteValue - 10) >> 31) & -39))); //lower
        }
        else
        {
          sb.Append((char)(55 + byteValue + (((byteValue - 10) >> 31) & -7))); //upper 
        }
        byteValue = data[i] & 0xF;

        if (hcase == HexCase.Lower)
        {
          sb.Append((char)(87 + byteValue + (((byteValue - 10) >> 31) & -39))); //lower
        }
        else
        {
          sb.Append((char)(55 + byteValue + (((byteValue - 10) >> 31) & -7))); //upper 
        }
      }

      return sb.ToString();
    }

    /// <summary>Converts a hex-encoded string to a byte array.</summary>
    /// <param name="hex">Hex-encoded data.</param>
    /// <returns>A byte array of the decoded string.</returns>
    /// <exception cref="Exception"></exception>
    public static byte[] HexToBinary(string hex)
    {
      const string IGNORED_CHARS = ":- ";

      var arr = new byte[hex.Length >> 1];
      var bin = Marshal.AllocHGlobal(arr.Length);
      int binLength;

      //we call sodium_hex2bin with some chars to be ignored
      var ret = SodiumLibrary.sodium_hex2bin(bin, arr.Length, hex, hex.Length, IGNORED_CHARS, out binLength, null);

      Marshal.Copy(bin, arr, 0, binLength);
      Marshal.FreeHGlobal(bin);

      if (ret != 0)
      {
        throw new Exception("Internal error, decoding failed.");
      }

      //remove the trailing nulls from the array, if there were some format characters in the hex string before
      if (arr.Length != binLength)
      {
        var tmp = new byte[binLength];
        Array.Copy(arr, 0, tmp, 0, binLength);
        return tmp;
      }

      return arr;
    }

    /// <summary>
    /// Takes a unsigned number, and increments it.
    /// </summary>
    /// <param name="value">The value to increment.</param>
    /// <returns>The incremented value.</returns>
    public static byte[] Increment(byte[] value)
    {
      var buffer = value;
      SodiumLibrary.sodium_increment(buffer, buffer.Length);

      return buffer;
    }

    /// <summary>
    /// Compares two values in constant time.
    /// </summary>
    /// <param name="a">The first value.</param>
    /// <param name="b">The second value.</param>
    /// <returns><c>true</c> if the values are equal, otherwise <c>false</c></returns>
    public static bool Compare(byte[] a, byte[] b)
    {
      var ret = SodiumLibrary.sodium_compare(a, b, a.Length);

      return ret == 0;
    }
  }
}
