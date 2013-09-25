using System;
using System.Linq;

namespace Sodium
{
  internal static class Helper
  {
    /// <summary>
    /// Takes a byte array and returns a hex-encoded string
    /// </summary>
    /// <param name="data">Data to be encoded</param>
    /// <returns>Hex-encoded string, lowercase.</returns>
    public static string BinaryToHex(byte[] data)
    {
      //TODO: Find a faster version of this...
      return string.Concat(data.Select(b => b.ToString("x2")));
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

      for (int i = 0; i < hex.Length >> 1; ++i)
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
  }
}
