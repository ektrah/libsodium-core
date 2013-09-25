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
      return string.Concat(data.Select(b => b.ToString("x2")));
    }
  }
}
