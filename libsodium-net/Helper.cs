using System.Linq;

namespace Sodium
{
  internal static class Helper
  {
    public static string BinaryToHex(byte[] data)
    {
      return string.Concat(data.Select(b => b.ToString("x2")));
    }
  }
}
