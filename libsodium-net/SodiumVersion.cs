using System.Runtime.InteropServices;

namespace Sodium
{
  /// <summary>
  /// libsodium version information.
  /// </summary>
  public class SodiumVersion
  {
    /// <summary>
    /// Returns the version of libsodium in use.
    /// </summary>
    /// <returns>
    /// The sodium version string.
    /// </returns>
    [DllImport("libsodium-4.dll", EntryPoint = "sodium_version_string")]
    public static extern string SodiumVersionString();
  }
}
