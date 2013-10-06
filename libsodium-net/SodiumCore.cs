using System.Runtime.InteropServices;

namespace Sodium
{
  /// <summary>
  /// libsodium core information.
  /// </summary>
  public static class SodiumCore
  {
    static SodiumCore()
    {
      _Init();
    }
    
    /// <summary>
    /// Returns the version of libsodium in use.
    /// </summary>
    /// <returns>
    /// The sodium version string.
    /// </returns>
    [DllImport("libsodium-4.dll", EntryPoint = "sodium_version_string", CallingConvention = CallingConvention.Cdecl)]
    public static extern string SodiumVersionString();

    [DllImport("libsodium-4.dll", EntryPoint = "sodium_init", CallingConvention = CallingConvention.Cdecl)]
    private static extern string _Init();
  }
}
