using System;
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

    /// <summary>Gets random bytes</summary>
    /// <param name="count">The count of bytes to return.</param>
    /// <returns>An array of random bytes.</returns>
    public static byte[] GetRandomBytes(int count)
    {
      var buffer = new byte[count];

      _GetRandomBytes(buffer, count);

      return buffer;
    }

    /// <summary>
    /// Returns the version of libsodium in use.
    /// </summary>
    /// <returns>
    /// The sodium version string.
    /// </returns>
    public static string SodiumVersionString()
    {
      var ptr = _SodiumVersionString();
      return Marshal.PtrToStringAnsi(ptr);
    }

    [DllImport("libsodium", EntryPoint = "sodium_version_string", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr _SodiumVersionString();

    [DllImport("libsodium", EntryPoint = "sodium_init", CallingConvention = CallingConvention.Cdecl)]
    private static extern void _Init();

    [DllImport("libsodium", EntryPoint = "randombytes_buf", CallingConvention = CallingConvention.Cdecl)]
    private static extern void _GetRandomBytes(byte[] buffer, int size);
  }
}
