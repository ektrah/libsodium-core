using System;
using System.Runtime.InteropServices;
namespace Sodium
{
  /// <summary>
  /// libsodium core information.
  /// </summary>
  public static class SodiumCore
  {
    internal const string LIBRARY_X86 = "libsodium.dll";
    internal const string LIBRARY_X64 = "libsodium-64.dll";

    internal static bool Is64 { get; private set; }
    
    static SodiumCore()
    {
      Is64 = (IntPtr.Size == 8);

      if (Is64)
        _Init64();
      else
        _Init86();
    }

    /// <summary>Gets random bytes</summary>
    /// <param name="count">The count of bytes to return.</param>
    /// <returns>An array of random bytes.</returns>
    public static byte[] GetRandomBytes(int count)
    {
      var buffer = new byte[count];

      if (Is64)
        _GetRandomBytes64(buffer, count);
      else
        _GetRandomBytes86(buffer, count);

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
      IntPtr ptr;

      if (Is64)
        ptr = _SodiumVersionString64();
      else
        ptr = _SodiumVersionString86();

      return Marshal.PtrToStringAnsi(ptr);
    }

    [DllImport(LIBRARY_X86, EntryPoint = "sodium_version_string", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr _SodiumVersionString86();

    [DllImport(LIBRARY_X86, EntryPoint = "sodium_init", CallingConvention = CallingConvention.Cdecl)]
    private static extern void _Init86();

    [DllImport(LIBRARY_X86, EntryPoint = "randombytes_buf", CallingConvention = CallingConvention.Cdecl)]
    private static extern void _GetRandomBytes86(byte[] buffer, int size);

    [DllImport(LIBRARY_X64, EntryPoint = "sodium_version_string", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr _SodiumVersionString64();

    [DllImport(LIBRARY_X64, EntryPoint = "sodium_init", CallingConvention = CallingConvention.Cdecl)]
    private static extern void _Init64();

    [DllImport(LIBRARY_X64, EntryPoint = "randombytes_buf", CallingConvention = CallingConvention.Cdecl)]
    private static extern void _GetRandomBytes64(byte[] buffer, int size);
  }
}
