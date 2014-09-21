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

      var init = DynamicInvoke.GetDynamicInvoke<_Init>("sodium_init", LibraryName());
      init();
    }

    /// <summary>Gets random bytes</summary>
    /// <param name="count">The count of bytes to return.</param>
    /// <returns>An array of random bytes.</returns>
    public static byte[] GetRandomBytes(int count)
    {
      var buffer = new byte[count];

      var rnd = DynamicInvoke.GetDynamicInvoke<_GetRandomBytes>("randombytes_buf", LibraryName());
      rnd(buffer, count);

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
      var ver = DynamicInvoke.GetDynamicInvoke<_SodiumVersionString>("sodium_version_string", LibraryName());
      var ptr = ver();

      return Marshal.PtrToStringAnsi(ptr);
    }

    internal static bool IsRunningOnMono()
    {
      return Type.GetType("Mono.Runtime") != null;
    }

    internal static string LibraryName()
    {
      if (Is64)
        return LIBRARY_X64;
      else
        return LIBRARY_X86;
    }

    private delegate IntPtr _SodiumVersionString();
    private delegate void _Init();
    private delegate void _GetRandomBytes(byte[] buffer, int size);

    //randombytes_buf
    [DllImport(LIBRARY_X86, EntryPoint = "randombytes_buf", CallingConvention = CallingConvention.Cdecl)]
    private static extern void _GetRandomBytes86(byte[] buffer, int size);
    [DllImport(LIBRARY_X64, EntryPoint = "randombytes_buf", CallingConvention = CallingConvention.Cdecl)]
    private static extern void _GetRandomBytes64(byte[] buffer, int size);
  }
}
