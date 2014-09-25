using System;
using System.Runtime.InteropServices;
namespace Sodium
{
  /// <summary>
  /// libsodium core information.
  /// </summary>
  public static class SodiumCore
  {
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
      const string LIBRARY_X86 = "libsodium.dll";
      const string LIBRARY_X64 = "libsodium-64.dll";
      const string LIBRARY_MONO = "libsodium";

      var lib = Is64 ? LIBRARY_X64 : LIBRARY_X86;

      //if we're on mono, override
      if (IsRunningOnMono())
      {
        lib = LIBRARY_MONO;
      }

      return lib;
    }

    private delegate IntPtr _SodiumVersionString();
    private delegate void _Init();
    private delegate void _GetRandomBytes(byte[] buffer, int size);
  }
}
