using System.Runtime.InteropServices;
using System;

namespace Sodium
{
  /// <summary>Scalar Multiplication</summary>
  public static class ScalarMult
  {
    private const int BYTES = 32;
    private const int SCALAR_BYTES = 32;

    //TODO: Add documentation header
    public static int Bytes()
    {
      return SodiumCore.Is64 ? _Bytes64() : _Bytes86();
    }

    //TODO: Add documentation header
    public static int ScalarBytes()
    {
      return SodiumCore.Is64 ? _ScalarBytes64() : _ScalarBytes86();
    }

    //TODO: Add documentation header
    //TODO: Unit test(s)
    static byte Primitive()
    {
      return SodiumCore.Is64 ? _Primitive64() : _Primitive86();
    }

    //TODO: Add documentation header
    public static int Base(byte[] q, byte[] n)
    {
      return SodiumCore.Is64 ? _Base64(q, n) : _Base86(q, n);
    }

    //TODO: Add documentation header
    public static int Mult(byte[] q, byte[] n, byte[] p)
    {
      //validate the length of the scalar
      if (n == null || n.Length != SCALAR_BYTES)
      {
        throw new ArgumentOutOfRangeException("n", (n == null) ? 0 : n.Length,
          string.Format("n must be {0} bytes in length.", SCALAR_BYTES));
      }

      //validate the length of the group element
      if (p == null || p.Length != BYTES)
      {
        throw new ArgumentOutOfRangeException("p", (p == null) ? 0 : p.Length,
          string.Format("p must be {0} bytes in length.", BYTES));
      }

      return SodiumCore.Is64 ? _ScalarMult64(q, n, p) : _ScalarMult86(q, n, p);
    }

    //crypto_scalarmult_bytes
    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_scalarmult_bytes", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Bytes64();
    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_scalarmult_bytes", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Bytes86();

    //crypto_scalarmult_scalarbytes
    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_scalarmult_scalarbytes", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _ScalarBytes86();
    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_scalarmult_scalarbytes", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _ScalarBytes64();

    //crypto_scalarmult_primitive
    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_scalarmult_primitive", CallingConvention = CallingConvention.Cdecl)]
    private static extern byte _Primitive64();
    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_scalarmult_primitive", CallingConvention = CallingConvention.Cdecl)]
    private static extern byte _Primitive86();

    //crypto_scalarmult_base
    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_scalarmult_base", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Base64(byte[] q, byte[] n);
    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_scalarmult_base", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Base86(byte[] q, byte[] n);

    //crypto_scalarmult
    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_scalarmult", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _ScalarMult64(byte[] q, byte[] n, byte[] p);
    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_scalarmult", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _ScalarMult86(byte[] q, byte[] n, byte[] p);
  }
}
