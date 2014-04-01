using System.Runtime.InteropServices;
using System;

namespace Sodium
{
  /// <summary>
  /// Scalar Multiplication
  /// </summary>
  public static class ScalarMult
  {
    private const int BYTES = 32;
    private const int SCALAR_BYTES = 32;

    public static int Bytes()
    {
      return _Bytes();
    }

    public static int ScalarBytes()
    {
      return _ScalarBytes();
    }

    public static byte Primitive()
    {
      return _Primitive();
    }

    public static int Base(byte[] q, byte[] n)
    {
      return _Base(q, n);
    }

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

      return _ScalarMult(q, n, p);
    }

    [DllImport(SodiumCore.LIBRARY_NAME, EntryPoint = "crypto_scalarmult_bytes", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Bytes();

    [DllImport(SodiumCore.LIBRARY_NAME, EntryPoint = "crypto_scalarmult_scalarbytes", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _ScalarBytes();

    [DllImport(SodiumCore.LIBRARY_NAME, EntryPoint = "crypto_scalarmult_primitive", CallingConvention = CallingConvention.Cdecl)]
    private static extern byte _Primitive();

    [DllImport(SodiumCore.LIBRARY_NAME, EntryPoint = "crypto_scalarmult_base", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Base(byte[] q, byte[] n);

    [DllImport(SodiumCore.LIBRARY_NAME, EntryPoint = "crypto_scalarmult", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _ScalarMult(byte[] q, byte[] n, byte[] p);
  }
}
