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
        var b = DynamicInvoke.GetDynamicInvoke<_Bytes>("crypto_scalarmult_bytes", SodiumCore.LibraryName());
        return b();
    }

    //TODO: Add documentation header
    public static int ScalarBytes()
    {
        var sb = DynamicInvoke.GetDynamicInvoke<_ScalarBytes>("crypto_scalarmult_scalarbytes", SodiumCore.LibraryName());
        return sb();
    }

    //TODO: Add documentation header
    //TODO: Unit test(s)
    static byte Primitive()
    {
        var p = DynamicInvoke.GetDynamicInvoke<_Primitive>("crypto_scalarmult_primitive", SodiumCore.LibraryName());
        return p();
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="q"></param>
    /// <param name="n"></param>
    /// <returns></returns>
    public static int Base(byte[] q, byte[] n)
    {
        var b = DynamicInvoke.GetDynamicInvoke<_Base>("crypto_scalarmult_base", SodiumCore.LibraryName());
        return b(q, n);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="q"></param>
    /// <param name="n"></param>
    /// <param name="p"></param>
    /// <returns></returns>
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

      var smult = DynamicInvoke.GetDynamicInvoke<_ScalarMult>("crypto_scalarmult", SodiumCore.LibraryName());
      return smult(q, n, p);
    }

    //crypto_scalarmult_bytes
    private delegate int _Bytes();
    //crypto_scalarmult_scalarbytes
    private delegate int _ScalarBytes();
    //crypto_scalarmult_primitive
    private delegate byte _Primitive();
    //crypto_scalarmult_base
    private delegate int _Base(byte[] q, byte[] n);
    //crypto_scalarmult
    private delegate int _ScalarMult(byte[] q, byte[] n, byte[] p);
  }
}
