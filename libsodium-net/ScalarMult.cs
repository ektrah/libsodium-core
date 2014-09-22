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
    /// Diffie-Hellman (function computes the public key)
    /// </summary>
    /// <param name="q"></param>
    /// <param name="secretKey">A secret key.</param>
    /// <returns></returns>
    public static int Base(byte[] q, byte[] secretKey)
    {
        //validate the length of the scalar
        if (secretKey == null || secretKey.Length != SCALAR_BYTES)
        {
            throw new ArgumentOutOfRangeException("secretKey", (secretKey == null) ? 0 : secretKey.Length,
            string.Format("secretKey must be {0} bytes in length.", SCALAR_BYTES));
        }
        var b = DynamicInvoke.GetDynamicInvoke<_Base>("crypto_scalarmult_base", SodiumCore.LibraryName());
        return b(q, secretKey);
    }

    /// <summary>
    /// Diffie-Hellman (function computes a secret shared by the two keys) 
    /// </summary>
    /// <param name="secretShared"></param>
    /// <param name="secretKey">A secret key.</param>
    /// <param name="publicKey">A public key.</param>
    /// <returns></returns>
    public static int Mult(byte[] secretShared, byte[] secretKey, byte[] publicKey)
    {
      //validate the length of the scalar
      if (secretKey == null || secretKey.Length != SCALAR_BYTES)
      {
          throw new ArgumentOutOfRangeException("secretKey", (secretKey == null) ? 0 : secretKey.Length,
          string.Format("secretKey must be {0} bytes in length.", SCALAR_BYTES));
      }

      //validate the length of the group element
      if (publicKey == null || publicKey.Length != BYTES)
      {
          throw new ArgumentOutOfRangeException("publicKey", (publicKey == null) ? 0 : publicKey.Length,
          string.Format("publicKey must be {0} bytes in length.", BYTES));
      }

      var smult = DynamicInvoke.GetDynamicInvoke<_ScalarMult>("crypto_scalarmult", SodiumCore.LibraryName());
      return smult(secretShared, secretKey, publicKey);
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
