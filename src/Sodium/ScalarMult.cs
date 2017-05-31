using Sodium.Exceptions;

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
      return SodiumLibrary.crypto_scalarmult_bytes();
    }

    //TODO: Add documentation header
    public static int ScalarBytes()
    {
      return SodiumLibrary.crypto_scalarmult_scalarbytes();
    }

    //TODO: Add documentation header
    //TODO: Unit test(s)
    static byte Primitive()
    {
      return SodiumLibrary.crypto_scalarmult_primitive();
    }

    /// <summary>
    /// Diffie-Hellman (function computes the public key)
    /// </summary>
    /// <param name="secretKey">A secret key.</param>
    /// <returns>A computed public key.</returns>
    /// <exception cref="KeyOutOfRangeException"></exception>
    public static byte[] Base(byte[] secretKey)
    {
      //validate the length of the scalar
      if (secretKey == null || secretKey.Length != SCALAR_BYTES)
        throw new KeyOutOfRangeException("secretKey", (secretKey == null) ? 0 : secretKey.Length,
          string.Format("secretKey must be {0} bytes in length.", SCALAR_BYTES));

      var publicKey = new byte[SCALAR_BYTES];
      SodiumLibrary.crypto_scalarmult_base(publicKey, secretKey);

      return publicKey;
    }

    /// <summary>
    /// Diffie-Hellman (function computes a secret shared by the two keys) 
    /// </summary>
    /// <param name="secretKey">A secret key.</param>
    /// <param name="publicKey">A public key.</param>
    /// <returns>A computed secret shared.</returns>
    /// <exception cref="KeyOutOfRangeException"></exception>
    public static byte[] Mult(byte[] secretKey, byte[] publicKey)
    {
      //validate the length of the scalar
      if (secretKey == null || secretKey.Length != SCALAR_BYTES)
        throw new KeyOutOfRangeException("secretKey", (secretKey == null) ? 0 : secretKey.Length,
          string.Format("secretKey must be {0} bytes in length.", SCALAR_BYTES));

      //validate the length of the group element
      if (publicKey == null || publicKey.Length != BYTES)
        throw new KeyOutOfRangeException("publicKey", (publicKey == null) ? 0 : publicKey.Length,
          string.Format("publicKey must be {0} bytes in length.", BYTES));

      var secretShared = new byte[BYTES];
      SodiumLibrary.crypto_scalarmult(secretShared, secretKey, publicKey);

      return secretShared;
    }
  }
}
