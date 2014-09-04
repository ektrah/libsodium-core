using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Sodium
{
  /// <summary>
  /// One Time Message Authentication
  /// </summary>
  public static class SecretKeyAuth
  {
    private const int KEY_BYTES = 32;
    private const int BYTES = 32;

    private const int CRYPTO_AUTH_HMACSHA256_KEY_BYTES = 32;
    private const int CRYPTO_AUTH_HMACSHA256_BYTES = 32;

    private const int CRYPTO_AUTH_HMACSHA512_KEY_BYTES = 32;
    private const int CRYPTO_AUTH_HMACSHA512_BYTES = 64;

    /// <summary>Generates a random 32 byte key.</summary>
    /// <returns>Returns a byte array with 32 random bytes</returns>
    public static byte[] GenerateKey()
    {
      return SodiumCore.GetRandomBytes(KEY_BYTES);
    }

    /// <summary>Signs a message with HMAC-SHA512-256.</summary>
    /// <param name="message">The message.</param>
    /// <param name="key">The 32 byte key.</param>
    /// <returns>32 byte authentication code.</returns>
    public static byte[] Sign(string message, byte[] key)
    {
      return Sign(Encoding.UTF8.GetBytes(message), key);
    }

    /// <summary>Signs a message with HMAC-SHA512-256.</summary>
    /// <param name="message">The message.</param>
    /// <param name="key">The 32 byte key.</param>
    /// <returns>32 byte authentication code.</returns>
    public static byte[] Sign(byte[] message, byte[] key)
    {
      //validate the length of the key
      if (key == null || key.Length != KEY_BYTES)
      {
        throw new ArgumentOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", KEY_BYTES));
      }

      var buffer = new byte[BYTES];
      
      if (SodiumCore.Is64)
        _Sign64(buffer, message, message.Length, key);
      else
        _Sign86(buffer, message, message.Length, key);

      return buffer;
    }

    /// <summary>Verifies a message signed with the Sign method.</summary>
    /// <param name="message">The message.</param>
    /// <param name="signature">The 32 byte signature.</param>
    /// <param name="key">The 32 byte key.</param>
    /// <returns>True if verified.</returns>
    public static bool Verify(string message, byte[] signature, byte[] key)
    {
      return Verify(Encoding.UTF8.GetBytes(message), signature, key);
    }

    /// <summary>Verifies a message signed with the Sign method.</summary>
    /// <param name="message">The message.</param>
    /// <param name="signature">The 32 byte signature.</param>
    /// <param name="key">The 32 byte key.</param>
    /// <returns>True if verified.</returns>
    public static bool Verify(byte[] message, byte[] signature, byte[] key)
    {
      //validate the length of the key
      if (key == null || key.Length != KEY_BYTES)
      {
        throw new ArgumentOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", KEY_BYTES));
      }

      //validate the length of the signature
      if (signature == null || signature.Length != BYTES)
      {
        throw new ArgumentOutOfRangeException("signature", (signature == null) ? 0 : signature.Length,
          string.Format("signature must be {0} bytes in length.", BYTES));
      }

      var ret = SodiumCore.Is64
                  ? _Verify64(signature, message, message.Length, key)
                  : _Verify86(signature, message, message.Length, key);

      return ret == 0;
    }

    /// <summary>Signs a message with HMAC-SHA-256.</summary>
    /// <param name="message">The message.</param>
    /// <param name="key">The 32 byte key.</param>
    /// <returns>32 byte authentication code.</returns>
    public static byte[] SignHmacSha256(byte[] message, byte[] key)
    {
        //validate the length of the key
        if (key == null || key.Length != CRYPTO_AUTH_HMACSHA256_KEY_BYTES)
        {
            throw new ArgumentOutOfRangeException("key", (key == null) ? 0 : key.Length,
              string.Format("key must be {0} bytes in length.", CRYPTO_AUTH_HMACSHA256_KEY_BYTES));
        }

        var buffer = new byte[CRYPTO_AUTH_HMACSHA256_BYTES];

        if (SodiumCore.Is64)
            _CRYPTO_AUTH_HMACSHA256_64(buffer, message, message.Length, key);
        else
            _CRYPTO_AUTH_HMACSHA256_86(buffer, message, message.Length, key);

        return buffer;
    }

    /// <summary>Signs a message with HMAC-SHA-256.</summary>
    /// <param name="message">The message.</param>
    /// <param name="key">The 32 byte key.</param>
    /// <returns>32 byte authentication code.</returns>
    public static byte[] SignHmacSha256(string message, byte[] key)
    {
        return SignHmacSha256(Encoding.UTF8.GetBytes(message), key);
    }

    /// <summary>Signs a message with HMAC-SHA-512.</summary>
    /// <param name="message">The message.</param>
    /// <param name="key">The 32 byte key.</param>
    /// <returns>64 byte authentication code.</returns>
    public static byte[] SignHmacSha512(byte[] message, byte[] key)
    {
        //validate the length of the key
        if (key == null || key.Length != CRYPTO_AUTH_HMACSHA512_KEY_BYTES)
        {
            throw new ArgumentOutOfRangeException("key", (key == null) ? 0 : key.Length,
              string.Format("key must be {0} bytes in length.", CRYPTO_AUTH_HMACSHA512_KEY_BYTES));
        }

        var buffer = new byte[CRYPTO_AUTH_HMACSHA512_BYTES];

        if (SodiumCore.Is64)
            _CRYPTO_AUTH_HMACSHA512_64(buffer, message, message.Length, key);
        else
            _CRYPTO_AUTH_HMACSHA512_86(buffer, message, message.Length, key);

        return buffer;
    }

    /// <summary>Signs a message with HMAC-SHA-512.</summary>
    /// <param name="message">The message.</param>
    /// <param name="key">The 32 byte key.</param>
    /// <returns>64 byte authentication code.</returns>
    public static byte[] SignHmacSha512(string message, byte[] key)
    {
        return SignHmacSha512(Encoding.UTF8.GetBytes(message), key);
    }

    /// <summary>Verifies a message signed with the SignHmacSha256 method.</summary>
    /// <param name="message">The message.</param>
    /// <param name="signature">The 32 byte signature.</param>
    /// <param name="key">The 32 byte key.</param>
    /// <returns>True if verified.</returns>
    public static bool VerifyHmacSha256(string message, byte[] signature, byte[] key)
    {
        return VerifyHmacSha256(Encoding.UTF8.GetBytes(message), signature, key);
    }

    /// <summary>Verifies a message signed with the SignHmacSha256 method.</summary>
    /// <param name="message">The message.</param>
    /// <param name="signature">The 32 byte signature.</param>
    /// <param name="key">The 32 byte key.</param>
    /// <returns>True if verified.</returns>
    public static bool VerifyHmacSha256(byte[] message, byte[] signature, byte[] key)
    {
        //validate the length of the key
        if (key == null || key.Length != CRYPTO_AUTH_HMACSHA256_KEY_BYTES)
        {
            throw new ArgumentOutOfRangeException("key", (key == null) ? 0 : key.Length,
              string.Format("key must be {0} bytes in length.", CRYPTO_AUTH_HMACSHA256_KEY_BYTES));
        }

        //validate the length of the signature
        if (signature == null || signature.Length != CRYPTO_AUTH_HMACSHA256_BYTES)
        {
            throw new ArgumentOutOfRangeException("signature", (signature == null) ? 0 : signature.Length,
              string.Format("signature must be {0} bytes in length.", CRYPTO_AUTH_HMACSHA256_BYTES));
        }

        var ret = SodiumCore.Is64
                    ? _CRYPTO_AUTH_HMACSHA256_VERIFY_64(signature, message, message.Length, key)
                    : _CRYPTO_AUTH_HMACSHA256_VERIFY_86(signature, message, message.Length, key);

        return ret == 0;
    }

    /// <summary>Verifies a message signed with the SignHmacSha512 method.</summary>
    /// <param name="message">The message.</param>
    /// <param name="signature">The 64 byte signature.</param>
    /// <param name="key">The 32 byte key.</param>
    /// <returns>True if verified.</returns>
    public static bool VerifyHmacSha512(string message, byte[] signature, byte[] key)
    {
        return VerifyHmacSha512(Encoding.UTF8.GetBytes(message), signature, key);
    }

    /// <summary>Verifies a message signed with the SignHmacSha512 method.</summary>
    /// <param name="message">The message.</param>
    /// <param name="signature">The 64 byte signature.</param>
    /// <param name="key">The 32 byte key.</param>
    /// <returns>True if verified.</returns>
    public static bool VerifyHmacSha512(byte[] message, byte[] signature, byte[] key)
    {
        //validate the length of the key
        if (key == null || key.Length != CRYPTO_AUTH_HMACSHA512_KEY_BYTES)
        {
            throw new ArgumentOutOfRangeException("key", (key == null) ? 0 : key.Length,
              string.Format("key must be {0} bytes in length.", CRYPTO_AUTH_HMACSHA512_KEY_BYTES));
        }

        //validate the length of the signature
        if (signature == null || signature.Length != CRYPTO_AUTH_HMACSHA512_BYTES)
        {
            throw new ArgumentOutOfRangeException("signature", (signature == null) ? 0 : signature.Length,
              string.Format("signature must be {0} bytes in length.", CRYPTO_AUTH_HMACSHA512_BYTES));
        }

        var ret = SodiumCore.Is64
                    ? _CRYPTO_AUTH_HMACSHA512_VERIFY_64(signature, message, message.Length, key)
                    : _CRYPTO_AUTH_HMACSHA512_VERIFY_86(signature, message, message.Length, key);

        return ret == 0;
    }

    //crypto_auth
    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_auth", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Sign64(byte[] buffer, byte[] message, long messageLength, byte[] key);
    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_auth", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Sign86(byte[] buffer, byte[] message, long messageLength, byte[] key);
    //crypto_auth_verify
    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_auth_verify", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Verify64(byte[] signature, byte[] message, long messageLength, byte[] key);
    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_auth_verify", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Verify86(byte[] signature, byte[] message, long messageLength, byte[] key);
    //crypto_auth_hmacsha256
    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_auth_hmacsha256", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _CRYPTO_AUTH_HMACSHA256_86(byte[] buffer, byte[] message, long messageLength, byte[] key);
    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_auth_hmacsha256", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _CRYPTO_AUTH_HMACSHA256_64(byte[] buffer, byte[] message, long messageLength, byte[] key);
    //crypto_auth_hmacsha256_verify
    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_auth_hmacsha256_verify", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _CRYPTO_AUTH_HMACSHA256_VERIFY_86(byte[] signature, byte[] message, long messageLength, byte[] key);
    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_auth_hmacsha256_verify", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _CRYPTO_AUTH_HMACSHA256_VERIFY_64(byte[] signature, byte[] message, long messageLength, byte[] key);
    //crypto_auth_hmacsha512
    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_auth_hmacsha512", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _CRYPTO_AUTH_HMACSHA512_86(byte[] buffer, byte[] message, long messageLength, byte[] key);
    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_auth_hmacsha512", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _CRYPTO_AUTH_HMACSHA512_64(byte[] buffer, byte[] message, long messageLength, byte[] key);
    //crypto_auth_hmacsha512_verify
    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_auth_hmacsha512_verify", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _CRYPTO_AUTH_HMACSHA512_VERIFY_86(byte[] signature, byte[] message, long messageLength, byte[] key);
    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_auth_hmacsha512_verify", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _CRYPTO_AUTH_HMACSHA512_VERIFY_64(byte[] signature, byte[] message, long messageLength, byte[] key);
  }
}
