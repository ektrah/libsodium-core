using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Sodium
{
  /// <summary>One Time Message Authentication</summary>
  public static class PublicKeyAuth
  {
    private const int SECRET_KEY_BYTES = 64;
    private const int PUBLIC_KEY_BYTES = 32;
    private const int BYTES = 64;
    private const int SEED_BYTES = 32;

    /// <summary>Creates a new key pair based on a random seed.</summary>
    /// <returns></returns>
    public static KeyPair GenerateKeyPair()
    {
      var publicKey = new byte[PUBLIC_KEY_BYTES];
      var privateKey = new byte[SECRET_KEY_BYTES];

      if (SodiumCore.Is64)
        _GenerateKeyPair64(publicKey, privateKey);
      else
        _GenerateKeyPair86(publicKey, privateKey);

      return new KeyPair(publicKey, privateKey);
    }

    /// <summary>Creates a new key pair based on the provided seed.</summary>
    /// <param name="seed">The seed.</param>
    /// <returns></returns>
    public static KeyPair GenerateKeyPair(byte[] seed)
    {
      var publicKey = new byte[PUBLIC_KEY_BYTES];
      var privateKey = new byte[SECRET_KEY_BYTES];

      //validate the length of the seed
      if (seed == null || seed.Length != SEED_BYTES)
      {
        throw new ArgumentOutOfRangeException("seed", (seed == null) ? 0 : seed.Length,
          string.Format("seed must be {0} bytes in length.", SEED_BYTES));
      }

      if (SodiumCore.Is64)
        _GenerateKeyPair64(publicKey, privateKey, seed);
      else
        _GenerateKeyPair86(publicKey, privateKey, seed);

      return new KeyPair(publicKey, privateKey);
    }

    /// <summary>Signs a message with Ed25519.</summary>
    /// <param name="message">The message.</param>
    /// <param name="key">The 64 byte private key.</param>
    /// <returns>Signed message.</returns>
    public static byte[] Sign(string message, byte[] key)
    {
      return Sign(Encoding.UTF8.GetBytes(message), key);
    }

    /// <summary>Signs a message with Ed25519.</summary>
    /// <param name="message">The message.</param>
    /// <param name="key">The 64 byte private key.</param>
    /// <returns>Signed message.</returns>
    public static byte[] Sign(byte[] message, byte[] key)
    {
      //validate the length of the key
      if (key == null || key.Length != SECRET_KEY_BYTES)
      {
        throw new ArgumentOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", SECRET_KEY_BYTES));
      }

      var buffer = new byte[message.Length + BYTES];
      long bufferLength = 0;

      if (SodiumCore.Is64)
        _Sign64(buffer, ref bufferLength, message, message.Length, key);
      else
        _Sign86(buffer, ref bufferLength, message, message.Length, key);

      var final = new byte[bufferLength];
      Array.Copy(buffer, 0, final, 0, bufferLength);

      return final;
    }

    /// <summary>Verifies a message signed with the Sign method.</summary>
    /// <param name="signedMessage">The signed message.</param>
    /// <param name="key">The 32 byte public key.</param>
    /// <returns>Message.</returns>
    public static byte[] Verify(byte[] signedMessage, byte[] key)
    {
      //validate the length of the key
      if (key == null || key.Length != PUBLIC_KEY_BYTES)
      {
        throw new ArgumentOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", PUBLIC_KEY_BYTES));
      }

      var buffer = new byte[signedMessage.Length];
      long bufferLength = 0;

      var ret = SodiumCore.Is64
                  ? _Verify64(buffer, ref bufferLength, signedMessage, signedMessage.Length, key)
                  : _Verify86(buffer, ref bufferLength, signedMessage, signedMessage.Length, key);

      if (ret != 0)
        throw new CryptographicException("Failed to verify signature.");

      var final = new byte[bufferLength];
      Array.Copy(buffer, 0, final, 0, bufferLength);

      return final;
    }

    /// <summary>Converts the ed25519 public key to curve25519 public key.</summary>
    /// <param name="ed25519PublicKey">Ed25519 public key.</param>
    /// <returns>The curve25519 public key.</returns>
    public static byte[] ConvertEd25519PublicKeyToCurve25519PublicKey(byte[] ed25519PublicKey)
    {
        //validate the length of the key
        if (ed25519PublicKey == null || ed25519PublicKey.Length != PUBLIC_KEY_BYTES)
        {
            throw new ArgumentOutOfRangeException("ed25519PublicKey", (ed25519PublicKey == null) ? 0 : ed25519PublicKey.Length,
              string.Format("ed25519PublicKey must be {0} bytes in length.", PUBLIC_KEY_BYTES));
        }

        var buffer = new byte[PublicKeyBox.PUBLIC_KEY_BYTES];

        var ret = SodiumCore.Is64
                    ? _Ed25519PublicKeyToCurve25519PublicKey64(buffer, ed25519PublicKey)
                    : _Ed25519PublicKeyToCurve25519PublicKey86(buffer, ed25519PublicKey);

        if (ret != 0)
            throw new CryptographicException("Failed to convert public key.");

        return buffer;
    }

    /// <summary>Converts the ed25519 secret key to curve25519 secret key.</summary>
    /// <param name="ed25519SecretKey">Ed25519 secret key.</param>
    /// <returns>The curve25519 secret key.</returns>
    public static byte[] ConvertEd25519SecretKeyToCurve25519SecretKey(byte[] ed25519SecretKey)
    {
        //validate the length of the key, which can be appended with the public key or not (both are allowed)
        if (ed25519SecretKey == null || (ed25519SecretKey.Length != PUBLIC_KEY_BYTES && ed25519SecretKey.Length != SECRET_KEY_BYTES))
        {
            throw new ArgumentOutOfRangeException("ed25519SecretKey", (ed25519SecretKey == null) ? 0 : ed25519SecretKey.Length,
              string.Format("ed25519SecretKey must be either {0} or {1} bytes in length.", PUBLIC_KEY_BYTES, SECRET_KEY_BYTES));
        }

        var buffer = new byte[PublicKeyBox.SECRET_KEY_BYTES];

        var ret = SodiumCore.Is64
                    ? _Ed25519SecretKeyToCurve25519SecretKey64(buffer, ed25519SecretKey)
                    : _Ed25519SecretKeyToCurve25519SecretKey86(buffer, ed25519SecretKey);

        if (ret != 0)
            throw new CryptographicException("Failed to convert secret key.");

        return buffer;
    }

    //crypto_sign_keypair
    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_sign_keypair", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _GenerateKeyPair64(byte[] publicKey, byte[] secretKey);
    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_sign_keypair", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _GenerateKeyPair86(byte[] publicKey, byte[] secretKey);

    //crypto_sign_seed_keypair
    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_sign_seed_keypair", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _GenerateKeyPair64(byte[] publicKey, byte[] secretKey, byte[] seed);
    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_sign_seed_keypair", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _GenerateKeyPair86(byte[] publicKey, byte[] secretKey, byte[] seed);

    //crypto_sign
    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_sign", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Sign64(byte[] buffer, ref long bufferLength, byte[] message, long messageLength, byte[] key);
    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_sign", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Sign86(byte[] buffer, ref long bufferLength, byte[] message, long messageLength, byte[] key);

    //crypto_sign_open
    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_sign_open", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Verify64(byte[] buffer, ref long bufferLength, byte[] signedMessage, long signedMessageLength, byte[] key);
    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_sign_open", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Verify86(byte[] buffer, ref long bufferLength, byte[] signedMessage, long signedMessageLength, byte[] key);

    // crypto_sign_ed25519_pk_to_curve25519
    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_sign_ed25519_pk_to_curve25519", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Ed25519PublicKeyToCurve25519PublicKey64(byte[] curve25519Pk, byte[] ed25519Pk);
    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_sign_ed25519_pk_to_curve25519", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Ed25519PublicKeyToCurve25519PublicKey86(byte[] curve25519Pk, byte[] ed25519Pk);

    // crypto_sign_ed25519_sk_to_curve25519
    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_sign_ed25519_sk_to_curve25519", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Ed25519SecretKeyToCurve25519SecretKey64(byte[] curve25519Sk, byte[] ed25519Sk);
    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_sign_ed25519_sk_to_curve25519", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Ed25519SecretKeyToCurve25519SecretKey86(byte[] curve25519Sk, byte[] ed25519Sk);
  }
}
