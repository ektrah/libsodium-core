using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Sodium
{
  /// <summary>Create and Open Boxes.</summary>
  public static class PublicKeyBox
  {
    public const int PublicKeyBytes = 32;
    public const int SecretKeyBytes = 32;

    private const int NONCE_BYTES = 24;
    private const int MAC_BYTES = 16;

    /// <summary>Creates a new key pair based on a random seed.</summary>
    /// <returns></returns>
    public static KeyPair GenerateKeyPair()
    {
      var publicKey = new byte[PublicKeyBytes];
      var privateKey = new byte[SecretKeyBytes];

      if (SodiumCore.Is64)
        _GenerateKeyPair64(publicKey, privateKey);
      else
        _GenerateKeyPair86(publicKey, privateKey);

      return new KeyPair(publicKey, privateKey);
    }

    /// <summary>Creates a new key pair based on the provided private key.</summary>
    /// <param name="privateKey">The private key.</param>
    /// <returns></returns>
    public static KeyPair GenerateKeyPair(byte[] privateKey)
    {
      var publicKey = new byte[PublicKeyBytes];

      //validate the length of the seed
      if (privateKey == null || privateKey.Length != SecretKeyBytes)
      {
        throw new ArgumentOutOfRangeException("privateKey", (privateKey == null) ? 0 : privateKey.Length,
          string.Format("privateKey must be {0} bytes in length.", SecretKeyBytes));
      }

      ScalarMult.Base(publicKey, privateKey);

      return new KeyPair(publicKey, privateKey);
    }

    /// <summary>Creates a Box</summary>
    /// <param name="message"></param>
    /// <param name="nonce"></param>
    /// <param name="secretKey">The secret key to sign message with.</param>
    /// <param name="publicKey">The recipient's public key.</param>
    /// <returns></returns>
    public static byte[] Create(string message, byte[] nonce, byte[] secretKey, byte[] publicKey)
    {
      return Create(Encoding.UTF8.GetBytes(message), nonce, secretKey, publicKey);
    }

    /// <summary>Creates a Box</summary>
    /// <param name="message"></param>
    /// <param name="nonce"></param>
    /// <param name="secretKey">The secret key to sign message with.</param>
    /// <param name="publicKey">The recipient's public key.</param>
    /// <returns></returns>
    public static byte[] Create(byte[] message, byte[] nonce, byte[] secretKey, byte[] publicKey)
    {
      //validate the length of the secret key
      if (secretKey == null || secretKey.Length != SecretKeyBytes)
      {
        throw new ArgumentOutOfRangeException("secretKey", (secretKey == null) ? 0 : secretKey.Length,
          string.Format("key must be {0} bytes in length.", SecretKeyBytes));
      }

      //validate the length of the public key
      if (publicKey == null || publicKey.Length != PublicKeyBytes)
      {
        throw new ArgumentOutOfRangeException("publicKey", (publicKey == null) ? 0 : secretKey.Length,
          string.Format("key must be {0} bytes in length.", PublicKeyBytes));
      }

      //validate the length of the nonce
      if (nonce == null || nonce.Length != NONCE_BYTES)
      {
        throw new ArgumentOutOfRangeException("nonce", (nonce == null) ? 0 : nonce.Length,
          string.Format("nonce must be {0} bytes in length.", NONCE_BYTES));
      }

      var buffer = new byte[message.Length + MAC_BYTES];
      var ret = SodiumCore.Is64
                  ? _Create64(buffer, message, message.Length, nonce, publicKey, secretKey)
                  : _Create86(buffer, message, message.Length, nonce, publicKey, secretKey);

      if (ret != 0)
      {
        throw new CryptographicException("Failed to create SecretBox");
      }

      return buffer;
    }

    /// <summary>Creates detached a Box</summary>
    /// <param name="message">The message.</param>
    /// <param name="nonce">The 24 byte nonce.</param>
    /// <param name="secretKey">The secret key to sign message with.</param>
    /// <param name="publicKey">The recipient's public key.</param>
    /// <returns>A detached object with a cipher and a mac.</returns>
    public static Detached CreateDetached(string message, byte[] nonce, byte[] secretKey, byte[] publicKey)
    {
        return CreateDetached(Encoding.UTF8.GetBytes(message), nonce, secretKey, publicKey);
    }

    /// <summary>Creates a detached Box</summary>
    /// <param name="message">The message.</param>
    /// <param name="nonce">The 24 byte nonce.</param>
    /// <param name="secretKey">The secret key to sign message with.</param>
    /// <param name="publicKey">The recipient's public key.</param>
    /// <returns>A detached object with a cipher and a mac.</returns>
    public static Detached CreateDetached(byte[] message, byte[] nonce, byte[] secretKey, byte[] publicKey)
    {
        //validate the length of the secret key
        if (secretKey == null || secretKey.Length != SecretKeyBytes)
        {
            throw new ArgumentOutOfRangeException("secretKey", (secretKey == null) ? 0 : secretKey.Length,
              string.Format("key must be {0} bytes in length.", SecretKeyBytes));
        }

        //validate the length of the public key
        if (publicKey == null || publicKey.Length != PublicKeyBytes)
        {
            throw new ArgumentOutOfRangeException("publicKey", (publicKey == null) ? 0 : secretKey.Length,
              string.Format("key must be {0} bytes in length.", PublicKeyBytes));
        }

        //validate the length of the nonce
        if (nonce == null || nonce.Length != NONCE_BYTES)
        {
            throw new ArgumentOutOfRangeException("nonce", (nonce == null) ? 0 : nonce.Length,
              string.Format("nonce must be {0} bytes in length.", NONCE_BYTES));
        }

        var cipher = new byte[message.Length];
        var mac = new byte[MAC_BYTES];

        var ret = SodiumCore.Is64
                    ? _CreateDetached64(cipher, mac, message, message.Length, nonce, secretKey, publicKey)
                    : _CreateDetached86(cipher, mac, message, message.Length, nonce, secretKey, publicKey);

        if (ret != 0)
            throw new CryptographicException("Failed to create detached Box");

        return new Detached(cipher, mac);
    }

    /// <summary>Opens a Box</summary>
    /// <param name="cipherText"></param>
    /// <param name="nonce"></param>
    /// <param name="secretKey">The recipient's secret key.</param>
    /// <param name="publicKey">The sender's public key.</param>
    /// <returns></returns>
    public static byte[] Open(byte[] cipherText, byte[] nonce, byte[] secretKey, byte[] publicKey)
    {
      //validate the length of the secret key
      if (secretKey == null || secretKey.Length != SecretKeyBytes)
      {
        throw new ArgumentOutOfRangeException("secretKey", (secretKey == null) ? 0 : secretKey.Length,
          string.Format("key must be {0} bytes in length.", SecretKeyBytes));
      }

      //validate the length of the public key
      if (publicKey == null || publicKey.Length != PublicKeyBytes)
      {
        throw new ArgumentOutOfRangeException("publicKey", (publicKey == null) ? 0 : secretKey.Length,
          string.Format("key must be {0} bytes in length.", PublicKeyBytes));
      }

      //validate the length of the nonce
      if (nonce == null || nonce.Length != NONCE_BYTES)
      {
        throw new ArgumentOutOfRangeException("nonce", (nonce == null) ? 0 : nonce.Length,
          string.Format("nonce must be {0} bytes in length.", NONCE_BYTES));
      }

      //check to see if there are MAC_BYTES of leading nulls, if so, trim.
      //this is required due to an error in older versions.
      if (cipherText[0] == 0)
      {
        //check to see if trim is needed
        var trim = true;
        for (var i = 0; i < MAC_BYTES - 1; i++)
        {
          if (cipherText[i] != 0)
          {
            trim = false;
            break;
          }
        }

        //if the leading MAC_BYTES are null, trim it off before going on.
        if (trim)
        {
          var temp = new byte[cipherText.Length - MAC_BYTES];
          Array.Copy(cipherText, MAC_BYTES, temp, 0, cipherText.Length - MAC_BYTES);

          cipherText = temp;
        }
      }

      var buffer = new byte[cipherText.Length - MAC_BYTES];
      var ret = SodiumCore.Is64
                  ? _Open64(buffer, cipherText, cipherText.Length, nonce, publicKey, secretKey)
                  : _Open86(buffer, cipherText, cipherText.Length, nonce, publicKey, secretKey);

      if (ret != 0)
        throw new CryptographicException("Failed to open SecretBox");
      
      return buffer;
    }

    /// <summary>Opens a detached Box</summary>
    /// <param name="cipherText">Hex-encoded string to be opened</param>
    /// <param name="mac">The 16 byte mac.</param>
    /// <param name="nonce">The 24 byte nonce.</param>
    /// <param name="secretKey">The recipient's secret key.</param>
    /// <param name="publicKey">The sender's public key.</param>
    /// <returns></returns>
    public static byte[] OpenDetached(string cipherText, byte[] mac, byte[] nonce, byte[] secretKey, byte[] publicKey)
    {
        return OpenDetached(Utilities.HexToBinary(cipherText), mac, nonce, secretKey, publicKey);
    }

    /// <summary>Opens a detached Box</summary>
    /// <param name="detached">A detached object.</param>
    /// <param name="nonce">The 24 byte nonce.</param>
    /// <param name="secretKey">The recipient's secret key.</param>
    /// <param name="publicKey">The sender's public key.</param>
    /// <returns></returns>
    public static byte[] OpenDetached(Detached detached, byte[] nonce, byte[] secretKey, byte[] publicKey)
    {
        return OpenDetached(detached.Cipher, detached.Mac, nonce, secretKey, publicKey);
    }

    /// <summary>Opens a detached Box</summary>
    /// <param name="cipherText">The cipherText.</param>
    /// <param name="mac">The 16 byte mac.</param>
    /// <param name="nonce">The 24 byte nonce.</param>
    /// <param name="secretKey">The recipient's secret key.</param>
    /// <param name="publicKey">The sender's public key.</param>
    /// <returns></returns>
    public static byte[] OpenDetached(byte[] cipherText, byte[] mac, byte[] nonce, byte[] secretKey, byte[] publicKey)
    {
        //validate the length of the secret key
        if (secretKey == null || secretKey.Length != SecretKeyBytes)
        {
            throw new ArgumentOutOfRangeException("secretKey", (secretKey == null) ? 0 : secretKey.Length,
              string.Format("key must be {0} bytes in length.", SecretKeyBytes));
        }

        //validate the length of the public key
        if (publicKey == null || publicKey.Length != PublicKeyBytes)
        {
            throw new ArgumentOutOfRangeException("publicKey", (publicKey == null) ? 0 : secretKey.Length,
              string.Format("key must be {0} bytes in length.", PublicKeyBytes));
        }

        //validate the length of the mac
        if (mac == null || mac.Length != MAC_BYTES)
        {
            throw new ArgumentOutOfRangeException("mac", (mac == null) ? 0 : mac.Length,
              string.Format("mac must be {0} bytes in length.", MAC_BYTES));
        }

        //validate the length of the nonce
        if (nonce == null || nonce.Length != NONCE_BYTES)
        {
            throw new ArgumentOutOfRangeException("nonce", (nonce == null) ? 0 : nonce.Length,
              string.Format("nonce must be {0} bytes in length.", NONCE_BYTES));
        }

        var buffer = new byte[cipherText.Length];
        var ret = SodiumCore.Is64
                    ? _OpenDetached64(buffer, cipherText, mac, cipherText.Length, nonce, secretKey, publicKey)
                    : _OpenDetached86(buffer, cipherText, mac, cipherText.Length, nonce, secretKey, publicKey);

        if (ret != 0)
            throw new CryptographicException("Failed to open detached Box");

        return buffer;
    }

    //crypto_box_keypair
    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_box_keypair", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _GenerateKeyPair64(byte[] publicKey, byte[] secretKey);
    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_box_keypair", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _GenerateKeyPair86(byte[] publicKey, byte[] secretKey);

    //crypto_box_easy
    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_box_easy", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Create64(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] publicKey, byte[] secretKey);
    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_box_easy", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Create86(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] publicKey, byte[] secretKey);

    //crypto_box_open_easy
    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_box_open_easy", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Open64(byte[] buffer, byte[] cipherText, long cipherTextLength, byte[] nonce, byte[] publicKey, byte[] secretKey);
    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_box_open_easy", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _Open86(byte[] buffer, byte[] cipherText, long cipherTextLength, byte[] nonce, byte[] publicKey, byte[] secretKey);

    //crypto_box_detached
    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_box_detached", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _CreateDetached64(byte[] cipher, byte[] mac, byte[] message, long messageLength, byte[] nonce, byte[] pk, byte[] sk);
    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_box_detached", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _CreateDetached86(byte[] cipher, byte[] mac, byte[] message, long messageLength, byte[] nonce, byte[] pk, byte[] sk);

    //crypto_box_open_detached
    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_box_open_detached", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _OpenDetached64(byte[] buffer, byte[] cipherText, byte[] mac, long cipherTextLength, byte[] nonce, byte[] pk, byte[] sk);
    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_box_open_detached", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _OpenDetached86(byte[] buffer, byte[] cipherText, byte[] mac, long cipherTextLength, byte[] nonce, byte[] pk, byte[] sk);
  }
}
