using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Sodium
{
  /// <summary>Create and Open Boxes.</summary>
  public static class PublicKeyBox
  {
    private const int PUBLIC_KEY_BYTES = 32;
    private const int SECRET_KEY_BYTES = 32;
    private const int NONCE_BYTES = 24;
    private const int MAC_BYTES = 16;

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

    /// <summary>Creates a new key pair based on the provided private key.</summary>
    /// <param name="privateKey">The private key.</param>
    /// <returns></returns>
    public static KeyPair GenerateKeyPair(byte[] privateKey)
    {
      var publicKey = new byte[PUBLIC_KEY_BYTES];

      //validate the length of the seed
      if (privateKey == null || privateKey.Length != SECRET_KEY_BYTES)
      {
        throw new ArgumentOutOfRangeException("privateKey", (privateKey == null) ? 0 : privateKey.Length,
          string.Format("privateKey must be {0} bytes in length.", SECRET_KEY_BYTES));
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
      if (secretKey == null || secretKey.Length != SECRET_KEY_BYTES)
      {
        throw new ArgumentOutOfRangeException("secretKey", (secretKey == null) ? 0 : secretKey.Length,
          string.Format("key must be {0} bytes in length.", SECRET_KEY_BYTES));
      }

      //validate the length of the public key
      if (publicKey == null || publicKey.Length != PUBLIC_KEY_BYTES)
      {
        throw new ArgumentOutOfRangeException("publicKey", (publicKey == null) ? 0 : secretKey.Length,
          string.Format("key must be {0} bytes in length.", PUBLIC_KEY_BYTES));
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

    /// <summary>Opens a Box</summary>
    /// <param name="cipherText"></param>
    /// <param name="nonce"></param>
    /// <param name="secretKey">The recipient's secret key.</param>
    /// <param name="publicKey">The sender's public key.</param>
    /// <returns></returns>
    public static byte[] Open(byte[] cipherText, byte[] nonce, byte[] secretKey, byte[] publicKey)
    {
      //validate the length of the secret key
      if (secretKey == null || secretKey.Length != SECRET_KEY_BYTES)
      {
        throw new ArgumentOutOfRangeException("secretKey", (secretKey == null) ? 0 : secretKey.Length,
          string.Format("key must be {0} bytes in length.", SECRET_KEY_BYTES));
      }

      //validate the length of the public key
      if (publicKey == null || publicKey.Length != PUBLIC_KEY_BYTES)
      {
        throw new ArgumentOutOfRangeException("publicKey", (publicKey == null) ? 0 : secretKey.Length,
          string.Format("key must be {0} bytes in length.", PUBLIC_KEY_BYTES));
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
  }
}
