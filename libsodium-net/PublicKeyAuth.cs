using System;
using System.Security.Cryptography;
using System.Text;
using Sodium.Exceptions;

namespace Sodium
{
  /// <summary>Public-key signatures</summary>
  public static class PublicKeyAuth
  {
    private const int SECRET_KEY_BYTES = 64;
    private const int PUBLIC_KEY_BYTES = 32;
    private const int SIGNATURE_BYTES = 64;
    private const int BYTES = 64;
    private const int SEED_BYTES = 32;

    /// <summary>Creates a new key pair based on a random seed.</summary>
    /// <returns>A KeyPair.</returns>
    public static KeyPair GenerateKeyPair()
    {
      var publicKey = new byte[PUBLIC_KEY_BYTES];
      var privateKey = new byte[SECRET_KEY_BYTES];

      SodiumLibrary.crypto_sign_keypair(publicKey, privateKey);

      return new KeyPair(publicKey, privateKey);
    }

    /// <summary>Creates a new key pair based on the provided seed.</summary>
    /// <param name="seed">The seed.</param>
    /// <returns>A KeyPair.</returns>
    /// <exception cref="SeedOutOfRangeException"></exception>
    public static KeyPair GenerateKeyPair(byte[] seed)
    {
      var publicKey = new byte[PUBLIC_KEY_BYTES];
      var privateKey = new byte[SECRET_KEY_BYTES];

      //validate the length of the seed
      if (seed == null || seed.Length != SEED_BYTES)
        throw new SeedOutOfRangeException("seed", (seed == null) ? 0 : seed.Length,
          string.Format("seed must be {0} bytes in length.", SEED_BYTES));

      SodiumLibrary.crypto_sign_seed_keypair(publicKey, privateKey, seed);

      return new KeyPair(publicKey, privateKey);
    }

    /// <summary>Signs a message with Ed25519.</summary>
    /// <param name="message">The message.</param>
    /// <param name="key">The 64 byte private key.</param>
    /// <returns>Signed message.</returns>
    /// <exception cref="KeyOutOfRangeException"></exception>
    public static byte[] Sign(string message, byte[] key)
    {
      return Sign(Encoding.UTF8.GetBytes(message), key);
    }

    /// <summary>Signs a message with Ed25519.</summary>
    /// <param name="message">The message.</param>
    /// <param name="key">The 64 byte private key.</param>
    /// <returns>Signed message.</returns>
    /// <exception cref="KeyOutOfRangeException"></exception>
    public static byte[] Sign(byte[] message, byte[] key)
    {
      //validate the length of the key
      if (key == null || key.Length != SECRET_KEY_BYTES)
        throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", SECRET_KEY_BYTES));

      var buffer = new byte[message.Length + BYTES];
      long bufferLength = 0;

      SodiumLibrary.crypto_sign(buffer, ref bufferLength, message, message.Length, key);

      var final = new byte[bufferLength];
      Array.Copy(buffer, 0, final, 0, bufferLength);

      return final;
    }

    /// <summary>Verifies a message signed with the Sign method.</summary>
    /// <param name="signedMessage">The signed message.</param>
    /// <param name="key">The 32 byte public key.</param>
    /// <returns>Message.</returns>
    /// <exception cref="KeyOutOfRangeException"></exception>
    /// <exception cref="CryptographicException"></exception>
    public static byte[] Verify(byte[] signedMessage, byte[] key)
    {
      //validate the length of the key
      if (key == null || key.Length != PUBLIC_KEY_BYTES)
        throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", PUBLIC_KEY_BYTES));

      var buffer = new byte[signedMessage.Length];
      long bufferLength = 0;

      var ret = SodiumLibrary.crypto_sign_open(buffer, ref bufferLength, signedMessage, signedMessage.Length, key);

      if (ret != 0)
        throw new CryptographicException("Failed to verify signature.");

      var final = new byte[bufferLength];
      Array.Copy(buffer, 0, final, 0, bufferLength);

      return final;
    }

    /// <summary>Signs a message with Ed25519.</summary>
    /// <param name="message">The message.</param>
    /// <param name="key">The 64 byte private key.</param>
    /// <returns>The signature.</returns>
    /// <exception cref="KeyOutOfRangeException"></exception>
    public static byte[] SignDetached(string message, byte[] key)
    {
      return SignDetached(Encoding.UTF8.GetBytes(message), key);
    }

    /// <summary>Signs a message with Ed25519.</summary>
    /// <param name="message">The message.</param>
    /// <param name="key">The 64 byte private key.</param>
    /// <returns>The signature.</returns>
    /// <exception cref="KeyOutOfRangeException"></exception>
    public static byte[] SignDetached(byte[] message, byte[] key)
    {
      //validate the length of the key
      if (key == null || key.Length != SECRET_KEY_BYTES)
        throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", SECRET_KEY_BYTES));

      var signature = new byte[SIGNATURE_BYTES];
      long signatureLength = 0;

      SodiumLibrary.crypto_sign_detached(signature, ref signatureLength, message, message.Length, key);

      return signature;
    }

    /// <summary>Verifies a message signed with the SignDetached method.</summary>
    /// <param name="signature">The signature.</param>
    /// <param name="message">The message.</param>
    /// <param name="key">The 32 byte public key.</param>
    /// <returns><c>true</c> on success; otherwise, <c>false</c>.</returns>
    /// <exception cref="SignatureOutOfRangeException"></exception>
    /// <exception cref="KeyOutOfRangeException"></exception>
    public static bool VerifyDetached(byte[] signature, byte[] message, byte[] key)
    {
      //validate the length of the signature
      if (signature == null || signature.Length != SIGNATURE_BYTES)
        throw new SignatureOutOfRangeException("signature", (signature == null) ? 0 : signature.Length,
          string.Format("signature must be {0} bytes in length.", SIGNATURE_BYTES));

      //validate the length of the key
      if (key == null || key.Length != PUBLIC_KEY_BYTES)
        throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", PUBLIC_KEY_BYTES));

      var ret = SodiumLibrary.crypto_sign_verify_detached(signature, message, message.Length, key);

      return ret == 0;
    }

    /// <summary>Converts the ed25519 public key to curve25519 public key.</summary>
    /// <param name="ed25519PublicKey">Ed25519 public key.</param>
    /// <returns>The curve25519 public key.</returns>
    /// <exception cref="KeyOutOfRangeException"></exception>
    /// <exception cref="CryptographicException"></exception>
    public static byte[] ConvertEd25519PublicKeyToCurve25519PublicKey(byte[] ed25519PublicKey)
    {
      //validate the length of the key
      if (ed25519PublicKey == null || ed25519PublicKey.Length != PUBLIC_KEY_BYTES)
        throw new KeyOutOfRangeException("ed25519PublicKey", (ed25519PublicKey == null) ? 0 : ed25519PublicKey.Length,
          string.Format("ed25519PublicKey must be {0} bytes in length.", PUBLIC_KEY_BYTES));

      var buffer = new byte[PublicKeyBox.PublicKeyBytes];

      var ret = SodiumLibrary.crypto_sign_ed25519_pk_to_curve25519(buffer, ed25519PublicKey);

      if (ret != 0)
        throw new CryptographicException("Failed to convert public key.");

      return buffer;
    }

    /// <summary>Converts the ed25519 secret key to curve25519 secret key.</summary>
    /// <param name="ed25519SecretKey">Ed25519 secret key.</param>
    /// <returns>The curve25519 secret key.</returns>
    /// <exception cref="KeyOutOfRangeException"></exception>
    /// <exception cref="CryptographicException"></exception>
    public static byte[] ConvertEd25519SecretKeyToCurve25519SecretKey(byte[] ed25519SecretKey)
    {
      //validate the length of the key, which can be appended with the public key or not (both are allowed)
      if (ed25519SecretKey == null || (ed25519SecretKey.Length != PUBLIC_KEY_BYTES && ed25519SecretKey.Length != SECRET_KEY_BYTES))
        throw new KeyOutOfRangeException("ed25519SecretKey", (ed25519SecretKey == null) ? 0 : ed25519SecretKey.Length,
          string.Format("ed25519SecretKey must be either {0} or {1} bytes in length.", PUBLIC_KEY_BYTES,
            SECRET_KEY_BYTES));

      var buffer = new byte[PublicKeyBox.SecretKeyBytes];

      var ret = SodiumLibrary.crypto_sign_ed25519_sk_to_curve25519(buffer, ed25519SecretKey);

      if (ret != 0)
        throw new CryptographicException("Failed to convert secret key.");

      return buffer;
    }

    /// <summary>
    /// Extracts the seed from the Ed25519 secret key.
    /// </summary>
    /// <param name="ed25519SecretKey">The 64 byte Ed25519 secret key.</param>
    /// <returns>The associated seed.</returns>
    public static byte[] ExtractEd25519SeedFromEd25519SecretKey(byte[] ed25519SecretKey)
    {
      //validate the length of the key
      if (ed25519SecretKey == null || ed25519SecretKey.Length != SECRET_KEY_BYTES)
        throw new KeyOutOfRangeException("ed25519SecretKey", (ed25519SecretKey == null) ? 0 : ed25519SecretKey.Length,
            string.Format("ed25519SecretKey must be {0} bytes in length.", SECRET_KEY_BYTES));

      var buffer = new byte[SEED_BYTES];

      var ret = SodiumLibrary.crypto_sign_ed25519_sk_to_seed(buffer, ed25519SecretKey);

      if (ret != 0)
        throw new CryptographicException("Failed to extract seed from secret key.");

      return buffer;
    }

    /// <summary>
    /// Extracts the Ed25519 public key from the Ed25519 secret key.
    /// </summary>
    /// <param name="ed25519SecretKey">The 64 byte Ed25519 secret key.</param>
    /// <returns>The associated ed25519PublicKey.</returns>
    public static byte[] ExtractEd25519PublicKeyFromEd25519SecretKey(byte[] ed25519SecretKey)
    {
      //validate the length of the key
      if (ed25519SecretKey == null || ed25519SecretKey.Length != SECRET_KEY_BYTES)
        throw new KeyOutOfRangeException("ed25519SecretKey", (ed25519SecretKey == null) ? 0 : ed25519SecretKey.Length,
          string.Format("ed25519SecretKey must be {0} bytes in length.", SECRET_KEY_BYTES));

      var buffer = new byte[PUBLIC_KEY_BYTES];

      var ret = SodiumLibrary.crypto_sign_ed25519_sk_to_pk(buffer, ed25519SecretKey);

      if (ret != 0)
        throw new CryptographicException("Failed to extract public key from secret key.");

      return buffer;
    }
  }
}
