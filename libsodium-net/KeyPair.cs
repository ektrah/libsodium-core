using System;

namespace Sodium
{
  /// <summary>A public / private key pair.</summary>
  public class KeyPair : IDisposable
  {
    private readonly byte[] _publicKey;
    private readonly byte[] _privateKey;

    /// <summary>Initializes a new instance of the <see cref="KeyPair"/> class.</summary>
    /// <param name="publicKey">The public key.</param>
    /// <param name="privateKey">The private key.</param>
    public KeyPair(byte[] publicKey, byte[] privateKey)
    {
      _publicKey = publicKey;
      _privateKey = privateKey;
    }

    ~KeyPair()
    {
      Dispose();
    }

    /// <summary>Gets or sets the Public Key.</summary>
    public byte[] PublicKey
    {
      get { return _publicKey; }
    }

    /// <summary>Gets or sets the Private Key.</summary>
    public byte[] PrivateKey
    {
      get { return _privateKey; }
    }

    /// <summary>Dispose of private key in memory.</summary>
    public void Dispose()
    {
      if (_privateKey != null && _privateKey.Length > 0)
        Array.Clear(_privateKey, 0, _privateKey.Length);
    }
  }
}
