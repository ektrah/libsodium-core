namespace Sodium
{
  /// <summary>A public / private key pair.</summary>
  public class KeyPair
  {
    /// <summary>Initializes a new instance of the <see cref="KeyPair"/> class.</summary>
    public KeyPair()
    {
      //do nothing
    }

    /// <summary>Initializes a new instance of the <see cref="KeyPair"/> class.</summary>
    /// <param name="publicKey">The public key.</param>
    /// <param name="privateKey">The private key.</param>
    public KeyPair(byte[] publicKey, byte[] privateKey)
    {
      PublicKey = publicKey;
      PrivateKey = privateKey;
    }

    /// <summary>Gets or sets the Public Key.</summary>
    public byte[] PublicKey { get; set; }

    /// <summary>Gets or sets the Private Key.</summary>
    public byte[] PrivateKey { get; set; }
  }
}
