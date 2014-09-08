namespace Sodium
{
  /// <summary>A ciphertext / mac pair.</summary>
  public class DetachedBox
  {
    /// <summary>Initializes a new instance of the <see cref="DetachedBox"/> class.</summary>
    public DetachedBox()
    {
      //do nothing
    }

    /// <summary>Initializes a new instance of the <see cref="DetachedBox"/> class.</summary>
    /// <param name="cipherText">The cipher.</param>
    /// <param name="mac">The 16 byte mac.</param>
    public DetachedBox(byte[] cipherText, byte[] mac)
    {
      CipherText = cipherText;
      Mac = mac;
    }

    /// <summary>Gets or sets the Cipher.</summary>
    public byte[] CipherText { get; set; }

    /// <summary>Gets or sets the MAC.</summary>
    public byte[] Mac { get; set; }
  }
}
